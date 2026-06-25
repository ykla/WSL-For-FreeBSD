/*
 * SPDX-License-Identifier: MIT
 *
 * drvfs_mount.h - DrvFs filesystem mounting module.
 *
 * Implements DrvFs volume mounting for WSL-For-FreeBSD, mirroring the
 * reference WSL implementation in:
 *   - src/linux/init/drvfs.cpp (MountDrvfs, MountPlan9Filesystem, MountDrvfsEntry)
 *   - src/linux/init/config.cpp (ConfigMountDrvFsVolumes)
 *
 * Mount flow:
 *   1. Guest init receives Initialize(5) with DrvfsMount != None and
 *      DrvFsVolumesBitmap (bit 0 = A:, bit 2 = C:, etc.)
 *   2. Guest iterates bitmap: mkdir target (/mnt/c), build options, mount -t 9p
 *   3. Host runs Plan9 file server on port 50002 (non-elevated) or 50003 (elevated)
 *   4. Guest connects via vsock/fd and mounts using 9p filesystem type
 *
 * FreeBSD limitation: no native 9p/drvfs kernel filesystem type.
 * Mount calls use "best-effort" strategy — failures are logged but non-fatal,
 * allowing protocol flow testing without a real 9p server. This mirrors the
 * F2 unmount behavior where failures are logged but don't block shutdown.
 *
 * Three mount paths (matching reference):
 *   Path 1: Automatic mount after Initialize(5) — drvfs_mount_volumes()
 *   Path 2: RemountDrvfs(13) message — caller parses msg, calls drvfs_mount_volumes()
 *   Path 3: User mount.drvfs — drvfs_mount_entry()
 *
 * Usage:
 *   #include "drvfs_mount.h"
 *
 *   // Path 1: After Initialize(5) parse
 *   if (g_config.drvfs_mount != WSL_DRVFS_MOUNT_NONE) {
 *       drvfs_mount_volumes(g_config.drvfs_volumes_bitmap,
 *                           g_config.drvfs_default_owner,
 *                           g_config.drvfs_elevated,
 *                           g_wsl_conf.automount_root ? g_wsl_conf.automount_root : "/mnt",
 *                           g_wsl_conf.automount_options);
 *   }
 *
 *   // Path 3: mount.drvfs entry
 *   if (strcmp(argv[0], "mount.drvfs") == 0) {
 *       return drvfs_mount_entry(argc, argv);
 *   }
 */
#ifndef DRVFS_MOUNT_H
#define DRVFS_MOUNT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

/* ---- Constants from reference implementation ----
 * Source: src/linux/init/util.h, config.cpp, lxinitshared.h */

#define DRVFS_SOURCE_TEMPLATE " :\\"     /* Source[0] set to 'A' + drive index */
#define DRVFS_TARGET_MODE 0777           /* mkdir mode for mount points */
#define PLAN9_FS_TYPE "9p"               /* 9p filesystem type for mount() */
#define VIRTIO_FS_TYPE "virtiofs"        /* virtiofs filesystem type */
#define PLAN9_ANAME_OPTION "aname="      /* 9p aname option prefix */
#define PLAN9_ANAME_DRVFS "aname=drvfs"  /* 9p aname for DrvFs share */
#define PLAN9_ANAME_OPTION_SEP ';'       /* 9p option separator */

/* Plan9 ports (lxinitshared.h) */
#define LX_INIT_UTILITY_VM_PLAN9_DRVFS_PORT 50002       /* non-elevated 9p server */
#define LX_INIT_UTILITY_VM_PLAN9_DRVFS_ADMIN_PORT 50003 /* elevated (admin) 9p server */
#define LX_INIT_UTILITY_VM_PLAN9_BUFFER_SIZE 65536      /* 9p buffer size */

/* Virtio tags (lxinitshared.h) */
#define LX_INIT_DRVFS_VIRTIO_TAG "drvfs"       /* non-elevated virtio tag */
#define LX_INIT_DRVFS_ADMIN_VIRTIO_TAG "drvfsa" /* elevated (admin) virtio tag */

/* Environment variable for elevated mode (util.h) */
#define WSL_DRVFS_ELEVATED_ENV "WSL_DRVFS_ELEVATED"

/* Feature flags from config_parser.h (re-declared for standalone use) */
#define DRVFS_FEATURE_VIRTIO_9P 0x01
#define DRVFS_FEATURE_VIRTIO_FS 0x02

/* ---- Internal: platform-specific mount wrapper ----
 *
 * FreeBSD: int mount(const char *type, const char *dir, int flags, void *data);
 * Linux:   int mount(const char *source, const char *target,
 *                    const char *filesystemtype, unsigned long mountflags,
 *                    const void *data);
 *
 * For 9p mounts, the source is encoded in the 9p options (trans=fd mode),
 * so the FreeBSD signature (which lacks source) is sufficient. */
static inline int drvfs_do_mount(const char *source, const char *target,
                                  const char *fstype, const char *options)
{
    (void)source; /* source is encoded in 9p options for fd transport */
#ifdef __FreeBSD__
    /* FreeBSD: mount(type, dir, flags, data)
     * NOTE: FreeBSD has no 9p kernel filesystem type; this returns ENODEV.
     * The options string is not passed because FreeBSD mount() uses a
     * filesystem-specific data structure, not an options string. */
    (void)options;
    return mount(fstype, target, 0, NULL);
#else
    /* Linux: mount(source, target, fstype, flags, data) */
    return mount(source, target, fstype, 0, options);
#endif
}

/* ---- Internal: build 9p mount options ----
 *
 * Constructs the full 9p mount options string, mirroring MountPlan9Filesystem
 * in drvfs.cpp:447-494. The format is:
 *   "cache=mmap,{standard_options},aname=drvfs;path={source};{drvfs_options}"
 *
 * For virtio-9p mode (feature flag 0x01):
 *   "msize=262144,trans=virtio,{above_options}"
 * For fd transport (default):
 *   "msize=65536,trans=fd,rfdno={fd},wfdno={fd},{above_options}"
 *
 * Since we don't have a real 9p server connection in the test environment,
 * the fd transport options are omitted (mount will fail, which is expected).
 *
 * Parameters:
 *   buf         - output buffer
 *   bufsize     - size of buf
 *   source      - DrvFs source path (e.g. "C:\")
 *   std_options - standard mount options (e.g. "noatime,uid=1000,gid=1000")
 *   drvfs_opts  - DrvFs-specific options (e.g. "metadata,umask=022"), may be NULL
 *   feature_flags - WSL feature flags (for virtio-9p/virtiofs detection)
 *   elevated    - 1 for admin 9p server, 0 for regular
 *
 * Returns 0 on success, -1 if buffer too small. */
static inline int drvfs_build_options(char *buf, size_t bufsize,
                                       const char *source,
                                       const char *std_options,
                                       const char *drvfs_opts,
                                       uint32_t feature_flags,
                                       int elevated)
{
    if (!buf || bufsize == 0) return -1;
    buf[0] = '\0';

    /* Virtio-9p mode: use virtio transport with tag */
    if (feature_flags & DRVFS_FEATURE_VIRTIO_9P) {
        const char *tag = elevated ? LX_INIT_DRVFS_ADMIN_VIRTIO_TAG
                                   : LX_INIT_DRVFS_VIRTIO_TAG;
        snprintf(buf, bufsize, "msize=262144,trans=virtio,%s,cache=mmap,",
                 tag);
    } else {
        /* FD transport mode (default). In production, rfdno/wfdno would be
         * set to the connected vsock fd. In test, mount fails (no 9p server). */
        snprintf(buf, bufsize, "msize=%d,trans=fd,cache=mmap,",
                 LX_INIT_UTILITY_VM_PLAN9_BUFFER_SIZE);
    }

    /* Append standard options */
    if (std_options && *std_options) {
        size_t cur = strlen(buf);
        snprintf(buf + cur, bufsize - cur, "%s,", std_options);
    }

    /* Append 9p aname with path and drvfs-specific options */
    size_t cur = strlen(buf);
    int n = snprintf(buf + cur, bufsize - cur, "%s;path=%s",
                     PLAN9_ANAME_DRVFS, source);
    if (n < 0 || (size_t)n >= bufsize - cur) return -1;

    /* Append drvfs-specific options as semicolon-separated 9p options */
    if (drvfs_opts && *drvfs_opts) {
        cur = strlen(buf);
        /* Convert comma-separated drvfs options to semicolon-separated 9p options.
         * E.g. "metadata,umask=022" -> ";metadata;umask=022" */
        n = snprintf(buf + cur, bufsize - cur, ";");
        if (n < 0 || (size_t)n >= bufsize - cur) return -1;
        cur = strlen(buf);
        for (const char *p = drvfs_opts; *p && cur < bufsize - 2; p++) {
            buf[cur++] = (*p == ',') ? ';' : *p;
        }
        buf[cur] = '\0';
    }

    return 0;
}

/* ---- Internal: resolve owner GID from UID ----
 * Mirrors config.cpp:1960-1965. Returns ROOT_GID (0) if no passwd entry. */
static inline gid_t drvfs_resolve_gid(uid_t uid)
{
    struct passwd *pw = getpwuid(uid);
    return pw ? pw->pw_gid : 0;
}

/* ---- Internal: recursive mkdir (mkdir -p style) ----
 * Creates all intermediate directories. Ignores EEXIST. */
static inline int drvfs_mkdir_p(const char *path, mode_t mode)
{
    char tmp[512];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    /* Remove trailing slash */
    if (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    /* Create each path component */
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    /* Create final component */
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* ---- Mount a single DrvFs volume ----
 *
 * Creates the target directory and attempts a 9p mount.
 * Mirrors MountDrvfs + MountPlan9Filesystem in drvfs.cpp.
 *
 * Parameters:
 *   source       - Windows source path (e.g. "C:\\")
 *   target       - Mount point path (e.g. "/mnt/c")
 *   std_options  - Standard mount options (e.g. "noatime,uid=1000,gid=1000")
 *   drvfs_opts   - DrvFs-specific options (may be NULL)
 *   feature_flags - WSL feature flags
 *   elevated     - 1 for admin 9p server
 *   track_mount  - Callback to record mount for later cleanup (may be NULL)
 *
 * Returns 0 on success, -1 on failure (logged, non-fatal). */
static inline int drvfs_mount_single(const char *source, const char *target,
                                      const char *std_options,
                                      const char *drvfs_opts,
                                      uint32_t feature_flags,
                                      int elevated,
                                      void (*track_mount)(const char *))
{
    if (!source || !target) return -1;

    /* Create target directory (mkdir -p style, ignore EEXIST) */
    struct stat st;
    if (stat(target, &st) != 0) {
        if (drvfs_mkdir_p(target, DRVFS_TARGET_MODE) < 0) {
            fprintf(stderr, "[drvfs] mkdir %s failed: %s\n",
                    target, strerror(errno));
            return -1;
        }
    }

    /* Build full 9p mount options */
    char options[1024];
    if (drvfs_build_options(options, sizeof(options), source,
                            std_options ? std_options : "",
                            drvfs_opts, feature_flags, elevated) < 0) {
        fprintf(stderr, "[drvfs] options too long for %s\n", target);
        return -1;
    }

    printf("[drvfs] mounting %s -> %s (options: %s)\n",
           source, target, options);

    /* Attempt the mount (best-effort: fails expectedly without 9p server) */
    int rc = drvfs_do_mount(source, target, PLAN9_FS_TYPE, options);
    if (rc < 0) {
        /* Log but don't fail — best-effort strategy.
         * In test environment: no 9p server running.
         * In FreeBSD production: no 9p kernel module.
         * The mount intent is logged for protocol flow verification. */
        fprintf(stderr, "[drvfs] mount %s failed: %s (expected without 9p server)\n",
                target, strerror(errno));
        return -1;
    }

    printf("[drvfs] mounted %s at %s\n", source, target);
    if (track_mount) {
        track_mount(target);
    }
    return 0;
}

/* ---- Mount all DrvFs volumes from a bitmap ----
 *
 * Iterates the DrvFsVolumes bitmap (bit 0 = A:, bit 2 = C:, etc.),
 * creates mount points, and attempts 9p mounts.
 * Mirrors ConfigMountDrvFsVolumes in config.cpp:1913-2022.
 *
 * Parameters:
 *   bitmap       - Drive bitmap (bit 0 = A:, bit 1 = B:, bit 2 = C:, ...)
 *   owner_uid    - UID for file ownership
 *   elevated     - 1 for admin mount namespace, 0 for regular
 *   prefix       - Mount prefix (e.g. "/mnt" or "/mnt/"), trailing / OK
 *   drvfs_opts   - Additional DrvFs options (e.g. "metadata,umask=022"), may be NULL
 *   feature_flags - WSL feature flags (for virtio-9p detection)
 *   track_mount  - Callback to record mount for cleanup (may be NULL)
 *
 * Returns number of successfully mounted volumes. */
static inline int drvfs_mount_volumes(unsigned int bitmap, uid_t owner_uid,
                                      int elevated, const char *prefix,
                                      const char *drvfs_opts,
                                      uint32_t feature_flags,
                                      void (*track_mount)(const char *))
{
    if (bitmap == 0) {
        printf("[drvfs] no volumes to mount (bitmap=0)\n");
        return 0;
    }

    if (!prefix || !*prefix) {
        prefix = "/mnt";
    }

    /* Resolve owner GID (mirrors config.cpp:1960-1965) */
    gid_t owner_gid = drvfs_resolve_gid(owner_uid);
    printf("[drvfs] mounting volumes bitmap=0x%08x uid=%u gid=%u elevated=%d prefix=%s\n",
           bitmap, owner_uid, owner_gid, elevated, prefix);

    /* Build standard options: "noatime,uid={uid},gid={gid}" */
    char std_options[256];
    snprintf(std_options, sizeof(std_options), "noatime,uid=%u,gid=%u",
             owner_uid, owner_gid);

    /* Normalize prefix: remove trailing '/' for path construction.
     * We'll add it back as "{prefix}/{letter}" */
    size_t prefix_len = strlen(prefix);
    while (prefix_len > 1 && prefix[prefix_len - 1] == '/') {
        prefix_len--;
    }

    int mounted = 0;
    unsigned int remaining = bitmap;

    /* Iterate set bits using __builtin_ffs (1-based index) */
    while (remaining != 0) {
        int index = __builtin_ffs((int)remaining);
        if (index == 0) break;
        index -= 1; /* convert to 0-based */
        remaining ^= (1u << index);

        /* Build source: "C:\" (Source[0] = 'A' + index) */
        char source[8];
        snprintf(source, sizeof(source), "%c:\\", 'A' + index);

        /* Build target: "{prefix}/{letter}" (lowercase) */
        char target[256];
        snprintf(target, sizeof(target), "%.*s/%c", (int)prefix_len, prefix,
                 'a' + index);

        printf("[drvfs] drive %c: -> %s\n", 'A' + index, target);

        if (drvfs_mount_single(source, target, std_options, drvfs_opts,
                               feature_flags, elevated, track_mount) == 0) {
            mounted++;
        }
    }

    printf("[drvfs] mounted %d volume(s) from bitmap 0x%08x\n",
           mounted, bitmap);
    return mounted;
}

/* ---- mount.drvfs entry point ----
 *
 * Handles user-initiated `mount -t drvfs C: /mnt/foo` commands.
 * The mount.drvfs binary is a symlink to /init, which detects argv[0]
 * and dispatches here (mirrors init.cpp:182-184, drvfs.cpp:405-445).
 *
 * Expected argv:
 *   argv[0] = "mount.drvfs" (or path ending in mount.drvfs)
 *   argv[1] = source (e.g. "C:" or "C:\\" or UNC path)
 *   argv[2] = target (e.g. "/mnt/foo")
 *   argv[3] = "-o" (optional)
 *   argv[4] = options (optional, e.g. "metadata,uid=1000")
 *
 * Returns 0 on success, 1 on failure (matching mount exit codes). */
static inline int drvfs_mount_entry(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: mount.drvfs <source> <target> [-o options]\n");
        return 1;
    }

    const char *source = argv[1];
    const char *target = argv[2];
    const char *options = NULL;

    /* Parse optional -o options */
    for (int i = 3; i < argc - 1; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            options = argv[i + 1];
            break;
        }
    }

    /* Check WSL_DRVFS_ELEVATED env for elevated mode (util.h) */
    int elevated = (getenv(WSL_DRVFS_ELEVATED_ENV) != NULL);

    printf("[drvfs] mount.drvfs: source=%s target=%s options=%s elevated=%d\n",
           source, target, options ? options : "(none)", elevated);

    /* For mount.drvfs, use default uid/gid (root) if not in options.
     * The reference parses options to extract uid/gid, but for simplicity
     * we pass the raw options as drvfs_opts. */
    if (drvfs_mount_single(source, target, NULL, options,
                           0, elevated, NULL) == 0) {
        return 0;
    }

    fprintf(stderr, "[drvfs] mount.drvfs: failed to mount %s at %s\n",
            source, target);
    return 1;
}

#endif /* DRVFS_MOUNT_H */
