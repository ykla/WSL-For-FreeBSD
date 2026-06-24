/*
 * SPDX-License-Identifier: MIT
 *
 * config_parser.h - WSL Initialize(5) message configuration parser.
 *
 * Parses the LX_INIT_CONFIGURATION_INFORMATION message (type 5, host->guest)
 * sent by the WSL host during instance initialization. Extracts all
 * configuration fields including hostname, domainname, distribution name,
 * timezone, DrvFs settings, and feature flags from the variable-length
 * Buffer[] using offset fields.
 *
 * Matches the reference implementation in src/linux/init/config.cpp
 * ConfigInitializeInstance().
 *
 * Usage:
 *   #include "config_parser.h"
 *
 *   struct wsl_config config;
 *   wsl_config_init(&config);
 *
 *   if (wsl_config_parse(&config, msg_buf, msg_size) == 0) {
 *       printf("hostname=%s, distro=%s, timezone=%s\n",
 *              config.hostname, config.distribution_name, config.timezone);
 *       // Use config.default_uid, config.feature_flags, etc.
 *   }
 *   wsl_config_free(&config);
 *
 * Edge cases handled:
 *   - Message smaller than struct header -> parse fails, returns -1
 *   - Offset beyond Buffer[] boundary -> string set to NULL
 *   - Empty string (offset points to NUL byte) -> strdup("") returns ""
 *   - Duplicate NUL terminators -> strnup-safe extraction
 *   - NULL message pointer -> parse fails gracefully
 */
#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ---- DrvFs mount mode (from lxinitshared.h LX_INIT_DRVFS_MOUNT) ---- */
enum {
    WSL_DRVFS_MOUNT_NONE        = 0,
    WSL_DRVFS_MOUNT_NONELEVATED = 1,
    WSL_DRVFS_MOUNT_ELEVATED    = 2
};

/* ---- Feature flags (from lxinitshared.h LX_INIT_FEATURE_FLAGS) ---- */
#define WSL_FEATURE_NONE              0x00u
#define WSL_FEATURE_VIRTIO_9P         0x01u
#define WSL_FEATURE_VIRTIO_FS         0x02u
#define WSL_FEATURE_DISABLE_9P_SERVER 0x04u
#define WSL_FEATURE_ROOTFS_COMPRESSED 0x08u
#define WSL_FEATURE_SYSTEM_DISTRO     0x10u
#define WSL_FEATURE_DNS_TUNNELING     0x20u

/* ---- Internal structure matching LX_INIT_CONFIGURATION_INFORMATION ----
 * This mirrors the wire format exactly. DO NOT change field order or types. */
struct wsl_init_message {
    struct MESSAGE_HEADER Header;
    uint32_t HostnameOffset;
    uint32_t DomainnameOffset;
    uint32_t WindowsHostsOffset;
    uint32_t DistributionNameOffset;
    uint32_t Plan9SocketOffset;
    uint32_t TimezoneOffset;
    uint32_t DrvFsVolumesBitmap;
    uint32_t DrvFsDefaultOwner;
    uint32_t FeatureFlags;
    uint32_t DrvfsMount;
    /* Buffer[] follows — variable length */
};

/* ---- Parsed configuration storage ----
 * All string fields are heap-allocated (strdup) and must be freed via
 * wsl_config_free(). NULL indicates the field was not present or invalid. */
struct wsl_config {
    char *hostname;           /* NUL-terminated, may be "" */
    char *domainname;         /* NUL-terminated, may be "" */
    char *windows_hosts;      /* Contents of Windows hosts file */
    char *distribution_name;  /* e.g. "FreeBSD" */
    char *plan9_socket_path;  /* Plan9 server socket path */
    char *timezone;           /* IANA tz, e.g. "Asia/Shanghai" */

    uint32_t drvfs_volumes_bitmap;  /* Bit 0 = A:, bit 2 = C:, etc. */
    uint32_t drvfs_default_owner;   /* Default UID for DrvFs files */
    uint32_t feature_flags;         /* WSL_FEATURE_* bitmask */
    uint32_t drvfs_mount;           /* WSL_DRVFS_MOUNT_* enum value */

    /* Derived fields */
    int drvfs_elevated;       /* 1 if drvfs_mount == WSL_DRVFS_MOUNT_ELEVATED */
};

/* Initialize a wsl_config struct to safe defaults (all NULL/zero). */
static inline void wsl_config_init(struct wsl_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
}

/* Safely extract a NUL-terminated string from a buffer at a given offset.
 * Returns a strdup'd copy, or NULL if the offset is out of bounds.
 * If offset is valid but points to a NUL byte, returns strdup(""). */
static inline char *wsl_extract_string(const char *buffer, size_t buffer_size,
                                       uint32_t offset)
{
    if (!buffer || offset >= buffer_size)
        return NULL;

    /* The string starts at buffer[offset] and runs until NUL or end of buffer.
     * Use strnlen to avoid reading past the buffer boundary. */
    const char *str = buffer + offset;
    size_t remaining = buffer_size - offset;
    size_t len = strnlen(str, remaining);

    /* Allocate len+1 to include NUL terminator (even if str is not NUL-terminated
     * within the buffer, we add one). */
    char *result = malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, str, len);
    result[len] = '\0';
    return result;
}

/* Parse a raw Initialize(5) message buffer into a wsl_config struct.
 *
 * Parameters:
 *   cfg     - pointer to initialized wsl_config (call wsl_config_init first)
 *   msg_buf - pointer to the raw message buffer (including MESSAGE_HEADER)
 *   msg_size- total size of the message buffer in bytes
 *
 * Returns:
 *   0 on success (all available fields populated)
 *  -1 on fatal error (message too small, NULL pointer, etc.)
 *
 * On failure, cfg may be partially populated; caller should still call
 * wsl_config_free() to release any allocated strings.
 *
 * Edge cases:
 *   - msg_size < sizeof(struct wsl_init_message): returns -1 (too small)
 *   - Offset beyond Buffer[]: corresponding string set to NULL
 *   - msg_buf is NULL: returns -1
 */
static inline int wsl_config_parse(struct wsl_config *cfg,
                                   const void *msg_buf, size_t msg_size)
{
    if (!cfg || !msg_buf)
        return -1;

    /* Validate minimum message size — must contain at least the fixed header */
    if (msg_size < sizeof(struct wsl_init_message))
        return -1;

    const struct wsl_init_message *msg =
        (const struct wsl_init_message *)msg_buf;

    /* Calculate Buffer[] region */
    const char *buffer = (const char *)msg_buf + sizeof(struct wsl_init_message);
    size_t buffer_size = msg_size - sizeof(struct wsl_init_message);

    /* Extract all 6 strings using their offsets.
     * NULL is acceptable — means the field was not provided or offset invalid. */
    cfg->hostname = wsl_extract_string(buffer, buffer_size, msg->HostnameOffset);
    cfg->domainname = wsl_extract_string(buffer, buffer_size, msg->DomainnameOffset);
    cfg->windows_hosts = wsl_extract_string(buffer, buffer_size, msg->WindowsHostsOffset);
    cfg->distribution_name = wsl_extract_string(buffer, buffer_size, msg->DistributionNameOffset);
    cfg->plan9_socket_path = wsl_extract_string(buffer, buffer_size, msg->Plan9SocketOffset);
    cfg->timezone = wsl_extract_string(buffer, buffer_size, msg->TimezoneOffset);

    /* Copy scalar fields */
    cfg->drvfs_volumes_bitmap = msg->DrvFsVolumesBitmap;
    cfg->drvfs_default_owner = msg->DrvFsDefaultOwner;
    cfg->feature_flags = msg->FeatureFlags;
    cfg->drvfs_mount = msg->DrvfsMount;
    cfg->drvfs_elevated = (msg->DrvfsMount == WSL_DRVFS_MOUNT_ELEVATED);

    return 0;
}

/* Free all heap-allocated strings in a wsl_config struct.
 * Safe to call on a partially-populated or zero-initialized struct.
 * Resets all fields to NULL/zero after freeing. */
static inline void wsl_config_free(struct wsl_config *cfg)
{
    if (!cfg) return;
    free(cfg->hostname);
    free(cfg->domainname);
    free(cfg->windows_hosts);
    free(cfg->distribution_name);
    free(cfg->plan9_socket_path);
    free(cfg->timezone);
    memset(cfg, 0, sizeof(*cfg));
}

/* Print a debug dump of the parsed configuration to stdout.
 * Useful for testing and diagnostics. */
static inline void wsl_config_dump(const struct wsl_config *cfg)
{
    if (!cfg) {
        printf("[config] (null)\n");
        return;
    }
    printf("[config] parsed Initialize(5) message:\n");
    printf("[config]   hostname          = '%s'\n",
           cfg->hostname ? cfg->hostname : "(null)");
    printf("[config]   domainname        = '%s'\n",
           cfg->domainname ? cfg->domainname : "(null)");
    printf("[config]   windows_hosts     = '%.80s%s'\n",
           cfg->windows_hosts ? cfg->windows_hosts : "(null)",
           (cfg->windows_hosts && strlen(cfg->windows_hosts) > 80) ? "..." : "");
    printf("[config]   distribution_name = '%s'\n",
           cfg->distribution_name ? cfg->distribution_name : "(null)");
    printf("[config]   plan9_socket_path = '%s'\n",
           cfg->plan9_socket_path ? cfg->plan9_socket_path : "(null)");
    printf("[config]   timezone          = '%s'\n",
           cfg->timezone ? cfg->timezone : "(null)");
    printf("[config]   drvfs_volumes     = 0x%08x\n", cfg->drvfs_volumes_bitmap);
    printf("[config]   drvfs_default_uid = %u\n", cfg->drvfs_default_owner);
    printf("[config]   feature_flags     = 0x%08x\n", cfg->feature_flags);
    printf("[config]   drvfs_mount       = %u (%s)\n", cfg->drvfs_mount,
           cfg->drvfs_mount == WSL_DRVFS_MOUNT_NONE ? "none" :
           cfg->drvfs_mount == WSL_DRVFS_MOUNT_NONELEVATED ? "non-elevated" :
           cfg->drvfs_mount == WSL_DRVFS_MOUNT_ELEVATED ? "elevated" : "unknown");
}

/* Check if a specific feature flag is set. */
static inline int wsl_config_has_feature(const struct wsl_config *cfg, uint32_t flag)
{
    return cfg && (cfg->feature_flags & flag) != 0;
}

/* Build a variable-length Initialize message for testing.
 * Packs the 6 strings into Buffer[] and fills offset fields.
 *
 * Parameters:
 *   hostname, domainname, windows_hosts, distribution_name,
 *   plan9_socket, timezone - NUL-terminated strings (NULL treated as "")
 *   drvfs_bitmap, drvfs_owner, feature_flags, drvfs_mount - scalar fields
 *   seq - sequence number for the message header
 *   out_size - receives the total message size
 *
 * Returns:
 *   malloc'd buffer containing the complete message (caller must free),
 *   or NULL on allocation failure.
 */
static inline void *wsl_config_build_message(
    const char *hostname, const char *domainname,
    const char *windows_hosts, const char *distribution_name,
    const char *plan9_socket, const char *timezone,
    uint32_t drvfs_bitmap, uint32_t drvfs_owner,
    uint32_t feature_flags, uint32_t drvfs_mount,
    unsigned int seq, size_t *out_size)
{
    /* Treat NULL strings as empty */
    if (!hostname) hostname = "";
    if (!domainname) domainname = "";
    if (!windows_hosts) windows_hosts = "";
    if (!distribution_name) distribution_name = "";
    if (!plan9_socket) plan9_socket = "";
    if (!timezone) timezone = "";

    /* Calculate string lengths (including NUL terminator) */
    size_t hlen = strlen(hostname) + 1;
    size_t dlen = strlen(domainname) + 1;
    size_t whlen = strlen(windows_hosts) + 1;
    size_t dnlen = strlen(distribution_name) + 1;
    size_t p9len = strlen(plan9_socket) + 1;
    size_t tzlen = strlen(timezone) + 1;

    size_t buffer_size = hlen + dlen + whlen + dnlen + p9len + tzlen;
    size_t msg_size = sizeof(struct wsl_init_message) + buffer_size;

    struct wsl_init_message *msg = malloc(msg_size);
    if (!msg) return NULL;
    memset(msg, 0, sizeof(*msg));

    /* Fill header */
    msg->Header.MessageType = LxInitMessageInitialize;  /* 5 */
    msg->Header.MessageSize = (unsigned int)msg_size;
    msg->Header.SequenceNumber = seq;

    /* Fill scalar fields */
    msg->DrvFsVolumesBitmap = drvfs_bitmap;
    msg->DrvFsDefaultOwner = drvfs_owner;
    msg->FeatureFlags = feature_flags;
    msg->DrvfsMount = drvfs_mount;

    /* Pack strings into Buffer[] and record offsets */
    uint32_t offset = 0;
    char *buf = msg->Buffer;  /* flexible array member — but we allocated manually */

    msg->HostnameOffset = offset;
    memcpy(buf + offset, hostname, hlen);
    offset += hlen;

    msg->DomainnameOffset = offset;
    memcpy(buf + offset, domainname, dlen);
    offset += dlen;

    msg->WindowsHostsOffset = offset;
    memcpy(buf + offset, windows_hosts, whlen);
    offset += whlen;

    msg->DistributionNameOffset = offset;
    memcpy(buf + offset, distribution_name, dnlen);
    offset += dnlen;

    msg->Plan9SocketOffset = offset;
    memcpy(buf + offset, plan9_socket, p9len);
    offset += p9len;

    msg->TimezoneOffset = offset;
    memcpy(buf + offset, timezone, tzlen);
    offset += tzlen;

    if (out_size) *out_size = msg_size;
    return msg;
}

#endif /* CONFIG_PARSER_H */
