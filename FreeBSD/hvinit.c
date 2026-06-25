/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 Balaje Sankar */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>    /* A2: for getpwnam() to resolve user.default */

#include "gns_engine.h"

/* B (DNS Tunneling): Include DNS tunneling module.
 * Must come after gns_engine.h so MESSAGE_HEADER is defined. */
#include "dns_tunneling.h"


struct sockaddr_hvs {
    unsigned char   sa_len;
    sa_family_t     sa_family;
    unsigned int    hvs_port;
unsigned char   hvs_zero[sizeof(struct sockaddr) -
                             sizeof(sa_family_t) -
                             sizeof(unsigned char) -
                             sizeof(unsigned int)];
};

#define PORT_HVS              50000  // same port for all connections
#define PORT_HVS_GNS          50001  // GNS engine channel
#define PORT_HVS_BSD          60000

// WSL message type values (from lxinitshared.h LX_MESSAGE_TYPE enum)
#define LxInitMessageCreateProcess               1
#define LxInitMessageCreateSession               2
#define LxInitMessageCreateSessionResponse       3
#define LxInitMessageInitialize                  5
#define LxInitMessageInitializeResponse          6
#define LxInitMessageTimezoneInformation          7  /* A3: host->guest timezone update */
#define LxInitMessageCreateProcessUtilityVm      8
#define LxInitMessageExitStatus                  9
#define LxInitMessageWindowSizeChanged           10
#define LxInitMessageTerminateInstance           14
#define LxMiniInitMessageCreateInstanceResult    33
#define LxMiniInitMessageGuestCapabilities       43
#define LxMessageResultUint32                    78
#define LxInitMessageOobeResult                  28  /* F1: guest->host, OOBE completion */
/* Phase 9 (Task Group C): networking message types */
#define LxInitMessageNetworkInformation           4
#define LxInitMessageStartSocketRelay            15
#define LxInitMessageQueryNetworkingMode         25
#define LxInitMessageQueryVmId                   26

/* F1: CreateProcess AllowOOBE flag (from lxinitshared.h LX_INIT_CREATE_PROCESS_FLAGS) */
#define LxInitCreateProcessFlagAllowOOBE         0x20

/* MESSAGE_HEADER, RESULT_MESSAGE_UINT32/INT32/BOOL and typedefs are provided
 * by gns_engine.h (included above). No redefinition here to avoid conflicts. */

/* A1: Include the Initialize(5) config parser after MESSAGE_HEADER is defined */
#include "config_parser.h"

/* A2: Include /etc/wsl.conf parser */
#include "wsl_conf_parser.h"

/* A3: Include timezone handler */
#include "timezone_handler.h"

/* A4: Include network configuration (hostname/hosts generation) */
#include "network_config.h"

/* B1: Include DrvFs mount module */
#include "drvfs_mount.h"

/* E1: Include binfmt_misc handler */
#include "binfmt_handler.h"

/* Group A: Include Plan9 file server module.
 * Uses lib9p on FreeBSD (hvsocket 50001), 9P stub on Linux (TCP 50001). */
#include "plan9_server.h"

/* A1: Global parsed configuration from Initialize(5) message. */
static struct wsl_config g_config;
static int g_config_parsed = 0;

/* A2: Global parsed /etc/wsl.conf configuration. */
static struct wsl_conf g_wsl_conf;
static int g_wsl_conf_parsed = 0;

typedef struct LX_INIT_GUEST_CAPABILITIES {
    MESSAGE_HEADER Header;    // full 12-byte message header
    bool SeccompAvailable;
    char Buffer[];            // kernel version string
} LX_INIT_GUEST_CAPABILITIES;

/* RESULT_MESSAGE_UINT32 is provided by gns_engine.h — no redefinition here. */

typedef struct _LX_INIT_CREATE_SESSION {
    MESSAGE_HEADER Header;
    int64_t ConsoleId;
} LX_INIT_CREATE_SESSION;

typedef struct _LX_INIT_CREATE_SESSION_RESPONSE {
    MESSAGE_HEADER Header;
    unsigned int Port;   // port to return
} LX_INIT_CREATE_SESSION_RESPONSE;


typedef struct _LX_INIT_CONFIGURATION_INFORMATION_RESPONSE {
    MESSAGE_HEADER Header;
    uint32_t Plan9Port;
    uint32_t DefaultUid;
    uint32_t InteropPort;
    bool SystemdEnabled;
    uint64_t PidNamespace;
    uint32_t FlavorIndex;
    uint32_t VersionIndex;
    char Buffer[]; // optional extra data
} LX_INIT_CONFIGURATION_INFORMATION_RESPONSE;


/* Equivalent of LX_MINI_INIT_CREATE_INSTANCE_RESULT in C */
#define LX_MINI_INIT_CREATE_INSTANCE_RESULT_TYPE 33

typedef struct _LX_MINI_INIT_CREATE_INSTANCE_RESULT {
    struct MESSAGE_HEADER Header;
    int Result;
    unsigned int FailureStep;
    uint64_t Pid;
    uint32_t ConnectPort;
    unsigned int WarningsOffset;
    char Buffer[];
} LX_MINI_INIT_CREATE_INSTANCE_RESULT;

/* Phase 1: WindowSizeChanged message (type 10) */
typedef struct _LX_INIT_WINDOW_SIZE_CHANGED {
    MESSAGE_HEADER Header;
    unsigned short Rows;
    unsigned short Columns;
} LX_INIT_WINDOW_SIZE_CHANGED;

/* Phase 1: ExitStatus message (type 9) */
typedef struct _LX_INIT_PROCESS_EXIT_STATUS {
    MESSAGE_HEADER Header;
    int ExitCode;
} LX_INIT_PROCESS_EXIT_STATUS;

/* F1: OobeResult (guest -> host, type 28)
 * Sent on a dedicated OOBE channel when the distribution's first-run
 * setup (OOBE) completes. The host blocks waiting for this message
 * when RunOOBE=true and the create-process request has an empty
 * filename/commandline with the AllowOOBE flag (0x20) set.
 *
 * Fields:
 *   Result     - 0 on success, non-zero on failure
 *   DefaultUid - configured default UID, or -1 if not present
 *
 * Reference: src/shared/inc/lxinitshared.h LX_INIT_OOBE_RESULT */
typedef struct _LX_INIT_OOBE_RESULT {
    MESSAGE_HEADER Header;
    uint32_t Result;
    int64_t DefaultUid;
} LX_INIT_OOBE_RESULT;

/* ---- Helper: reliable send/recv ---- */
/* FIX: handle EAGAIN on non-blocking sockets by polling. */
static int send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* ---- F2: Filesystem mount tracking for graceful shutdown ----
 * Each entry records the mount point path. Unmount happens in reverse
 * order (last mounted = first unmounted), mirroring the reference WSL
 * shutdown sequence in init.cpp where the guest cleans up mounted
 * filesystems (DrvFs, Plan9, etc.) before exiting. */
#define F2_MAX_MOUNTS 16
static char g_mounted_fs[F2_MAX_MOUNTS][64];
static int g_mounted_count = 0;

/* F2: Record a filesystem mount for later cleanup. */
static void fs_track_mount(const char *path)
{
    if (g_mounted_count < F2_MAX_MOUNTS) {
        strncpy(g_mounted_fs[g_mounted_count], path,
                sizeof(g_mounted_fs[g_mounted_count]) - 1);
        g_mounted_fs[g_mounted_count][sizeof(g_mounted_fs[0]) - 1] = '\0';
        g_mounted_count++;
        printf("[init] tracked mount: %s (total=%d)\n", path, g_mounted_count);
    }
}

/* F2: Unmount all tracked filesystems in reverse mount order.
 * Returns the number of successful unmounts.
 * Uses FreeBSD unmount() — the production hvinit runs on FreeBSD. */
static int fs_unmount_all(void)
{
    int unmounted = 0;
    for (int i = g_mounted_count - 1; i >= 0; i--) {
        printf("[init] unmounting %s...\n", g_mounted_fs[i]);
        int rc = unmount(g_mounted_fs[i], 0);
        if (rc < 0 && errno == EBUSY) {
            fprintf(stderr, "[init] %s busy, forcing unmount\n", g_mounted_fs[i]);
            rc = unmount(g_mounted_fs[i], MNT_FORCE);
        }
        if (rc < 0) {
            /* Log but don't fail — best-effort cleanup. */
            fprintf(stderr, "[init] unmount %s: %s\n",
                    g_mounted_fs[i], strerror(errno));
        } else {
            unmounted++;
            printf("[init] unmounted %s\n", g_mounted_fs[i]);
        }
    }
    return unmounted;
}

/* ---- F1: OobeResult sender ----
 * Send OobeResult (type 28) on the given channel.
 *
 * In the reference WSL, this is sent on a dedicated OOBE channel when
 * the distribution's first-run setup completes. The host blocks waiting
 * for this message when RunOOBE=true and the create-process request
 * has AllowOOBE flag (0x20) set with empty filename/commandline.
 *
 * For the FreeBSD port, we send it on the init channel after the
 * handshake completes. The host reads it to unblock session creation.
 *
 * Parameters:
 *   fd          - channel to send on (typically init_fd)
 *   result      - 0 on success, non-zero on failure
 *   default_uid - configured default UID, or -1 if not present
 *
 * Reference: src/linux/init/init.cpp lines 642-648,
 *            src/shared/inc/lxinitshared.h LX_INIT_OOBE_RESULT */
static void send_oobe_result(int fd, uint32_t result, int64_t default_uid)
{
    LX_INIT_OOBE_RESULT msg;
    memset(&msg, 0, sizeof(msg));
    msg.Header.MessageType = LxInitMessageOobeResult;
    msg.Header.MessageSize = sizeof(msg);
    msg.Header.SequenceNumber = 1;  /* first message on the OOBE channel */
    msg.Result = result;
    msg.DefaultUid = default_uid;

    if (send_all(fd, &msg, sizeof(msg)) < 0) {
        perror("[init] send OobeResult");
    } else {
        printf("[init] sent OobeResult (type=%u, size=%u, Result=%u, DefaultUid=%lld)\n",
               msg.Header.MessageType, msg.Header.MessageSize,
               msg.Result, (long long)msg.DefaultUid);
    }
}

/* ---- Phase 1: File system initialization ---- */
static void initialize_filesystems(void)
{
    struct stat st;

    /* /dev — devfs */
    if (stat("/dev", &st) != 0) mkdir("/dev", 0755);
    if (mount("devfs", "/dev", 0, NULL) < 0)
        perror("[init] mount devfs (may already be mounted)");
    else
        fs_track_mount("/dev");

    /* /proc — linprocfs (Linux-compatible procfs on FreeBSD) */
    if (stat("/proc", &st) != 0) mkdir("/proc", 0555);
    if (mount("linprocfs", "/proc", 0, NULL) < 0)
        perror("[init] mount linprocfs (may already be mounted)");
    else
        fs_track_mount("/proc");

    /* /run — tmpfs */
    if (stat("/run", &st) != 0) mkdir("/run", 0755);
    if (mount("tmpfs", "/run", 0, NULL) < 0)
        perror("[init] mount tmpfs (may already be mounted)");
    else
        fs_track_mount("/run");

    printf("[init] filesystems initialized (devfs, linprocfs, tmpfs)\n");
}

/* ---- Phase 1: Signal handling ---- */
static int g_sigchld_pipe[2];

/* C1: GNS engine child process */
static pid_t g_gns_pid = -1;

/* B: DNS tunneling channel fd passed to the GNS child. -1 = disabled. */
static int g_dns_channel_fd = -1;

static int hv_connect(unsigned int port);

static void gns_configure_test_paths(void)
{
    const char *test_root = getenv("WSL_TEST_ROOT");
    if (test_root && test_root[0]) {
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/resolv.conf", test_root);
        if (n > 0 && (size_t)n < sizeof(path)) {
            gns_set_resolvconf_path(path);
            printf("[init] WSL_TEST_ROOT: resolv.conf -> %s\n", path);
        }
    }
}

static void gns_stop_engine(void)
{
    if (g_gns_pid > 0) {
        kill(g_gns_pid, SIGTERM);
        waitpid(g_gns_pid, NULL, 0);
        printf("[init] GNS engine stopped (pid=%d)\n", (int)g_gns_pid);
        g_gns_pid = -1;
    }
}

static void gns_start_engine(int cap_fd, int notify_fd, int init_fd)
{
    int gns_fd = hv_connect(PORT_HVS_GNS);
    if (gns_fd < 0) {
        fprintf(stderr, "[init] GNS channel connect failed (non-fatal)\n");
        return;
    }

    /* B (DNS Tunneling): if the host requested DNS tunneling, open a second
     * channel to PORT_HVS that the GNS child uses to relay DNS packets.
     * The host accepts this extra connection only when the feature flag is
     * set, so a failure here is fatal only when DNS tunneling is required. */
    int dns_fd = -1;
    if (g_dns_channel_fd >= 0) {
        /* The init process already opened it; just take ownership. */
        dns_fd = g_dns_channel_fd;
        g_dns_channel_fd = -1;
    } else if (g_config_parsed && (g_config.feature_flags & 0x20 /*LxInitFeatureDnsTunneling*/)) {
        dns_fd = hv_connect(PORT_HVS);
        if (dns_fd < 0) {
            fprintf(stderr, "[init] DNS tunneling channel connect failed (non-fatal)\n");
        } else {
            printf("[init] DNS tunneling channel opened (fd=%d)\n", dns_fd);
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("[init] gns fork");
        close(gns_fd);
        if (dns_fd >= 0) close(dns_fd);
        return;
    }
    if (pid == 0) {
        close(cap_fd);
        if (notify_fd >= 0) close(notify_fd);
        close(init_fd);

        /* B: If DNS tunneling is enabled, start the DNS relay in a
         * grandchild process so it runs concurrently with the GNS loop.
         * Both the GNS channel and the DNS channel are owned by the
         * GNS child; the DNS relay gets only the DNS channel. */
        if (dns_fd >= 0) {
            pid_t dns_pid = fork();
            if (dns_pid < 0) {
                perror("[init] dns tunnel fork");
                close(dns_fd);
            } else if (dns_pid == 0) {
                close(gns_fd);  /* DNS relay does not use the GNS channel */
                struct dns_tunnel tunnel;
                memset(&tunnel, 0, sizeof(tunnel));
                tunnel.channel_fd = dns_fd;

                /* Tests override the listen IP via WSL_DNS_TUNNEL_IP so they
                 * can bind 127.0.0.1 instead of 10.255.255.254. Production
                 * uses the canonical 10.255.255.254 from lxinitshared.h. */
                const char *ip = getenv("WSL_DNS_TUNNEL_IP");
                dns_tunnel_run(&tunnel, ip);
                _exit(0);
            } else {
                printf("[init] DNS tunneling relay started (pid=%d)\n", (int)dns_pid);
                close(dns_fd);
            }
        }

        gns_engine_loop(gns_fd);
        _exit(0);
    }

    close(gns_fd);
    if (dns_fd >= 0) close(dns_fd);
    g_gns_pid = pid;
    printf("[init] GNS engine started (pid=%d)\n", (int)pid);
}

static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_sigchld_pipe[1] >= 0) {
        ssize_t wr = write(g_sigchld_pipe[1], "c", 1);
        (void)wr;
    }
}

static void reap_children(void)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        printf("[init] child pid %d exited (status=%d)\n", pid, status);
    }
}

/* ---- Phase 1: Message handlers ---- */

/* F2: Handle TerminateInstance (type 14) — graceful shutdown.
 *
 * Enhanced from Phase 1's simple sync()+exit() to a proper cleanup sequence:
 *   1. Send ResultUint32 response (acknowledge the request)
 *   2. Unmount all tracked filesystems in reverse mount order
 *   3. sync() to flush all pending filesystem writes
 *   4. exit(0)
 *
 * This mirrors the reference WSL shutdown sequence in init.cpp where
 * the guest cleans up mounted filesystems (DrvFs, Plan9, etc.) before
 * exiting. For the FreeBSD port, we unmount devfs/linprocfs/tmpfs that
 * were mounted during initialize_filesystems().
 *
 * Edge cases:
 *   - Unmount failure (EBUSY): retry with MNT_FORCE, log but continue
 *   - No tracked mounts: skip unmount step entirely
 *   - Double TerminateInstance: first call exits before second can arrive */
static void handle_terminate_instance(int init_fd, MESSAGE_HEADER *hdr)
{
    printf("[init] received TerminateInstance, initiating graceful shutdown\n");

    /* 1. Send success response immediately so the host knows we're shutting down */
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = hdr->SequenceNumber;
    resp.Result = 0;
    send_all(init_fd, &resp, sizeof(resp));
    printf("[init] sent TerminateInstance response (seq=%u, result=0)\n",
           hdr->SequenceNumber);

    /* 2. Stop GNS engine child */
    gns_stop_engine();

    /* Group A: Stop Plan9 file server (force=true for shutdown) */
    if (plan9_is_running()) {
        printf("[init] stopping Plan9 server for shutdown\n");
        plan9_stop_server(true);
    }

    /* 3. Unmount tracked filesystems in reverse order */
    if (g_mounted_count > 0) {
        printf("[init] unmounting %d filesystem(s)...\n", g_mounted_count);
        int unmounted = fs_unmount_all();
        printf("[init] unmounted %d/%d filesystem(s)\n", unmounted, g_mounted_count);
    }

    /* 3. Sync to flush all pending writes */
    sync();
    printf("[init] sync complete, exiting\n");

    /* 4. Exit */
    exit(0);
}

/* Handle WindowSizeChanged (type 10): forward to notify channel */
static void handle_window_size_changed(int notify_fd, void *msg_buf, size_t msg_size)
{
    if (msg_size < sizeof(LX_INIT_WINDOW_SIZE_CHANGED)) return;
    LX_INIT_WINDOW_SIZE_CHANGED *wsc = (LX_INIT_WINDOW_SIZE_CHANGED *)msg_buf;
    printf("[init] WindowSizeChanged: rows=%u, cols=%u\n", wsc->Rows, wsc->Columns);

    /* Forward to hvbridge via notify channel (if open) */
    if (notify_fd >= 0) {
        send_all(notify_fd, msg_buf, msg_size);
    }
}

/* ---- Phase 1: Event loop ---- */
static void event_loop(int init_fd, int notify_fd)
{
    printf("[init] entering event loop (init_fd=%d, notify_fd=%d)\n", init_fd, notify_fd);

    /* FIX: set init_fd non-blocking so recv_all can handle partial reads
     * without blocking the event loop (and missing SIGCHLD). */
    fcntl(init_fd, F_SETFL, fcntl(init_fd, F_GETFL) | O_NONBLOCK);

    /* Set up SIGCHLD handling via self-pipe */
    if (pipe(g_sigchld_pipe) < 0) {
        perror("[init] pipe");
        g_sigchld_pipe[0] = g_sigchld_pipe[1] = -1;
    } else {
        fcntl(g_sigchld_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(g_sigchld_pipe[1], F_SETFL, O_NONBLOCK);
        signal(SIGCHLD, sigchld_handler);
    }

    for (;;) {
        struct pollfd pfds[2];
        int nfds = 0;

        pfds[nfds].fd = init_fd;
        pfds[nfds].events = POLLIN;
        nfds++;

        if (g_sigchld_pipe[0] >= 0) {
            pfds[nfds].fd = g_sigchld_pipe[0];
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        int rc = poll(pfds, nfds, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[init] poll");
            break;
        }

        /* SIGCHLD received — reap zombie children */
        if (nfds > 1 && (pfds[1].revents & POLLIN)) {
            char c;
            while (read(g_sigchld_pipe[0], &c, 1) > 0) {}
            reap_children();
        }

        /* Message from host on init channel */
        if (pfds[0].revents & POLLIN) {
            MESSAGE_HEADER hdr;
            if (recv_all(init_fd, &hdr, sizeof(hdr)) < 0) {
                printf("[init] host disconnected from init channel\n");
                break;
            }

            if (hdr.MessageSize < sizeof(hdr)) {
                printf("[init] invalid message size %u\n", hdr.MessageSize);
                continue;
            }

            /* Read payload */
            size_t payload_len = hdr.MessageSize - sizeof(hdr);
            char *payload = NULL;
            if (payload_len > 0) {
                payload = malloc(payload_len);
                if (!payload) { perror("[init] malloc"); break; }
                if (recv_all(init_fd, payload, payload_len) < 0) {
                    printf("[init] failed to read payload\n");
                    free(payload);
                    break;
                }
            }

            /* Dispatch based on message type */
            char *full_msg = malloc(hdr.MessageSize);
            if (full_msg) {
                memcpy(full_msg, &hdr, sizeof(hdr));
                if (payload_len > 0)
                    memcpy(full_msg + sizeof(hdr), payload, payload_len);

                switch (hdr.MessageType) {
                case LxInitMessageTerminateInstance:
                    handle_terminate_instance(init_fd, &hdr);
                    break; /* not reached */

                case LxInitMessageWindowSizeChanged:
                    handle_window_size_changed(notify_fd, full_msg, hdr.MessageSize);
                    break;

                /* Phase 9 (Task Group C): networking messages */
                case LxInitMessageNetworkInformation:
                    gns_handle_network_information(full_msg, hdr.MessageSize);
                    break;

                /* A3: TimezoneInformation(7) — host pushes timezone update */
                case LxInitMessageTimezoneInformation: {
                    int auto_tz = g_wsl_conf_parsed
                                  ? g_wsl_conf.time_use_windows_timezone : 1;
                    timezone_handle_message(full_msg, hdr.MessageSize, auto_tz);
                    break;
                }

                case LxInitMessageStartSocketRelay: {
                    struct relay_state rs;
                    memset(&rs, 0, sizeof(rs));
                    int r = gns_handle_start_socket_relay(init_fd, full_msg,
                                                          hdr.MessageSize, &rs);
                    if (r < 0) {
                        fprintf(stderr, "[init] StartSocketRelay failed\n");
                    }
                    break;
                }

                case LxInitMessageQueryNetworkingMode:
                    gns_handle_query_networking_mode(init_fd, full_msg,
                                                    hdr.MessageSize);
                    break;

                case LxInitMessageQueryVmId:
                    gns_handle_query_vm_id(init_fd, full_msg, hdr.MessageSize);
                    break;

                /* B1: RemountDrvfs(13) — host requests DrvFs remount in namespace.
                 * Parses LX_INIT_MOUNT_DRVFS message, mounts specified volumes,
                 * sends RESULT_MESSAGE_INT32 response.
                 * Reference: init.cpp line 2448, config.cpp ConfigRemountDrvFsImpl() */
                case LxInitMessageRemountDrvfs: {
                    if (hdr.MessageSize < sizeof(LX_INIT_MOUNT_DRVFS)) {
                        fprintf(stderr, "[init] B1: RemountDrvfs too small (%u < %zu)\n",
                                hdr.MessageSize, sizeof(LX_INIT_MOUNT_DRVFS));
                        RESULT_MESSAGE_INT32 resp;
                        memset(&resp, 0, sizeof(resp));
                        resp.Header.MessageType = LxMessageResultInt32;
                        resp.Header.MessageSize = sizeof(resp);
                        resp.Header.SequenceNumber = hdr.SequenceNumber;
                        resp.Result = -1;
                        send_all(init_fd, &resp, sizeof(resp));
                        break;
                    }
                    LX_INIT_MOUNT_DRVFS *mnt = (LX_INIT_MOUNT_DRVFS *)full_msg;
                    printf("[init] B1: RemountDrvfs admin=%d volumes=0x%08x uid=%d\n",
                           mnt->Admin, mnt->VolumesToMount, mnt->DefaultOwnerUid);

                    const char *prefix = (g_wsl_conf_parsed &&
                                          g_wsl_conf.automount_root)
                                         ? g_wsl_conf.automount_root : "/mnt";
                    const char *opts = (g_wsl_conf_parsed &&
                                        g_wsl_conf.automount_options)
                                       ? g_wsl_conf.automount_options : NULL;
                    int mounted = drvfs_mount_volumes(mnt->VolumesToMount,
                                                       (uid_t)mnt->DefaultOwnerUid,
                                                       mnt->Admin ? 1 : 0,
                                                       prefix, opts,
                                                       g_config_parsed
                                                       ? g_config.feature_flags : 0,
                                                       fs_track_mount);

                    RESULT_MESSAGE_INT32 resp;
                    memset(&resp, 0, sizeof(resp));
                    resp.Header.MessageType = LxMessageResultInt32;
                    resp.Header.MessageSize = sizeof(resp);
                    resp.Header.SequenceNumber = hdr.SequenceNumber;
                    resp.Result = 0;
                    send_all(init_fd, &resp, sizeof(resp));
                    printf("[init] B1: RemountDrvfs response sent (result=0, mounted=%d)\n",
                           mounted);
                    break;
                }

                /* Group A: StopPlan9Server(24) — host requests Plan9 server shutdown.
                 * Force=true terminates immediately; Force=false attempts graceful stop.
                 * Responds with RESULT_MESSAGE<bool>.
                 * Reference: plan9.cpp StopPlan9Server(), RunPlan9ControlFile() */
                case LxInitMessageStopPlan9Server: {
                    if (hdr.MessageSize < sizeof(LX_INIT_STOP_PLAN9_SERVER_MSG)) {
                        fprintf(stderr, "[init] Group A: StopPlan9Server too small\n");
                        RESULT_MESSAGE_BOOL resp;
                        memset(&resp, 0, sizeof(resp));
                        resp.Header.MessageType = LxMessageResultBool;
                        resp.Header.MessageSize = sizeof(resp);
                        resp.Header.SequenceNumber = hdr.SequenceNumber;
                        resp.Result = false;
                        send_all(init_fd, &resp, sizeof(resp));
                        break;
                    }
                    LX_INIT_STOP_PLAN9_SERVER_MSG *stop =
                        (LX_INIT_STOP_PLAN9_SERVER_MSG *)full_msg;
                    printf("[init] Group A: StopPlan9Server force=%d\n",
                           stop->Force);
                    bool ok = plan9_stop_server(stop->Force);

                    RESULT_MESSAGE_BOOL resp;
                    memset(&resp, 0, sizeof(resp));
                    resp.Header.MessageType = LxMessageResultBool;
                    resp.Header.MessageSize = sizeof(resp);
                    resp.Header.SequenceNumber = hdr.SequenceNumber;
                    resp.Result = ok;
                    send_all(init_fd, &resp, sizeof(resp));
                    printf("[init] Group A: StopPlan9Server response sent (result=%d)\n",
                           ok);
                    break;
                }

                default:
                    printf("[init] unhandled message type %u (size=%u, seq=%u)\n",
                           hdr.MessageType, hdr.MessageSize, hdr.SequenceNumber);
                    break;
                }
                free(full_msg);
            }
            free(payload);
        }
    }
}

void send_create_session_response(int init_fd, unsigned int port, unsigned int seq)
{
    LX_INIT_CREATE_SESSION_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));

    resp.Header.MessageType = LxInitMessageCreateSessionResponse;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq; // echo host's sequence number
    resp.Port = port;

    ssize_t sent = send(init_fd, &resp, sizeof(resp), 0);
    if (sent < 0) {
        perror("[init] send create_session_response");
    } else {
        printf("[init] sent LX_INIT_CREATE_SESSION_RESPONSE (%zd bytes)\n", sent);
    }
}

void handle_create_process_utility_vm(int sock)
{
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <=0) {
        perror("recv");
        return;
    }

    // Just to show we got the request:
    printf("Received LX_INIT_CREATE_PROCESS_UTILITY_VM message (%zd bytes)\n", n);

    // Build RESULT_MESSAGE<uint32_t> with port=60000
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = 4;
    resp.Result = PORT_HVS_BSD;

    // Send back
    if (send(sock, &resp, sizeof(resp), 0) != sizeof(resp)) {
        perror("send");
    } else {
        printf("Sent RESULT_MESSAGE<uint32_t> with Type=%u Seq=%u Port=%u\n",
               resp.Header.MessageType, resp.Header.SequenceNumber, resp.Result);
    }
}

void send_configuration_info_response(int init_fd, unsigned int seq) {
    const char *flavor = "GenericFlavor";
    const char *version = "1.0.0";

    size_t payload_len = strlen(flavor) + 1 + strlen(version) + 1;
    size_t msglen = sizeof(LX_INIT_CONFIGURATION_INFORMATION_RESPONSE) + payload_len;

    LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *resp = malloc(msglen);
    if (!resp) { perror("malloc"); return; }
    memset(resp, 0, msglen);

    // Fill MESSAGE_HEADER - echo host's sequence number
    resp->Header.MessageType = LxInitMessageInitializeResponse;
    resp->Header.MessageSize = (unsigned int)msglen;
    resp->Header.SequenceNumber = seq;

    /* A1: Use parsed config values when available, otherwise use defaults.
     * Group A: Plan9Port comes from plan9_start_server() (50001 if running).
     * InteropPort is PORT_HVS_BSD (the bridge listen port).
     * SystemdEnabled is always false for FreeBSD. */
    resp->Plan9Port = plan9_get_port();  /* Group A: Plan9 file server port */
    resp->DefaultUid = g_config_parsed ? g_config.drvfs_default_owner : 1;
    resp->InteropPort = PORT_HVS_BSD;
    resp->SystemdEnabled = false;  /* FreeBSD does not use systemd */
    resp->PidNamespace = 0;        /* Not using PID namespaces */
    resp->FlavorIndex = 0;         /* Offset of flavor string in Buffer */
    resp->VersionIndex = (unsigned int)(strlen(flavor) + 1); /* Offset of version */

    // Copy strings sequentially in Buffer
    char *buf_ptr = resp->Buffer;
    strcpy(buf_ptr, flavor);
    buf_ptr += strlen(flavor) + 1;
    strcpy(buf_ptr, version);

    ssize_t sent = send(init_fd, resp, msglen, 0);
    if (sent < 0) {
        perror("[init] send configuration_info_response");
    } else {
        printf("[init] sent LX_INIT_CONFIGURATION_INFORMATION_RESPONSE (%zd bytes, DefaultUid=%u)\n",
               sent, resp->DefaultUid);
    }

    free(resp);
}

void send_create_instance_result(int init_fd)
{
    const char *warning_str = "No warnings";

    size_t payload_len = strlen(warning_str) + 1;
    size_t msglen = sizeof(LX_MINI_INIT_CREATE_INSTANCE_RESULT) + payload_len;

    LX_MINI_INIT_CREATE_INSTANCE_RESULT *msg = malloc(msglen);
    if (!msg) { perror("malloc"); return; }

    // Fill header
    msg->Header.MessageType = LxMiniInitMessageCreateInstanceResult;
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1; // first message from guest

    // Fill message fields
    msg->Result = 0;            // success
    msg->FailureStep = 0;       // example
    msg->Pid = 1;
    msg->ConnectPort = PORT_HVS_BSD;
    msg->WarningsOffset = 0;    // offset in Buffer

    // Copy Buffer content
    strcpy(msg->Buffer, warning_str);

    // Send over init_fd
    ssize_t sent = send(init_fd, msg, msglen, 0);
    if (sent < 0) {
        perror("[init] send create_instance_result");
    } else {
        printf("[init] sent LX_MINI_INIT_CREATE_INSTANCE_RESULT (%zd bytes)\n", sent);
    }

    free(msg);
}

static int hv_connect(unsigned int port) {
    int s = socket(AF_HYPERV, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_hvs addr;
    memset(&addr, 0, sizeof(addr));
    addr.sa_len = sizeof(addr);
    addr.sa_family = AF_HYPERV;
    addr.hvs_port = port;

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(s);
        return -1;
    }
    return s;
}

int main(void) {
    gns_configure_test_paths();

    /* Phase 1: Initialize filesystems before handshake */
    initialize_filesystems();

    /* === 1. Capability socket === */
    int cap_fd = hv_connect(PORT_HVS);
    if (cap_fd < 0) {
        fprintf(stderr, "Failed to establish capability socket\n");
        return 1;
    }

    const char *kver = "FreeBSD-13.3-HVPoC";
    size_t msglen = sizeof(LX_INIT_GUEST_CAPABILITIES) + strlen(kver) + 1;
    LX_INIT_GUEST_CAPABILITIES *msg = malloc(msglen);
    msg->Header.MessageType = LxMiniInitMessageGuestCapabilities;
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1;
    msg->SeccompAvailable = false;
    strcpy(msg->Buffer, kver);

    if (send(cap_fd, msg, msglen, 0) < 0) {
        perror("send mini_init");
        free(msg);
        close(cap_fd);
        return 1;
    }
    free(msg);

printf("[capability] sent capabilities: %s\n", kver);

    /* === 2. Notify socket === */
    int notify_fd = hv_connect(PORT_HVS);
    if (notify_fd < 0) {
        fprintf(stderr, "Failed to establish notify socket\n");
        // continue anyway, still have cap_fd
    } else {
        printf("[notify] socket connected (fd=%d)\n", notify_fd);
    }
    /* === 3. Receive first message on capability socket === */
    char buf[256];
    ssize_t r = recv(cap_fd, buf, sizeof(buf)-1, 0);
    if (r > 0) {
        buf[r] = '\0';
        printf("[capability] first message received (%zd bytes): %s\n", r, buf);
    } else if (r == 0) {
printf("[capability] Host closed connection before first message\n");
        close(cap_fd);
        if (notify_fd >= 0) close(notify_fd);
        return 1;
    } else {
        perror("[capability] recv");
        close(cap_fd);
        if (notify_fd >= 0) close(notify_fd);
        return 1;
    }
    /* === 4. Create init socket after first message === */
    int init_fd = hv_connect(PORT_HVS);
    if (init_fd < 0) {
        fprintf(stderr, "Failed to establish init socket\n");
    } else {
        printf("[init] socket connected (fd=%d)\n", init_fd);
    }
    /* === 5. Keep all three sockets open === */
    printf("[main] All sockets are open: cap_fd=%d notify_fd=%d init_fd=%d\n",
           cap_fd, notify_fd, init_fd);
    printf("Press Ctrl+C to exit; sockets stay open.\n");
    send_create_instance_result(init_fd);

//handle send and receive message from void WslCoreInstance::Initialize()

/* A1: Receive Initialize(5) message — read header first, then payload.
 * The message may contain a full LX_INIT_CONFIGURATION_INFORMATION with
 * variable-length Buffer[] (hostname, timezone, etc.), so we must read
 * MessageSize bytes total, not just a fixed buffer. */
{
    MESSAGE_HEADER init_hdr;
    ssize_t r_hdr = recv(init_fd, &init_hdr, sizeof(init_hdr), 0);
    if (r_hdr != (ssize_t)sizeof(init_hdr)) {
        perror("[init] recv Initialize header");
    } else if (init_hdr.MessageSize < sizeof(init_hdr)) {
        fprintf(stderr, "[init] invalid Initialize size %u\n", init_hdr.MessageSize);
    } else {
        size_t payload_len = init_hdr.MessageSize - sizeof(init_hdr);
        char *full_msg = malloc(init_hdr.MessageSize);
        if (!full_msg) {
            perror("[init] malloc Initialize");
        } else {
            memcpy(full_msg, &init_hdr, sizeof(init_hdr));
            if (payload_len > 0) {
                ssize_t r_body = recv(init_fd, full_msg + sizeof(init_hdr),
                                      payload_len, 0);
                if (r_body != (ssize_t)payload_len) {
                    fprintf(stderr, "[init] short read Initialize body: expected %zu, got %zd\n",
                            payload_len, r_body);
                    free(full_msg);
                    full_msg = NULL;
                }
            }

            if (full_msg) {
                printf("[init] received Initialize (type=%u, seq=%u, size=%u)\n",
                       init_hdr.MessageType, init_hdr.SequenceNumber,
                       init_hdr.MessageSize);

                /* A1: Parse the full Initialize message into g_config */
                wsl_config_init(&g_config);
                if (wsl_config_parse(&g_config, full_msg, init_hdr.MessageSize) == 0) {
                    g_config_parsed = 1;
                    wsl_config_dump(&g_config);

                    /* A1: Set WSL_DISTRO_NAME environment variable from config.
                     * This is used by interop and wslpath to identify the distro. */
                    if (g_config.distribution_name) {
                        setenv("WSL_DISTRO_NAME", g_config.distribution_name, 1);
                        printf("[init] set WSL_DISTRO_NAME=%s\n", g_config.distribution_name);
                    }

                    /* A1: Export feature flags as hex string for mount.drvfs
                     * (mirrors config.cpp line 682). */
                    char flags_str[16];
                    snprintf(flags_str, sizeof(flags_str), "%x", g_config.feature_flags);
                    setenv("WSL_FEATURE_FLAGS", flags_str, 1);
                } else {
                    printf("[init] Initialize message too small for full parse, using defaults\n");
                    /* Still send a response with default values */
                }

                /* A2: Parse /etc/wsl.conf after Initialize message.
                 * This reads per-distribution settings (automount, interop,
                 * network, user.default, etc.) and applies them.
                 * If user.default is set, look up the UID via getpwnam()
                 * and override DefaultUid (mirrors config.cpp:692). */
                wsl_conf_init(&g_wsl_conf);
                if (wsl_conf_parse_file(&g_wsl_conf, "/etc/wsl.conf") == 0) {
                    g_wsl_conf_parsed = 1;
                    wsl_conf_dump(&g_wsl_conf);

                    /* A2: If user.default is set, resolve UID and override DefaultUid */
                    if (g_wsl_conf.user_default && g_config_parsed) {
                        struct passwd *pw = getpwnam(g_wsl_conf.user_default);
                        if (pw) {
                            g_config.drvfs_default_owner = pw->pw_uid;
                            printf("[init] wsl.conf user.default='%s' -> UID=%u\n",
                                   g_wsl_conf.user_default, g_config.drvfs_default_owner);
                        } else {
                            fprintf(stderr, "[init] wsl.conf user.default='%s' not found\n",
                                    g_wsl_conf.user_default);
                        }
                    }
                }

                /* A3: Apply timezone from Initialize(5) message.
                 * The timezone is an IANA identifier (e.g. "Asia/Shanghai")
                 * extracted from the message's TimezoneOffset field.
                 * Gated by time.useWindowsTimezone (default true).
                 * Reference: config.cpp line 876, timezone.cpp UpdateTimezone() */
                if (g_config_parsed && g_config.timezone) {
                    int auto_tz = g_wsl_conf_parsed
                                  ? g_wsl_conf.time_use_windows_timezone : 1;
                    timezone_apply(g_config.timezone, auto_tz);
                }

                /* A4: Set hostname and generate /etc/hosts.
                 * The hostname comes from Initialize(5) message, optionally
                 * overridden by [network] hostname in /etc/wsl.conf.
                 * /etc/hosts generation is gated by generateHosts (default true).
                 * Reference: config.cpp ConfigInitializeInstance() lines 738-837 */
                if (g_config_parsed) {
                    const char *conf_host = g_wsl_conf_parsed
                                            ? g_wsl_conf.network_hostname : NULL;
                    network_apply_hostname(g_config.hostname, conf_host);
                    network_apply_domainname(g_config.domainname);

                    int gen_hosts = g_wsl_conf_parsed
                                    ? g_wsl_conf.network_generate_hosts : 1;
                    network_generate_hosts(g_config.hostname,
                                           g_config.domainname,
                                           g_config.windows_hosts,
                                           gen_hosts);
                }

                /* B1: Mount DrvFs volumes if automount is enabled.
                 * Triggered by Initialize(5) DrvfsMount field (None/NonElevated/Elevated)
                 * and DrvFsVolumesBitmap (bit 0=A:, bit 2=C:, etc.).
                 * Mount prefix and options come from /etc/wsl.conf [automount].
                 * Best-effort: mount failures are logged but non-fatal.
                 * Reference: config.cpp ConfigMountDrvFsVolumes() lines 1913-2022,
                 *            drvfs.cpp MountDrvfs() lines 306-403 */
                if (g_config_parsed && g_config.drvfs_mount != 0) {
                    int auto_mount = g_wsl_conf_parsed
                                     ? g_wsl_conf.automount_enabled : 1;
                    if (auto_mount) {
                        const char *prefix = (g_wsl_conf_parsed &&
                                              g_wsl_conf.automount_root)
                                             ? g_wsl_conf.automount_root : "/mnt";
                        const char *opts = (g_wsl_conf_parsed &&
                                            g_wsl_conf.automount_options)
                                           ? g_wsl_conf.automount_options : NULL;
                        printf("[init] B1: mounting DrvFs volumes (mount=%u, bitmap=0x%08x)\n",
                               g_config.drvfs_mount, g_config.drvfs_volumes_bitmap);
                        drvfs_mount_volumes(g_config.drvfs_volumes_bitmap,
                                            g_config.drvfs_default_owner,
                                            g_config.drvfs_elevated,
                                            prefix, opts,
                                            g_config.feature_flags,
                                            fs_track_mount);
                    } else {
                        printf("[init] B1: DrvFs automount disabled by wsl.conf\n");
                    }
                }

                /* E1: Register binfmt_misc WSLInterop handler.
                 * Allows Windows PE executables to be run from the guest
                 * by relaying to the host via the interop channel.
                 * Gated by boot.protectBinfmt (default true).
                 * On FreeBSD: skipped gracefully (no binfmt_misc). */
                {
                    int protect = g_wsl_conf_parsed
                                  ? g_wsl_conf.boot_protect_binfmt : 1;
                    binfmt_setup(protect);
                }

                /* E2: Execute boot.command from /etc/wsl.conf.
                 * Runs a custom startup command before the main event loop.
                 * Failures are logged but non-fatal.
                 * Reference: config.cpp ConfigInitializeInstance() line 858 */
                if (g_wsl_conf_parsed && g_wsl_conf.boot_command) {
                    printf("[init] E2: executing boot.command: '%s'\n",
                           g_wsl_conf.boot_command);
                    int rc = system(g_wsl_conf.boot_command);
                    if (rc == -1) {
                        perror("[init] boot.command system() failed");
                    } else if (rc != 0) {
                        fprintf(stderr, "[init] boot.command exited with code %d\n",
                                WEXITSTATUS(rc));
                    } else {
                        printf("[init] E2: boot.command completed successfully\n");
                    }
                }

                /* E3: Apply wsl.conf network.generateResolvConf setting.
                 * When false, GNS engine skips writing /etc/resolv.conf. */
                {
                    int gen_resolv = g_wsl_conf_parsed
                                     ? g_wsl_conf.network_generate_resolvconf : 1;
                    g_generate_resolvconf = gen_resolv;
                    printf("[init] E3: generateResolvConf=%d\n", gen_resolv);
                }

                /* E3: Apply interop.appendWindowsPath setting.
                 * When true (default), Windows PATH is appended to guest PATH.
                 * Stored as env var for interop server and bridge to check. */
                {
                    int append_path = g_wsl_conf_parsed
                                      ? g_wsl_conf.interop_append_windows_path : 1;
                    setenv("WSL_APPEND_WINDOWS_PATH",
                           append_path ? "1" : "0", 1);
                    printf("[init] E3: appendWindowsPath=%d\n", append_path);
                }

                /* Group A: Start Plan9 file server before sending InitializeResponse.
                 * The server exposes the guest filesystem to the Windows host
                 * for \\wsl$\ access. Uses lib9p on FreeBSD (hvsocket 50001),
                 * 9P stub on Linux test (TCP 50001).
                 * Reference: plan9.cpp StartPlan9Server() */
                {
                    unsigned int p9port = plan9_start_server();
                    if (p9port > 0) {
                        printf("[init] Group A: Plan9 server started on port %u\n",
                               p9port);
                    } else {
                        fprintf(stderr, "[init] Group A: Plan9 server failed to start"
                                " (non-fatal, continuing)\n");
                    }
                }

                send_configuration_info_response(init_fd, init_hdr.SequenceNumber);
                free(full_msg);
            }
        }
    }
}

// --- 6. Receive LX_INIT_CREATE_SESSION ---
LX_INIT_CREATE_SESSION create_sess;
ssize_t r2 = recv(init_fd, &create_sess, sizeof(create_sess), 0);
if (r2 <= 0) {
    perror("[init] recv create_session");
} else {
    printf("[init] received LX_INIT_CREATE_SESSION (%zd bytes): ConsoleId=%lld\n",
           r2, (long long)create_sess.ConsoleId);

    // Send back LX_INIT_CREATE_SESSION_RESPONSE
    // echo the sequence number from host
    send_create_session_response(init_fd, PORT_HVS_BSD, create_sess.Header.SequenceNumber);
}

/* F1: Send OobeResult (type 28) after handshake completes.
 * The host reads this to unblock session creation when RunOOBE=true.
 * DefaultUid comes from the parsed Initialize(5) config (DrvFsDefaultOwner),
 * or -1 if no config was parsed. */
{
    int64_t oobe_uid = -1;
    if (g_config_parsed && g_config.drvfs_default_owner != 0)
        oobe_uid = (int64_t)g_config.drvfs_default_owner;
    send_oobe_result(init_fd, 0, oobe_uid);
}

/* C1: Start GNS engine on dedicated channel (parallel to event loop) */
gns_start_engine(cap_fd, notify_fd, init_fd);

// --- 7. Receive and echo LX_INIT_CREATE_PROCESS_UTILITY_VM ---
// handle_create_process_utility_vm(init_fd);

    /* Phase 1: Enter event loop (replaces pause()) */
    event_loop(init_fd, notify_fd);

    /* A1: Free parsed config */
    if (g_config_parsed) {
        wsl_config_free(&g_config);
        g_config_parsed = 0;
    }

    /* A2: Free parsed wsl.conf */
    if (g_wsl_conf_parsed) {
        wsl_conf_free(&g_wsl_conf);
        g_wsl_conf_parsed = 0;
    }

    /* Clean up (only reached if event loop exits) */
    gns_stop_engine();
    close(cap_fd);
    if (notify_fd >= 0) close(notify_fd);
    if (init_fd >= 0) close(init_fd);
    return 0;
}
