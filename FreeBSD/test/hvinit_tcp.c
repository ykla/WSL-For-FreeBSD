/*
 * SPDX-License-Identifier: MIT
 *
 * hvinit_tcp.c - TCP-adapted version of hvinit.c for local testing.
 *
 * Replaces AF_HYPERV with AF_INET so the guest can run on Linux.
 * Protocol logic is identical to the Phase 0 fixed hvinit.c.
 */
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>    /* A2: for getpwnam() to resolve user.default */

#include "wsl_protocol.h"

/* A1: Include config parser from parent directory.
 * wsl_protocol.h already defines struct MESSAGE_HEADER and LxInitMessageInitialize. */
#include "../config_parser.h"

/* A2: Include /etc/wsl.conf parser */
#include "../wsl_conf_parser.h"

/* A3: Include timezone handler */
#include "../timezone_handler.h"

/* A4: Include network configuration (hostname/hosts generation) */
#include "../network_config.h"

/* B1: Include DrvFs mount module */
#include "../drvfs_mount.h"

/* E1: Include binfmt_misc handler */
#include "../binfmt_handler.h"

/* Group A: Include Plan9 file server module.
 * Uses lib9p on FreeBSD (hvsocket 50001), 9P stub on Linux (TCP 50001). */
#include "../plan9_server.h"

/* A1: Global parsed configuration from Initialize(5) message. */
static struct wsl_config g_config;
static int g_config_parsed = 0;

/* A2: Global parsed /etc/wsl.conf configuration. */
static struct wsl_conf g_wsl_conf;
static int g_wsl_conf_parsed = 0;

#include "../gns_engine.h"

/* B (DNS Tunneling): Include DNS tunneling module.
 * Must come after gns_engine.h so MESSAGE_HEADER is defined. */
#include "../dns_tunneling.h"

/* Phase 1: additional message types for event loop */
#define LxInitMessageTerminateInstance  14

/* Phase 1: SIGCHLD self-pipe */
static int g_sigchld_pipe[2] = {-1, -1};

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
                 * can bind 127.0.0.1 instead of 10.255.255.254. */
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

/* F2: Track mounted filesystems for graceful unmount on shutdown.
 * Each entry records the mount point path. Unmount happens in reverse
 * order (last mounted = first unmounted). */
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
 * Note: FreeBSD uses unmount(), Linux uses umount2(). The production
 * hvinit.c uses unmount() since it runs on FreeBSD. */
static int fs_unmount_all(void)
{
    int unmounted = 0;
    for (int i = g_mounted_count - 1; i >= 0; i--) {
        printf("[init] unmounting %s...\n", g_mounted_fs[i]);
#ifdef __FreeBSD__
        int rc = unmount(g_mounted_fs[i], 0);
        if (rc < 0 && errno == EBUSY) {
            fprintf(stderr, "[init] %s busy, forcing unmount\n", g_mounted_fs[i]);
            rc = unmount(g_mounted_fs[i], MNT_FORCE);
        }
#else
        /* Linux: use umount2 with MNT_FORCE for busy mounts */
        int rc = umount2(g_mounted_fs[i], 0);
        if (rc < 0 && errno == EBUSY) {
            fprintf(stderr, "[init] %s busy, forcing unmount\n", g_mounted_fs[i]);
            rc = umount2(g_mounted_fs[i], MNT_FORCE);
        }
#endif
        if (rc < 0) {
            /* Log but don't fail — best-effort cleanup.
             * In the test harness, these mounts don't actually exist
             * (we're on Linux, not FreeBSD), so ENOENT is expected. */
            fprintf(stderr, "[init] unmount %s: %s (expected in test harness)\n",
                    g_mounted_fs[i], strerror(errno));
        } else {
            unmounted++;
            printf("[init] unmounted %s\n", g_mounted_fs[i]);
        }
    }
    return unmounted;
}

/* F1: Send OobeResult (type 28) on the given channel.
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

static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_sigchld_pipe[1] >= 0) {
        char c = 'c';
        ssize_t wr = write(g_sigchld_pipe[1], &c, 1);
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
static void handle_terminate_instance(int init_fd, struct MESSAGE_HEADER *hdr)
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

    /* 4. Sync to flush all pending writes */
    sync();
    printf("[init] sync complete, exiting\n");

    /* 5. Exit */
    exit(0);
}

/* Phase 1: Handle WindowSizeChanged (type 10) — forward to notify channel */
static void handle_window_size_changed(int notify_fd, void *msg_buf, size_t msg_size)
{
    if (msg_size < sizeof(LX_INIT_WINDOW_SIZE_CHANGED)) return;
    LX_INIT_WINDOW_SIZE_CHANGED *wsc = (LX_INIT_WINDOW_SIZE_CHANGED *)msg_buf;
    printf("[init] WindowSizeChanged: rows=%u, cols=%u\n", wsc->Rows, wsc->Columns);

    if (notify_fd >= 0) {
        send_all(notify_fd, msg_buf, msg_size);
    }
}

/* Phase 1: Event loop — replaces pause() */
static void event_loop(int init_fd, int notify_fd)
{
    printf("[init] entering event loop (init_fd=%d, notify_fd=%d)\n", init_fd, notify_fd);

    /* FIX: set init_fd non-blocking so recv_all can handle partial reads
     * without blocking the event loop (and missing SIGCHLD). */
    fcntl(init_fd, F_SETFL, fcntl(init_fd, F_GETFL) | O_NONBLOCK);

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

        pfds[nfds].fd = init_fd;  pfds[nfds].events = POLLIN;  nfds++;
        if (g_sigchld_pipe[0] >= 0) {
            pfds[nfds].fd = g_sigchld_pipe[0];  pfds[nfds].events = POLLIN;  nfds++;
        }

        int rc = poll(pfds, nfds, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[init] poll");
            break;
        }

        /* SIGCHLD — reap zombie children */
        if (nfds > 1 && (pfds[1].revents & POLLIN)) {
            char c;
            while (read(g_sigchld_pipe[0], &c, 1) > 0) {}
            reap_children();
        }

        /* Message from host on init channel */
        if (pfds[0].revents & POLLIN) {
            struct MESSAGE_HEADER hdr;
            if (recv_all(init_fd, &hdr, sizeof(hdr)) < 0) {
                printf("[init] host disconnected from init channel\n");
                break;
            }

            if (hdr.MessageSize < sizeof(hdr)) {
                printf("[init] invalid message size %u\n", hdr.MessageSize);
                continue;
            }

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

            /* Build full message for handlers */
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
                        /* Send error response */
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

                    /* Send ResultInt32 response (0 = success, regardless of
                     * individual mount failures — best-effort strategy). */
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

                case LxInitMessageStopPlan9Server: {
                    if (hdr.MessageSize < sizeof(LX_INIT_STOP_PLAN9_SERVER_MSG)) {
                        fprintf(stderr, "[init] Group A: StopPlan9Server size %u < %zu\n",
                                hdr.MessageSize, sizeof(LX_INIT_STOP_PLAN9_SERVER_MSG));
                        break;
                    }
                    LX_INIT_STOP_PLAN9_SERVER_MSG *stop =
                        (LX_INIT_STOP_PLAN9_SERVER_MSG *)full_msg;
                    printf("[init] Group A: StopPlan9Server force=%d\n", stop->Force);
                    bool ok = plan9_stop_server(stop->Force);
                    RESULT_MESSAGE_BOOL resp;
                    memset(&resp, 0, sizeof(resp));
                    resp.Header.MessageType = LxMessageResultBool;
                    resp.Header.MessageSize = sizeof(resp);
                    resp.Header.SequenceNumber = hdr.SequenceNumber;
                    resp.Result = ok;
                    send_all(init_fd, &resp, sizeof(resp));
                    printf("[init] Group A: StopPlan9Server response sent (result=%d)\n", ok);
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

/* Connect to a TCP port on localhost. Returns fd or -1. */
static int hv_connect(unsigned int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

/* Send CreateInstanceResult (type 33) with ConnectPort=60000. */
static void send_create_instance_result(int init_fd)
{
    size_t msglen = sizeof(LX_MINI_INIT_CREATE_INSTANCE_RESULT);
    LX_MINI_INIT_CREATE_INSTANCE_RESULT *msg = malloc(msglen);
    if (!msg) return;
    memset(msg, 0, msglen);

    msg->Header.MessageType = LxMiniInitMessageCreateInstanceResult;
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1;
    msg->Result = 0;
    msg->Pid = (uint64_t)getpid();
    msg->ConnectPort = PORT_HVS_BSD;

    if (send_all(init_fd, msg, msglen) < 0)
        perror("[init] send create_instance_result");
    else
        printf("[init] sent CreateInstanceResult (type=%u, seq=%u, ConnectPort=%u)\n",
               msg->Header.MessageType, msg->Header.SequenceNumber, msg->ConnectPort);
    free(msg);
}

/* Send ConfigurationInformationResponse (type 6), echoing host's seq.
 * A1: Uses parsed config values (DefaultUid from DrvFsDefaultOwner) when available. */
static void send_configuration_info_response(int init_fd, unsigned int seq)
{
    const char *flavor = "GenericFlavor";
    const char *version = "1.0.0";
    size_t payload_len = strlen(flavor) + 1 + strlen(version) + 1;
    size_t msglen = sizeof(LX_INIT_CONFIGURATION_INFORMATION_RESPONSE) + payload_len;

    LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *resp = malloc(msglen);
    if (!resp) return;
    memset(resp, 0, msglen);

    resp->Header.MessageType = LxInitMessageInitializeResponse;
    resp->Header.MessageSize = (unsigned int)msglen;
    resp->Header.SequenceNumber = seq;  /* Phase 0 fix: echo host's seq */
    resp->Plan9Port = plan9_get_port();  /* Group A: Plan9 file server port */
    /* A1: Use DrvFsDefaultOwner from parsed config as DefaultUid */
    resp->DefaultUid = g_config_parsed ? g_config.drvfs_default_owner : 1;
    resp->InteropPort = PORT_HVS_BSD;
    resp->SystemdEnabled = false;  /* Phase 0 fix: FreeBSD has no systemd */
    resp->PidNamespace = 0;
    resp->FlavorIndex = 0;  /* Offset of flavor string in Buffer */
    resp->VersionIndex = (unsigned int)(strlen(flavor) + 1);  /* Offset of version */
    memcpy(resp->Buffer, flavor, strlen(flavor) + 1);
    memcpy(resp->Buffer + strlen(flavor) + 1, version, strlen(version) + 1);

    if (send_all(init_fd, resp, msglen) < 0)
        perror("[init] send config_response");
    else
        printf("[init] sent InitializeResponse (type=%u, seq=%u, DefaultUid=%u, InteropPort=%u, Systemd=%d)\n",
               resp->Header.MessageType, resp->Header.SequenceNumber,
               resp->DefaultUid, resp->InteropPort, resp->SystemdEnabled);
    free(resp);
}

/* Send CreateSessionResponse (type 3), echoing host's seq. */
static void send_create_session_response(int init_fd, unsigned int port, unsigned int seq)
{
    LX_INIT_CREATE_SESSION_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxInitMessageCreateSessionResponse;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;  /* Phase 0 fix: echo host's seq */
    resp.Port = port;

    if (send_all(init_fd, &resp, sizeof(resp)) < 0)
        perror("[init] send session_response");
    else
        printf("[init] sent CreateSessionResponse (type=%u, seq=%u, Port=%u)\n",
               resp.Header.MessageType, resp.Header.SequenceNumber, resp.Port);
}

int main(void)
{
    printf("[init] hvinit_tcp starting (pid=%d)\n", getpid());
    gns_configure_test_paths();

    /* 1. Capability channel: connect and send GuestCapabilities */
    int cap_fd = hv_connect(PORT_HVS);
    if (cap_fd < 0) { fprintf(stderr, "[init] FATAL: cannot connect to host\n"); return 1; }

    const char *kver = "FreeBSD-13.3-HVPoC";
    size_t msglen = sizeof(LX_INIT_GUEST_CAPABILITIES) + strlen(kver) + 1;
    LX_INIT_GUEST_CAPABILITIES *msg = malloc(msglen);
    memset(msg, 0, msglen);
    /* Phase 0 fix: full 12-byte MESSAGE_HEADER instead of uint32_t */
    msg->Header.MessageType = LxMiniInitMessageGuestCapabilities;  /* 43, not 1 */
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1;
    msg->SeccompAvailable = false;
    strcpy(msg->Buffer, kver);

    if (send_all(cap_fd, msg, msglen) < 0) {
        perror("[init] send capabilities");
        free(msg);
        return 1;
    }
    printf("[init] sent GuestCapabilities (type=%u, size=%zu, Seccomp=%d, kver='%s')\n",
           msg->Header.MessageType, msglen, msg->SeccompAvailable, msg->Buffer);
    free(msg);

    /* 2. Notify channel */
    int notify_fd = hv_connect(PORT_HVS);
    if (notify_fd < 0) return 1;
    printf("[init] notify channel connected\n");

    /* 3. Init channel */
    int init_fd = hv_connect(PORT_HVS);
    if (init_fd < 0) return 1;
    printf("[init] init channel connected\n");

    /* 4. Send CreateInstanceResult */
    send_create_instance_result(init_fd);

    /* 5. Receive Initialize(5), respond with InitializeResponse(6).
     * A1: Read header first, then payload, to handle variable-length
     * LX_INIT_CONFIGURATION_INFORMATION with Buffer[] strings. */
    {
        struct MESSAGE_HEADER init_hdr;
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

                        /* Set WSL_DISTRO_NAME env var from config */
                        if (g_config.distribution_name) {
                            setenv("WSL_DISTRO_NAME", g_config.distribution_name, 1);
                            printf("[init] set WSL_DISTRO_NAME=%s\n", g_config.distribution_name);
                        }

                        /* Export feature flags as hex string */
                        char flags_str[16];
                        snprintf(flags_str, sizeof(flags_str), "%x", g_config.feature_flags);
                        setenv("WSL_FEATURE_FLAGS", flags_str, 1);
                    } else {
                        printf("[init] Initialize too small for full parse, using defaults\n");
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
                     * Best-effort: mount failures are logged but non-fatal
                     * (no 9p server in test environment, no 9p kernel module on FreeBSD).
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
                     * Gated by boot.protectBinfmt (default true) which makes
                     * the handler immutable.
                     * On FreeBSD/test: skipped gracefully (no binfmt_misc).
                     * Reference: binfmt.cpp RegisterBinfmtInterop() */
                    {
                        int protect = g_wsl_conf_parsed
                                      ? g_wsl_conf.boot_protect_binfmt : 1;
                        binfmt_setup(protect);
                    }

                    /* E2: Execute boot.command from /etc/wsl.conf.
                     * This runs a custom startup command (e.g. starting a
                     * daemon, configuring kernel parameters) before the
                     * guest enters its main event loop.
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
                     * When false, the GNS engine should NOT overwrite
                     * /etc/resolv.conf when NetworkInformation(4) arrives.
                     * The flag is stored as a global in gns_engine.h.
                     * Reference: config.cpp line 753, gns.cpp UpdateResolvConf() */
                    {
                        int gen_resolv = g_wsl_conf_parsed
                                         ? g_wsl_conf.network_generate_resolvconf : 1;
                        g_generate_resolvconf = gen_resolv;
                        printf("[init] E3: generateResolvConf=%d\n", gen_resolv);
                    }

                    /* E3: Apply interop.appendWindowsPath setting.
                     * When true (default), the Windows PATH is appended to
                     * the guest PATH so Windows executables are accessible
                     * by name. When false, Windows PATH is not added.
                     * We store this as an environment variable that the
                     * interop server and bridge check when spawning processes.
                     * Reference: config.cpp line 760 */
                    {
                        int append_path = g_wsl_conf_parsed
                                          ? g_wsl_conf.interop_append_windows_path : 1;
                        setenv("WSL_APPEND_WINDOWS_PATH",
                               append_path ? "1" : "0", 1);
                        printf("[init] E3: appendWindowsPath=%d\n", append_path);
                    }

                    /* Group A: Start Plan9 file server before sending InitializeResponse.
                     * The host reads Plan9Port from the response and connects to
                     * the server for \\wsl$\ access. */
                    {
                        unsigned int p9port = plan9_start_server();
                        if (p9port > 0) {
                            printf("[init] Group A: Plan9 server started on port %u\n", p9port);
                        } else {
                            fprintf(stderr,
                                "[init] Group A: Plan9 server failed to start (non-fatal)\n");
                        }
                    }

                    send_configuration_info_response(init_fd, init_hdr.SequenceNumber);
                    free(full_msg);
                }
            }
        }
    }

    /* 6. Receive CreateSession(2), respond with CreateSessionResponse(3) */
    {
        char sess_buf[256];
        ssize_t r_sess = recv(init_fd, sess_buf, sizeof(sess_buf) - 1, 0);
        if (r_sess > 0) {
            sess_buf[r_sess] = '\0';
            printf("[init] received CreateSession (%zd bytes)\n", r_sess);
            unsigned int sess_seq = 1;
            if ((size_t)r_sess >= sizeof(struct MESSAGE_HEADER)) {
                struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)sess_buf;
                printf("[init]   host CreateSession: type=%u, seq=%u\n",
                       hdr->MessageType, hdr->SequenceNumber);
                sess_seq = hdr->SequenceNumber;
            }
            send_create_session_response(init_fd, PORT_HVS_BSD, sess_seq);
        } else {
            perror("[init] recv CreateSession");
        }
    }

    printf("[init] handshake complete\n");

    /* F1: Send OobeResult (type 28) on the init channel.
     *
     * In the reference WSL, this is sent on a dedicated OOBE channel when
     * RunOOBE=true. For the FreeBSD port, we send it on the init channel
     * after the handshake to signal that first-run setup is complete.
     * The host reads this to unblock session creation.
     *
     * Result=0 (success), DefaultUid from parsed config or -1 if not set. */
    {
        int64_t oobe_uid = -1;
        if (g_config_parsed && g_config.drvfs_default_owner != 0)
            oobe_uid = (int64_t)g_config.drvfs_default_owner;
        send_oobe_result(init_fd, 0, oobe_uid);
    }

    /* F2: Track filesystem mounts for graceful shutdown.
     * In the production hvinit.c, these are mounted by initialize_filesystems().
     * In the TCP test harness, we don't actually mount (we're on Linux, not
     * FreeBSD), but we track them so the graceful shutdown logic can be tested.
     * The mock host verifies the unmount log output. */
    fs_track_mount("/dev");
    fs_track_mount("/proc");
    fs_track_mount("/run");

    /* C1: Start GNS engine on dedicated channel (parallel to event loop) */
    gns_start_engine(cap_fd, notify_fd, init_fd);

    printf("[init] entering event loop\n");
    /* Phase 1: event loop replaces pause() */
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
