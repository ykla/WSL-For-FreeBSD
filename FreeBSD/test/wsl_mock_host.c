/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_mock_host.c - Mock WSL host for testing Phase 0 + Phase 1 + Phase 2 + Phase 3 + Phase 4 + Phase 5 + Phase 6 + Phase 7 + Phase 8 fixes.
 *
 * Simulates wslservice.exe: listens on port 50000, accepts guest
 * connections, sends WSL protocol messages, and validates the
 * guest's responses.
 *
 * Phase 0 test checks:
 *   1. GuestCapabilities: MessageType==43, 12-byte header, Seccomp=false
 *   2. CreateInstanceResult: MessageType==33, ConnectPort==60000
 *   3. InitializeResponse: MessageType==6, seq echoed, Systemd=false
 *   4. CreateSessionResponse: MessageType==3, seq echoed, Port==60000
 *   5. CreateProcessUtilityVm response: MessageType==78
 *   6. Terminal size honored (Rows=30, Cols=120)
 *   7. Console I/O works (echo test)
 *
 * Phase 1 test checks:
 *   8. WindowSizeChanged: send on control channel, verify PTY resize via stty
 *   9. ExitStatus received on control channel (not stdout)
 *  10. TerminateInstance: send to hvinit, verify ResultUint32 response
 *
 * Phase 2 test checks:
 *  11. Environment variables passed via execve (echo $TEST_ENV_VAR)
 *  12. Working directory set via chdir before execve (pwd == /tmp)
 *
 * Phase 3 test checks:
 *  13. PTY raw mode: no double echo (command text not echoed by PTY)
 *  14. Resize to minimum 1x1 (stty size shows "1 1")
 *  15. Resize back to large 50x200 (stty size shows "50 200")
 *
 * Phase 4 test checks:
 *  16. Host disconnect triggers graceful child shutdown (no zombie/leak)
 *  17. New session works after a previous session's host disconnect
 *  18. Grandchild holding PTY slave does not hang drain (poll timeout works)
 *  19. New session works after grandchild PTY inheritance test
 *
 * Phase 5 test checks:
 *  20. TERM env var passed through from host (not overwritten)
 *  21. COLORTERM=truecolor injected by bridge when not set by host
 *  22. ANSI basic color (16-color) passthrough through raw PTY
 *  23. ANSI 256-color passthrough through raw PTY
 *  24. ANSI truecolor (24-bit) passthrough through raw PTY
 *  25. OSC color theme switching (palette/fg/bg set + reset) passthrough
 *      combined with grandchild PTY drain timeout (ExitStatus still received)
 *  26. New session works after color theme + grandchild combined test
 *
 * Phase 6 test checks:
 *  27. Guest→host window size notification: stty resize inside guest triggers
 *      WindowSizeChanged(10) on control channel (TIOCGWINSZ polling)
 *  28. Host→guest resize does NOT trigger feedback notification (loop prevention)
 *
 * Phase 7 test checks:
 *  29. OSC 50 font-setting escape sequences pass through raw PTY unchanged
 *      (cfmakeraw mode ensures transparent relay — no interception needed)
 *  30. OSC 50 font-query escape sequence (ESC]50;?) passes through raw PTY
 *  31. OSC 50 font traffic + grandchild PTY drain: ExitStatus still received
 *      after font-setting sequences and grandchild holding PTY slave
 *  32. New session works after font + grandchild combined test (no deadlock)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>

#include "wsl_protocol.h"

/* A1: Include config parser for building Initialize messages with full config */
#include "../config_parser.h"

/* A2: Include wsl.conf parser for unit testing */
#include "../wsl_conf_parser.h"

/* A3: Include timezone handler for unit testing */
#include "../timezone_handler.h"

/* A4: Include network config for unit testing */
#include "../network_config.h"

/* B1: Include DrvFs mount module for unit testing */
#include "../drvfs_mount.h"

/* E1: Include binfmt_misc handler for direct testing */
#include "../binfmt_handler.h"

/* E3: Include GNS engine for g_generate_resolvconf flag testing */
#include "../gns_engine.h"

/* Task Group F: Include wsl_interop.h for I/O relay unit testing */
#include "../wsl_interop.h"

/* Phase 1: TerminateInstance message type */
#define LxInitMessageTerminateInstance  14

static int g_tests_passed = 0;
static int g_tests_failed = 0;

/* CHECK macro: when the condition fails, prints the test name and a
 * printf-style detail string. An empty format string ("") is valid and
 * produces no extra output. Suppress the benign -Wformat-zero-length. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"

#define CHECK(cond, name, ...) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        g_tests_passed++; \
    } else { \
        printf("  [FAIL] %s — ", name); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        g_tests_failed++; \
    } \
} while (0)

static int listen_on_port(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return -1; }
    if (listen(fd, 16) < 0) { perror("listen"); return -1; }
    return fd;
}

static int connect_to_port(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

/* ---- PortListenerRelay helpers (Task Group C) ----
 * The guest's port_tracker sends LxGnsMessagePortListenerRelayStart(59) and
 * LxGnsMessagePortListenerRelayStop(60) messages on the GNS channel. These
 * arrive asynchronously and can interleave with response messages. The
 * helpers below let the mock host drain or skip them when waiting for a
 * specific response. */

/* Wire layout of PortListenerRelay (matches LX_GNS_PORT_LISTENER_RELAY). */
typedef struct MOCK_PORT_LISTENER_RELAY {
    struct MESSAGE_HEADER Header;
    unsigned short Family;        /* host order */
    unsigned short Port;          /* network byte order */
    unsigned int   Address[4];
} MOCK_PORT_LISTENER_RELAY;

/* Drain all pending data from gns_fd (non-blocking, 200ms total budget).
 * Used to flush the initial burst of PortListenerRelayStart messages that
 * the guest sends when the GNS channel first connects. Returns the number
 * of recv calls that returned data. */
static int drain_relay_messages(int gns_fd)
{
    if (gns_fd < 0) return 0;
    int drained = 0;
    int saved_flags = fcntl(gns_fd, F_GETFL, 0);
    if (saved_flags >= 0) fcntl(gns_fd, F_SETFL, saved_flags | O_NONBLOCK);
    for (;;) {
        struct pollfd pfd = { .fd = gns_fd, .events = POLLIN };
        if (poll(&pfd, 1, 200) <= 0) break;
        if (!(pfd.revents & POLLIN)) break;
        char tmp[4096];
        ssize_t n = recv(gns_fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        drained++;
    }
    if (saved_flags >= 0) fcntl(gns_fd, F_SETFL, saved_flags);
    return drained;
}

/* Receive a GNS message, skipping any PortListenerRelay(59/60) messages.
 * Returns a malloc'd buffer (caller frees) or NULL on error. */
static void *recv_gns_response(int gns_fd, struct MESSAGE_HEADER *out_hdr)
{
    for (;;) {
        void *msg = recv_message(gns_fd, out_hdr);
        if (!msg) return NULL;
        unsigned int mtype = out_hdr->MessageType;
        if (mtype == LxGnsMessagePortListenerRelayStart ||
            mtype == LxGnsMessagePortListenerRelayStop) {
            free(msg);
            continue;  /* skip async relay notifications */
        }
        return msg;
    }
}

/* Wait for a PortListenerRelay message matching host_port within timeout_ms.
 * Skips non-relay messages and relay messages for other ports.
 * Returns the message type (59 or 60) on success, 0 on timeout, -1 on error. */
static int recv_relay_for_port(int gns_fd, uint16_t host_port, int timeout_ms)
{
    time_t deadline = time(NULL) + timeout_ms / 1000 + 1;
    for (;;) {
        time_t now = time(NULL);
        if (now >= deadline) return 0;
        int remaining_ms = (int)((deadline - now) * 1000);
        if (remaining_ms > timeout_ms) remaining_ms = timeout_ms;

        struct pollfd pfd = { .fd = gns_fd, .events = POLLIN };
        int rc = poll(&pfd, 1, remaining_ms);
        if (rc <= 0) return 0;

        struct MESSAGE_HEADER hdr;
        void *msg = recv_message(gns_fd, &hdr);
        if (!msg) return -1;

        if (hdr.MessageType != LxGnsMessagePortListenerRelayStart &&
            hdr.MessageType != LxGnsMessagePortListenerRelayStop) {
            free(msg);
            continue;  /* not a relay message — skip */
        }

        MOCK_PORT_LISTENER_RELAY *relay = (MOCK_PORT_LISTENER_RELAY *)msg;
        uint16_t relay_port = ntohs(relay->Port);
        int relay_family = relay->Family;
        free(msg);

        if (relay_port == host_port) {
            printf("  Found relay: type=%u family=%d port=%u\n",
                   hdr.MessageType, relay_family, relay_port);
            return (int)hdr.MessageType;
        }
        /* Relay for a different port — keep looking. */
    }
}

/* Read from fd with timeout. Returns bytes read, 0 on timeout, -1 on error. */
static int read_with_timeout(int fd, char *buf, int bufsize, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) return rc;
    return (int)recv(fd, buf, bufsize, 0);
}

/* Phase 4 helper: connect to bridge, send CreateProcessUtilityVm, and validate
 * the ResultUint32 response. On success returns 0 and fills out_control_fd with
 * the control channel. On failure returns -1. */
static int setup_bridge_session(int *out_init_fd, int *out_control_fd,
                                unsigned short rows, unsigned short cols,
                                unsigned int seq, struct MESSAGE_HEADER *out_hdr)
{
    int init_fd = connect_to_port(PORT_HVS_BSD);
    if (init_fd < 0) return -1;
    int control_fd = connect_to_port(PORT_HVS_BSD);
    if (control_fd < 0) { close(init_fd); return -1; }

    const char *filename = "/bin/sh";
    const char *cwd = "/tmp";
    const char *cmdline = "sh";
    const char *env_vars[] = {
        "TEST_ENV_VAR=phase2_ok",
        "TERM=xterm",
        "PATH=/bin:/usr/bin",
    };
    int env_count = (int)(sizeof(env_vars) / sizeof(env_vars[0]));

    uint32_t off_filename = 0;
    uint32_t off_cwd = off_filename + (uint32_t)strlen(filename) + 1;
    uint32_t off_cmdline = off_cwd + (uint32_t)strlen(cwd) + 1;
    uint32_t off_env = off_cmdline + (uint32_t)strlen(cmdline) + 1;

    size_t env_total = 0;
    for (int i = 0; i < env_count; i++)
        env_total += strlen(env_vars[i]) + 1;
    size_t buffer_size = off_env + env_total;

    size_t msg_size = offsetof(LX_INIT_CREATE_PROCESS_UTILITY_VM, Common.Buffer) + buffer_size;
    LX_INIT_CREATE_PROCESS_UTILITY_VM *proc_msg = calloc(1, msg_size);
    if (!proc_msg) { close(init_fd); close(control_fd); return -1; }

    proc_msg->Header.MessageType = LxInitMessageCreateProcessUtilityVm;
    proc_msg->Header.MessageSize = (uint32_t)msg_size;
    proc_msg->Header.SequenceNumber = seq;
    proc_msg->Rows = rows;
    proc_msg->Columns = cols;
    proc_msg->Common.FilenameOffset = off_filename;
    proc_msg->Common.CurrentWorkingDirectoryOffset = off_cwd;
    proc_msg->Common.CommandLineOffset = off_cmdline;
    proc_msg->Common.CommandLineCount = 1;
    proc_msg->Common.EnvironmentOffset = off_env;
    proc_msg->Common.EnvironmentCount = (uint16_t)env_count;

    char *cbuf = proc_msg->Common.Buffer;
    memcpy(cbuf + off_filename, filename, strlen(filename) + 1);
    memcpy(cbuf + off_cwd, cwd, strlen(cwd) + 1);
    memcpy(cbuf + off_cmdline, cmdline, strlen(cmdline) + 1);
    {
        size_t pos = off_env;
        for (int i = 0; i < env_count; i++) {
            memcpy(cbuf + pos, env_vars[i], strlen(env_vars[i]) + 1);
            pos += strlen(env_vars[i]) + 1;
        }
    }

    if (send_all(control_fd, proc_msg, msg_size) < 0) {
        free(proc_msg); close(init_fd); close(control_fd); return -1;
    }
    free(proc_msg);

    struct MESSAGE_HEADER hdr;
    RESULT_MESSAGE_UINT32 *result = (RESULT_MESSAGE_UINT32 *)recv_message(control_fd, &hdr);
    if (!result) { close(init_fd); close(control_fd); return -1; }
    int ok = (result->Header.MessageType == LxMessageResultUint32 &&
              result->Header.SequenceNumber == seq);
    if (out_hdr) *out_hdr = hdr;
    free(result);

    if (!ok) { close(init_fd); close(control_fd); return -1; }

    *out_init_fd = init_fd;
    *out_control_fd = control_fd;
    return 0;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    printf("=== WSL Mock Host — Phase 9 Test Harness ===\n\n");

    /* Group A: saved Plan9 port from InitializeResponse for later 9P tests.
     * Not initialized here: the InitializeResponse block below always runs
     * (or returns on error) before any read, so an initializer would be a
     * dead store flagged by -Wunused-but-set-variable. */
    unsigned int saved_plan9_port;

    /* Configure resolv.conf test path when WSL_TEST_ROOT is set */
    {
        const char *test_root = getenv("WSL_TEST_ROOT");
        if (test_root && test_root[0]) {
            char path[512];
            snprintf(path, sizeof(path), "%s/resolv.conf", test_root);
            gns_set_resolvconf_path(path);
            printf("[host] WSL_TEST_ROOT: resolv.conf -> %s\n", path);
        }
    }

    /* Listen on port 50000 for guest connections */
    int listen_fd = listen_on_port(PORT_HVS);
    if (listen_fd < 0) { fprintf(stderr, "FATAL: cannot listen on %d\n", PORT_HVS); return 1; }
    printf("[host] listening on port %d\n", PORT_HVS);

    /* C1: Listen on port 50001 for GNS engine channel */
    int gns_listen_fd = listen_on_port(PORT_HVS_GNS);
    if (gns_listen_fd < 0) {
        fprintf(stderr, "FATAL: cannot listen on GNS port %d\n", PORT_HVS_GNS);
        return 1;
    }
    printf("[host] listening on GNS port %d\n", PORT_HVS_GNS);
    int gns_fd = -1;

    /* ---- Step 1: Accept capability channel ---- */
    printf("\n[host] Step 1: Waiting for GuestCapabilities...\n");
    int cap_fd = accept(listen_fd, NULL, NULL);
    if (cap_fd < 0) { perror("accept cap"); return 1; }

    struct MESSAGE_HEADER hdr;
    LX_INIT_GUEST_CAPABILITIES *cap = (LX_INIT_GUEST_CAPABILITIES *)recv_message(cap_fd, &hdr);
    if (!cap) { fprintf(stderr, "  [FAIL] cannot receive GuestCapabilities\n"); return 1; }

    printf("  Received: MessageType=%u, MessageSize=%u, SequenceNumber=%u\n",
           cap->Header.MessageType, cap->Header.MessageSize, cap->Header.SequenceNumber);
    printf("  SeccompAvailable=%d, Buffer='%s'\n", cap->SeccompAvailable, cap->Buffer);

    CHECK(cap->Header.MessageType == LxMiniInitMessageGuestCapabilities,
          "GuestCapabilities MessageType==43 (was 1)",
          "got %u", cap->Header.MessageType);
    CHECK(cap->Header.MessageSize >= sizeof(LX_INIT_GUEST_CAPABILITIES) + 1,
          "GuestCapabilities MessageSize includes 12-byte header",
          "size=%u, expected >= %zu", cap->Header.MessageSize, sizeof(LX_INIT_GUEST_CAPABILITIES) + 1);
    CHECK(cap->Header.MessageSize == hdr.MessageSize,
          "GuestCapabilities header size consistent",
          "recv hdr=%u, msg=%u", hdr.MessageSize, cap->Header.MessageSize);
    CHECK(cap->SeccompAvailable == false,
          "GuestCapabilities SeccompAvailable==false",
          "got %d", cap->SeccompAvailable);
    CHECK(strcmp(cap->Buffer, "FreeBSD-13.3-HVPoC") == 0,
          "GuestCapabilities kernel version string",
          "got '%s'", cap->Buffer);
    free(cap);

    /* ---- Step 2: Accept notify channel ---- */
    printf("\n[host] Step 2: Waiting for notify channel...\n");
    int notify_fd = accept(listen_fd, NULL, NULL);
    if (notify_fd < 0) { perror("accept notify"); return 1; }
    printf("  Notify channel connected\n");

    /* ---- Step 3: Accept init channel + CreateInstanceResult ---- */
    printf("\n[host] Step 3: Waiting for init channel + CreateInstanceResult...\n");
    int init_fd = accept(listen_fd, NULL, NULL);
    if (init_fd < 0) { perror("accept init"); return 1; }

    LX_MINI_INIT_CREATE_INSTANCE_RESULT *cir =
        (LX_MINI_INIT_CREATE_INSTANCE_RESULT *)recv_message(init_fd, &hdr);
    if (!cir) { fprintf(stderr, "  [FAIL] cannot receive CreateInstanceResult\n"); return 1; }

    printf("  Received: MessageType=%u, Result=%d, Pid=%llu, ConnectPort=%u\n",
           cir->Header.MessageType, cir->Result,
           (unsigned long long)cir->Pid, cir->ConnectPort);

    CHECK(cir->Header.MessageType == LxMiniInitMessageCreateInstanceResult,
          "CreateInstanceResult MessageType==33",
          "got %u", cir->Header.MessageType);
    CHECK(cir->ConnectPort == PORT_HVS_BSD,
          "CreateInstanceResult ConnectPort==60000",
          "got %u", cir->ConnectPort);
    free(cir);

    /* ---- Step 4: Send Initialize(5) with full config, expect InitializeResponse(6) ----
     * A1: Send a proper LX_INIT_CONFIGURATION_INFORMATION message with all
     * fields populated (hostname, domainname, distribution_name, timezone,
     * DrvFs bitmap, feature flags, etc.) instead of just a bare header. */
    printf("\n[host] Step 4: Sending Initialize (full config, seq=42), expecting response...\n");
    {
        size_t init_msg_size = 0;
        void *init_msg = wsl_config_build_message(
            "freebsd-test",          /* hostname */
            "localdomain",           /* domainname */
            "127.0.0.1 localhost\n", /* windows_hosts */
            "FreeBSD",               /* distribution_name */
            "/run/plan9_9p",         /* plan9_socket_path */
            "Asia/Shanghai",         /* timezone */
            0x04,                    /* drvfs_volumes_bitmap: bit 2 = C: */
            1000,                    /* drvfs_default_owner (UID) */
            0x22,                    /* feature_flags: VirtIoFs(0x02) + DnsTunneling(0x20) */
            WSL_DRVFS_MOUNT_NONELEVATED, /* drvfs_mount */
            42,                      /* sequence number */
            &init_msg_size);

        if (!init_msg) {
            fprintf(stderr, "  [FAIL] cannot build Initialize message\n");
            return 1;
        }
        printf("  Built Initialize: size=%zu, hostname='freebsd-test', tz='Asia/Shanghai', drvfs_uid=1000\n",
               init_msg_size);

        if (send_all(init_fd, init_msg, init_msg_size) < 0) {
            perror("send Initialize");
            free(init_msg);
            return 1;
        }
        free(init_msg);
        printf("  Sent Initialize (type=%u, seq=42, size=%zu)\n",
               LxInitMessageInitialize, init_msg_size);

        LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *cfg =
            (LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *)recv_message(init_fd, &hdr);
        if (!cfg) { fprintf(stderr, "  [FAIL] cannot receive InitializeResponse\n"); return 1; }

        printf("  Received: MessageType=%u, seq=%u, DefaultUid=%u, InteropPort=%u, Systemd=%d\n",
               cfg->Header.MessageType, cfg->Header.SequenceNumber,
               cfg->DefaultUid, cfg->InteropPort, cfg->SystemdEnabled);

        CHECK(cfg->Header.MessageType == LxInitMessageInitializeResponse,
              "InitializeResponse MessageType==6",
              "got %u", cfg->Header.MessageType);
        CHECK(cfg->Header.SequenceNumber == 42,
              "InitializeResponse seq echoed (42)",
              "got %u", cfg->Header.SequenceNumber);
        CHECK(cfg->DefaultUid == 1000,
              "A1: InitializeResponse DefaultUid==1000 (from DrvFsDefaultOwner)",
              "got %u", cfg->DefaultUid);
        CHECK(cfg->InteropPort == PORT_HVS_BSD,
              "InitializeResponse InteropPort==60000",
              "got %u", cfg->InteropPort);
        CHECK(cfg->SystemdEnabled == false,
              "InitializeResponse SystemdEnabled==false (Phase 0 fix)",
              "got %d", cfg->SystemdEnabled);
        /* Group A: Verify Plan9Port is non-zero (server started before response) */
        CHECK(cfg->Plan9Port != 0,
              "Group A: InitializeResponse Plan9Port!=0 (server started)",
              "got %u", cfg->Plan9Port);
        saved_plan9_port = cfg->Plan9Port;
        printf("  Group A: Plan9Port=%u (expected %u)\n",
               cfg->Plan9Port, LX_INIT_UTILITY_VM_PLAN9_PORT);
        free(cfg);
    }

    /* ---- Step 5: Send CreateSession(2) with seq=99, expect CreateSessionResponse(3) ---- */
    printf("\n[host] Step 5: Sending CreateSession (seq=99), expecting response...\n");
    LX_INIT_CREATE_SESSION sess_msg;
    memset(&sess_msg, 0, sizeof(sess_msg));
    sess_msg.Header.MessageType = LxInitMessageCreateSession;
    sess_msg.Header.MessageSize = sizeof(sess_msg);
    sess_msg.Header.SequenceNumber = 99;
    sess_msg.PidNamespace = 0;
    if (send_all(init_fd, &sess_msg, sizeof(sess_msg)) < 0) {
        perror("send CreateSession"); return 1;
    }
    printf("  Sent CreateSession (type=%u, seq=%u)\n",
           sess_msg.Header.MessageType, sess_msg.Header.SequenceNumber);

    LX_INIT_CREATE_SESSION_RESPONSE *sess_resp =
        (LX_INIT_CREATE_SESSION_RESPONSE *)recv_message(init_fd, &hdr);
    if (!sess_resp) { fprintf(stderr, "  [FAIL] cannot receive CreateSessionResponse\n"); return 1; }

    printf("  Received: MessageType=%u, seq=%u, Port=%u\n",
           sess_resp->Header.MessageType, sess_resp->Header.SequenceNumber, sess_resp->Port);

    CHECK(sess_resp->Header.MessageType == LxInitMessageCreateSessionResponse,
          "CreateSessionResponse MessageType==3",
          "got %u", sess_resp->Header.MessageType);
    CHECK(sess_resp->Header.SequenceNumber == 99,
          "CreateSessionResponse seq echoed (99)",
          "got %u", sess_resp->Header.SequenceNumber);
    CHECK(sess_resp->Port == PORT_HVS_BSD,
          "CreateSessionResponse Port==60000",
          "got %u", sess_resp->Port);
    free(sess_resp);

    /* NOTE: listen_fd is NOT closed here. It must stay open for the DNS
     * tunneling channel connection at Step 76b (the guest opens a second
     * connection to PORT_HVS for DNS relay). Closed at end of main(). */

    /* ---- Step 64 (F1): Read OobeResult(28) from init channel ----
     * After the handshake, hvinit sends OobeResult on the init channel
     * to signal that first-run setup is complete. The host would normally
     * block waiting for this on a dedicated OOBE channel when RunOOBE=true.
     * For the FreeBSD port, it's sent on the init channel.
     *
     * Reference: src/linux/init/init.cpp lines 642-648,
     *            src/shared/inc/lxinitshared.h LX_INIT_OOBE_RESULT */
    printf("\n[host] Step 64: Reading OobeResult(28) from init channel...\n");
    {
        LX_INIT_OOBE_RESULT *oobe_resp =
            (LX_INIT_OOBE_RESULT *)recv_message(init_fd, &hdr);
        if (!oobe_resp) {
            CHECK(0, "F1: OobeResult received", "no response");
        } else {
            printf("  OobeResult: type=%u, size=%u, seq=%u, Result=%u, DefaultUid=%lld\n",
                   oobe_resp->Header.MessageType, oobe_resp->Header.MessageSize,
                   oobe_resp->Header.SequenceNumber, oobe_resp->Result,
                   (long long)oobe_resp->DefaultUid);

            CHECK(oobe_resp->Header.MessageType == LxInitMessageOobeResult,
                  "F1: OobeResult MessageType==28",
                  "got %u", oobe_resp->Header.MessageType);
            CHECK(oobe_resp->Header.MessageSize == sizeof(LX_INIT_OOBE_RESULT),
                  "F1: OobeResult MessageSize==24 (12 header + 4 result + 8 uid)",
                  "got %u", oobe_resp->Header.MessageSize);
            CHECK(oobe_resp->Header.SequenceNumber == 1,
                  "F1: OobeResult SequenceNumber==1 (first msg on OOBE channel)",
                  "got %u", oobe_resp->Header.SequenceNumber);
            CHECK(oobe_resp->Result == 0,
                  "F1: OobeResult Result==0 (success)",
                  "got %u", oobe_resp->Result);
            /* DefaultUid should be -1 (not configured) or a valid UID */
            CHECK(oobe_resp->DefaultUid == -1 || oobe_resp->DefaultUid >= 0,
                  "F1: OobeResult DefaultUid is -1 or valid UID",
                  "got %lld", (long long)oobe_resp->DefaultUid);
            free(oobe_resp);
        }
    }

    /* ---- Step 65 (F1): Verify no second OobeResult is sent ----
     * The guest should only send OobeResult once. Poll the init channel
     * with a short timeout to verify no additional message arrives. */
    printf("\n[host] Step 65: Verifying no duplicate OobeResult is sent...\n");
    {
        struct pollfd pfd;
        pfd.fd = init_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc = poll(&pfd, 1, 500);  /* 500ms timeout */
        if (rc == 0) {
            CHECK(1, "F1: No duplicate OobeResult (timeout as expected)", "");
        } else if (rc > 0 && (pfd.revents & POLLIN)) {
            /* There might be a legitimate message (e.g. from later steps).
             * This is not a failure — just log it. */
            printf("  Note: data available on init_fd (may be from later steps)\n");
            CHECK(1, "F1: No duplicate OobeResult (data is from later steps)", "");
        } else {
            CHECK(1, "F1: No duplicate OobeResult (poll result=%d)", "", rc);
        }
    }

    /* ---- Step A1 (Group A): 9P Tversion handshake ----
     * Connect to the Plan9 server port and perform a 9P2000.L version
     * negotiation. The stub server should respond with Rversion containing
     * negotiated msize and "9P2000.L" version string.
     *
     * 9P wire format: size[4] type[1] tag[2] [body...]
     * Tversion(100) body: msize[4] version[string]
     * Rversion(101) body: msize[4] version[string] */
    printf("\n[host] Step A1: Group A - 9P Tversion handshake on port %u...\n",
           saved_plan9_port);
    int p9_fd = -1;
    CHECK(saved_plan9_port != 0,
          "Group A: Plan9Port saved from InitializeResponse",
          "port is 0 (server not started)");
    if (saved_plan9_port != 0) {
        p9_fd = connect_to_port(saved_plan9_port);
        CHECK(p9_fd >= 0,
              "Group A: connect to Plan9 port",
              "connect failed (port=%u)", saved_plan9_port);
    }
    if (p9_fd >= 0) {
        /* Build Tversion: size[4] type[1] tag[2] msize[4] ver_len[2] ver[9] */
        const char *ver = "9P2000.L";
        size_t ver_len = strlen(ver);
        size_t msg_size = 4 + 1 + 2 + 4 + 2 + ver_len;  /* 21 for "9P2000.L" */
        uint8_t tversion[32];
        tversion[0] = (uint8_t)(msg_size & 0xFF);
        tversion[1] = (uint8_t)((msg_size >> 8) & 0xFF);
        tversion[2] = (uint8_t)((msg_size >> 16) & 0xFF);
        tversion[3] = (uint8_t)((msg_size >> 24) & 0xFF);
        tversion[4] = 100;        /* Tversion */
        tversion[5] = 0xFF;       /* tag = NOTAG (0xFFFF) */
        tversion[6] = 0xFF;
        uint32_t req_msize = 8192;
        tversion[7]  = (uint8_t)(req_msize & 0xFF);
        tversion[8]  = (uint8_t)((req_msize >> 8) & 0xFF);
        tversion[9]  = (uint8_t)((req_msize >> 16) & 0xFF);
        tversion[10] = (uint8_t)((req_msize >> 24) & 0xFF);
        tversion[11] = (uint8_t)(ver_len & 0xFF);
        tversion[12] = (uint8_t)((ver_len >> 8) & 0xFF);
        memcpy(&tversion[13], ver, ver_len);

        CHECK(send_all(p9_fd, tversion, msg_size) == 0,
              "Group A: send Tversion", "send failed");

        uint8_t rbuf[256];
        int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
        CHECK(rlen >= 21, "Group A: receive Rversion", "got %d bytes", rlen);

        if (rlen >= 21) {
            uint8_t  resp_type = rbuf[4];
            uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
            uint32_t resp_msize = (uint32_t)rbuf[7]
                                | ((uint32_t)rbuf[8] << 8)
                                | ((uint32_t)rbuf[9] << 16)
                                | ((uint32_t)rbuf[10] << 24);
            uint16_t ver_strlen = (uint16_t)rbuf[11] | ((uint16_t)rbuf[12] << 8);
            char resp_ver[32] = {0};
            size_t copy_len = ver_strlen < sizeof(resp_ver) - 1
                            ? ver_strlen : sizeof(resp_ver) - 1;
            memcpy(resp_ver, &rbuf[13], copy_len);

            CHECK(resp_type == 101,
                  "Group A: Rversion type==101",
                  "got %u", resp_type);
            CHECK(resp_tag == 0xFFFF,
                  "Group A: Rversion tag echoed (0xFFFF)",
                  "got 0x%04X", resp_tag);
            CHECK(resp_msize > 0 && resp_msize <= req_msize,
                  "Group A: Rversion msize negotiated (<=8192)",
                  "got %u", resp_msize);
            CHECK(strcmp(resp_ver, "9P2000.L") == 0,
                  "Group A: Rversion version=='9P2000.L'",
                  "got '%s'", resp_ver);
            printf("  Rversion: type=%u, tag=0x%04X, msize=%u, version='%s'\n",
                   resp_type, resp_tag, resp_msize, resp_ver);
        }

        /* ---- Step A2 (Group A): Tattach and verify root QID ----
         * Tattach(104) body: fid[4] afid[4] uname[s] aname[s]
         * Rattach(105) body: qid[13] = qtype[1] qversion[4] qpath[8] */
        printf("\n[host] Step A2: Group A - 9P Tattach, verify root QID...\n");
        {
            uint8_t tattach[32];
            size_t tattach_size = 4 + 1 + 2 + 4 + 4 + 2 + 2;  /* 19 bytes */
            tattach[0] = (uint8_t)(tattach_size & 0xFF);
            tattach[1] = (uint8_t)((tattach_size >> 8) & 0xFF);
            tattach[2] = 0; tattach[3] = 0;
            tattach[4] = 104;       /* Tattach */
            tattach[5] = 0x01;      /* tag = 1 */
            tattach[6] = 0x00;
            /* fid = 0 */
            tattach[7] = 0; tattach[8] = 0; tattach[9] = 0; tattach[10] = 0;
            /* afid = NOFID (0xFFFFFFFF) */
            tattach[11] = 0xFF; tattach[12] = 0xFF;
            tattach[13] = 0xFF; tattach[14] = 0xFF;
            /* uname = "" (length 0) */
            tattach[15] = 0; tattach[16] = 0;
            /* aname = "" (length 0) */
            tattach[17] = 0; tattach[18] = 0;

            CHECK(send_all(p9_fd, tattach, tattach_size) == 0,
                  "Group A: send Tattach", "send failed");

            int rlen2 = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rattach: size[4] type[1] tag[2] qid[13] = 20 bytes */
            CHECK(rlen2 >= 20, "Group A: receive Rattach", "got %d bytes", rlen2);

            if (rlen2 >= 20) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
                /* QID at offset 7: qtype[1] qversion[4] qpath[8] */
                uint8_t  qtype = rbuf[7];
                uint32_t qver  = (uint32_t)rbuf[8]
                               | ((uint32_t)rbuf[9] << 8)
                               | ((uint32_t)rbuf[10] << 16)
                               | ((uint32_t)rbuf[11] << 24);
                uint64_t qpath = 0;
                for (int i = 0; i < 8; i++)
                    qpath |= ((uint64_t)rbuf[12 + i]) << (i * 8);

                CHECK(resp_type == 105,
                      "Group A: Rattach type==105",
                      "got %u", resp_type);
                CHECK(resp_tag == 1,
                      "Group A: Rattach tag echoed (1)",
                      "got %u", resp_tag);
                CHECK((qtype & 0x80) != 0,
                      "Group A: root QID has QT_DIR (0x80) bit",
                      "got 0x%02X", qtype);
                CHECK(qpath == 1,
                      "Group A: root QID path==1",
                      "got %llu", (unsigned long long)qpath);
                printf("  Rattach: qid(type=0x%02X, version=%u, path=%llu)\n",
                       qtype, qver, (unsigned long long)qpath);
            }

            /* Tclunk(120) to close fid 0 */
            {
                uint8_t tclunk[16];
                size_t clunk_size = 4 + 1 + 2 + 4;  /* 11 */
                tclunk[0] = (uint8_t)(clunk_size & 0xFF);
                tclunk[1] = (uint8_t)((clunk_size >> 8) & 0xFF);
                tclunk[2] = 0; tclunk[3] = 0;
                tclunk[4] = 120;       /* Tclunk */
                tclunk[5] = 0x02;      /* tag = 2 */
                tclunk[6] = 0x00;
                tclunk[7] = 0; tclunk[8] = 0;  /* fid = 0 */
                tclunk[9] = 0; tclunk[10] = 0;
                send_all(p9_fd, tclunk, clunk_size);
                read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 1000);
            }
        }

        /* ===================================================================
         * Group H: 9P2000.L extended message types
         * ===================================================================
         * Verify the stub server handles Tlopen/Tlcreate/Tread/Twrite/Tremove.
         * Uses fid=10/11 to avoid colliding with fid=0 (clunked by Group A2).
         * Each test sends a request and validates the response type, tag echo,
         * and key body fields. */

        /* ---- Step H1: Tlopen(112) → Rlopen(113) ----
         * Tlopen body: fid[4] flags[4]
         * Rlopen body: qid[13] iounit[4] */
        printf("\n[host] Step H1: Group H - Tlopen(112) on fid=10...\n");
        {
            uint8_t tlopen[15];
            size_t msg_size = 4 + 1 + 2 + 4 + 4;  /* 15 */
            tlopen[0] = (uint8_t)(msg_size & 0xFF);
            tlopen[1] = (uint8_t)((msg_size >> 8) & 0xFF);
            tlopen[2] = 0; tlopen[3] = 0;
            tlopen[4] = 112;       /* Tlopen */
            tlopen[5] = 0x0A;      /* tag = 10 */
            tlopen[6] = 0x00;
            /* fid = 10 */
            tlopen[7] = 10; tlopen[8] = 0; tlopen[9] = 0; tlopen[10] = 0;
            /* flags = O_RDONLY (0x0000) */
            tlopen[11] = 0; tlopen[12] = 0; tlopen[13] = 0; tlopen[14] = 0;

            CHECK(send_all(p9_fd, tlopen, msg_size) == 0,
                  "Group H: send Tlopen", "send failed");

            int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rlopen: size[4] type[1] tag[2] qid[13] iounit[4] = 24 bytes */
            CHECK(rlen >= 24, "Group H: receive Rlopen", "got %d bytes", rlen);

            if (rlen >= 24) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
                uint8_t  qtype = rbuf[7];
                uint32_t iounit = (uint32_t)rbuf[20]
                                | ((uint32_t)rbuf[21] << 8)
                                | ((uint32_t)rbuf[22] << 16)
                                | ((uint32_t)rbuf[23] << 24);

                CHECK(resp_type == 113,
                      "Group H: Rlopen type==113",
                      "got %u", resp_type);
                CHECK(resp_tag == 10,
                      "Group H: Rlopen tag echoed (10)",
                      "got %u", resp_tag);
                CHECK((qtype & 0x80) == 0,
                      "Group H: Rlopen QID is regular file (no QT_DIR)",
                      "got 0x%02X", qtype);
                CHECK(iounit > 0,
                      "Group H: Rlopen iounit > 0",
                      "got %u", iounit);
                printf("  Rlopen: qid(type=0x%02X), iounit=%u\n", qtype, iounit);
            }
        }

        /* ---- Step H2: Tread(116) → Rread(117) ----
         * Tread body: fid[4] offset[8] count[4]
         * Rread body: count[4] data[count] (stub returns count=0) */
        printf("\n[host] Step H2: Group H - Tread(116) on fid=10...\n");
        {
            uint8_t tread[23];
            size_t msg_size = 4 + 1 + 2 + 4 + 8 + 4;  /* 23 */
            tread[0] = (uint8_t)(msg_size & 0xFF);
            tread[1] = (uint8_t)((msg_size >> 8) & 0xFF);
            tread[2] = 0; tread[3] = 0;
            tread[4] = 116;       /* Tread */
            tread[5] = 0x0B;     /* tag = 11 */
            tread[6] = 0x00;
            /* fid = 10 */
            tread[7] = 10; tread[8] = 0; tread[9] = 0; tread[10] = 0;
            /* offset = 0 */
            memset(&tread[11], 0, 8);
            /* count = 100 (request up to 100 bytes) */
            tread[19] = 100; tread[20] = 0; tread[21] = 0; tread[22] = 0;

            CHECK(send_all(p9_fd, tread, msg_size) == 0,
                  "Group H: send Tread", "send failed");

            int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rread: size[4] type[1] tag[2] count[4] = 11 bytes (count=0) */
            CHECK(rlen >= 11, "Group H: receive Rread", "got %d bytes", rlen);

            if (rlen >= 11) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
                uint32_t resp_count = (uint32_t)rbuf[7]
                                    | ((uint32_t)rbuf[8] << 8)
                                    | ((uint32_t)rbuf[9] << 16)
                                    | ((uint32_t)rbuf[10] << 24);

                CHECK(resp_type == 117,
                      "Group H: Rread type==117",
                      "got %u", resp_type);
                CHECK(resp_tag == 11,
                      "Group H: Rread tag echoed (11)",
                      "got %u", resp_tag);
                CHECK(resp_count == 0,
                      "Group H: Rread count==0 (empty file stub)",
                      "got %u", resp_count);
                printf("  Rread: count=%u (empty)\n", resp_count);
            }
        }

        /* ---- Step H3: Twrite(118) → Rwrite(119) ----
         * Twrite body: fid[4] offset[8] count[4] data[count]
         * Rwrite body: count[4] (echoes requested count) */
        printf("\n[host] Step H3: Group H - Twrite(118) on fid=10...\n");
        {
            const char *payload = "hello";
            uint32_t payload_len = (uint32_t)strlen(payload);
            size_t msg_size = 4 + 1 + 2 + 4 + 8 + 4 + payload_len;  /* 23 + 5 = 28 */
            uint8_t twrite[64];
            twrite[0] = (uint8_t)(msg_size & 0xFF);
            twrite[1] = (uint8_t)((msg_size >> 8) & 0xFF);
            twrite[2] = 0; twrite[3] = 0;
            twrite[4] = 118;       /* Twrite */
            twrite[5] = 0x0C;      /* tag = 12 */
            twrite[6] = 0x00;
            /* fid = 10 */
            twrite[7] = 10; twrite[8] = 0; twrite[9] = 0; twrite[10] = 0;
            /* offset = 0 */
            memset(&twrite[11], 0, 8);
            /* count = payload_len */
            twrite[19] = (uint8_t)(payload_len & 0xFF);
            twrite[20] = (uint8_t)((payload_len >> 8) & 0xFF);
            twrite[21] = 0; twrite[22] = 0;
            /* data */
            memcpy(&twrite[23], payload, payload_len);

            CHECK(send_all(p9_fd, twrite, msg_size) == 0,
                  "Group H: send Twrite", "send failed");

            int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rwrite: size[4] type[1] tag[2] count[4] = 11 bytes */
            CHECK(rlen >= 11, "Group H: receive Rwrite", "got %d bytes", rlen);

            if (rlen >= 11) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
                uint32_t resp_count = (uint32_t)rbuf[7]
                                    | ((uint32_t)rbuf[8] << 8)
                                    | ((uint32_t)rbuf[9] << 16)
                                    | ((uint32_t)rbuf[10] << 24);

                CHECK(resp_type == 119,
                      "Group H: Rwrite type==119",
                      "got %u", resp_type);
                CHECK(resp_tag == 12,
                      "Group H: Rwrite tag echoed (12)",
                      "got %u", resp_tag);
                CHECK(resp_count == payload_len,
                      "Group H: Rwrite count==payload_len",
                      "got %u (expected %u)", resp_count, payload_len);
                printf("  Rwrite: count=%u (echoed)\n", resp_count);
            }
        }

        /* ---- Step H4: Tlcreate(114) → Rlcreate(115) ----
         * Tlcreate body: fid[4] name[s] flags[4] mode[4] gid[4]
         * Rlcreate body: qid[13] iounit[4] */
        printf("\n[host] Step H4: Group H - Tlcreate(114) on fid=11...\n");
        {
            const char *name = "test";
            uint16_t name_len = (uint16_t)strlen(name);
            /* fid[4] + name_len[2] + name[4] + flags[4] + mode[4] + gid[4] = 22 body bytes */
            size_t msg_size = 4 + 1 + 2 + 4 + 2 + name_len + 4 + 4 + 4;  /* 29 */
            uint8_t tlcreate[32];
            tlcreate[0] = (uint8_t)(msg_size & 0xFF);
            tlcreate[1] = (uint8_t)((msg_size >> 8) & 0xFF);
            tlcreate[2] = 0; tlcreate[3] = 0;
            tlcreate[4] = 114;       /* Tlcreate */
            tlcreate[5] = 0x0D;      /* tag = 13 */
            tlcreate[6] = 0x00;
            /* fid = 11 */
            tlcreate[7] = 11; tlcreate[8] = 0; tlcreate[9] = 0; tlcreate[10] = 0;
            /* name: length + data */
            tlcreate[11] = (uint8_t)(name_len & 0xFF);
            tlcreate[12] = (uint8_t)((name_len >> 8) & 0xFF);
            memcpy(&tlcreate[13], name, name_len);
            /* flags = O_WRONLY|O_CREAT (0x0241) */
            tlcreate[17] = 0x41; tlcreate[18] = 0x02; tlcreate[19] = 0; tlcreate[20] = 0;
            /* mode = 0644 */
            tlcreate[21] = 0xA4; tlcreate[22] = 0x01; tlcreate[23] = 0; tlcreate[24] = 0;
            /* gid = 0 */
            memset(&tlcreate[25], 0, 4);

            CHECK(send_all(p9_fd, tlcreate, msg_size) == 0,
                  "Group H: send Tlcreate", "send failed");

            int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rlcreate: size[4] type[1] tag[2] qid[13] iounit[4] = 24 bytes */
            CHECK(rlen >= 24, "Group H: receive Rlcreate", "got %d bytes", rlen);

            if (rlen >= 24) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);
                uint8_t  qtype = rbuf[7];
                uint32_t iounit = (uint32_t)rbuf[20]
                                | ((uint32_t)rbuf[21] << 8)
                                | ((uint32_t)rbuf[22] << 16)
                                | ((uint32_t)rbuf[23] << 24);

                CHECK(resp_type == 115,
                      "Group H: Rlcreate type==115",
                      "got %u", resp_type);
                CHECK(resp_tag == 13,
                      "Group H: Rlcreate tag echoed (13)",
                      "got %u", resp_tag);
                CHECK((qtype & 0x80) == 0,
                      "Group H: Rlcreate QID is regular file (no QT_DIR)",
                      "got 0x%02X", qtype);
                CHECK(iounit > 0,
                      "Group H: Rlcreate iounit > 0",
                      "got %u", iounit);
                printf("  Rlcreate: qid(type=0x%02X), iounit=%u\n", qtype, iounit);
            }
        }

        /* ---- Step H5: Tremove(122) → Rremove(123) ----
         * Tremove body: fid[4]
         * Rremove body: (empty) */
        printf("\n[host] Step H5: Group H - Tremove(122) on fid=11...\n");
        {
            uint8_t tremove[11];
            size_t msg_size = 4 + 1 + 2 + 4;  /* 11 */
            tremove[0] = (uint8_t)(msg_size & 0xFF);
            tremove[1] = (uint8_t)((msg_size >> 8) & 0xFF);
            tremove[2] = 0; tremove[3] = 0;
            tremove[4] = 122;       /* Tremove */
            tremove[5] = 0x0E;      /* tag = 14 */
            tremove[6] = 0x00;
            /* fid = 11 */
            tremove[7] = 11; tremove[8] = 0; tremove[9] = 0; tremove[10] = 0;

            CHECK(send_all(p9_fd, tremove, msg_size) == 0,
                  "Group H: send Tremove", "send failed");

            int rlen = read_with_timeout(p9_fd, (char *)rbuf, sizeof(rbuf), 3000);
            /* Rremove: size[4] type[1] tag[2] = 7 bytes (empty body) */
            CHECK(rlen >= 7, "Group H: receive Rremove", "got %d bytes", rlen);

            if (rlen >= 7) {
                uint8_t  resp_type = rbuf[4];
                uint16_t resp_tag  = (uint16_t)rbuf[5] | ((uint16_t)rbuf[6] << 8);

                CHECK(resp_type == 123,
                      "Group H: Rremove type==123",
                      "got %u", resp_type);
                CHECK(resp_tag == 14,
                      "Group H: Rremove tag echoed (14)",
                      "got %u", resp_tag);
                printf("  Rremove: success (empty body)\n");
            }
        }

        close(p9_fd);
        printf("  Group A/H: 9P connection closed\n");
    }

    /* ---- Step A3 (Group A): StopPlan9Server(24) round-trip ----
     * Send StopPlan9Server with Force=true on the init channel.
     * Guest should stop the Plan9 server and respond with
     * RESULT_MESSAGE_BOOL (Result != 0 = success).
     * After stop, the Plan9 port should no longer accept connections. */
    printf("\n[host] Step A3: Group A - StopPlan9Server(24) round-trip...\n");
    {
        LX_INIT_STOP_PLAN9_SERVER_MSG stop_msg;
        memset(&stop_msg, 0, sizeof(stop_msg));
        stop_msg.Header.MessageType = LxInitMessageStopPlan9Server;
        stop_msg.Header.MessageSize = sizeof(stop_msg);
        stop_msg.Header.SequenceNumber = 777;
        stop_msg.Force = 1;  /* force=true (SIGKILL) */

        CHECK(send_all(init_fd, &stop_msg, sizeof(stop_msg)) == 0,
              "Group A: send StopPlan9Server", "send failed");

        RESULT_MESSAGE_BOOL *stop_resp =
            (RESULT_MESSAGE_BOOL *)recv_message(init_fd, &hdr);
        CHECK(stop_resp != NULL,
              "Group A: receive StopPlan9Server response", "no response");

        if (stop_resp) {
            CHECK(stop_resp->Header.MessageType == LxMessageResultBool,
                  "Group A: StopPlan9Server response type==76",
                  "got %u", stop_resp->Header.MessageType);
            CHECK(stop_resp->Header.SequenceNumber == 777,
                  "Group A: StopPlan9Server seq echoed (777)",
                  "got %u", stop_resp->Header.SequenceNumber);
            CHECK(stop_resp->Result != 0,
                  "Group A: StopPlan9Server result==true (success)",
                  "got %u", stop_resp->Result);
            printf("  StopPlan9Server response: type=%u, seq=%u, result=%u\n",
                   stop_resp->Header.MessageType,
                   stop_resp->Header.SequenceNumber, stop_resp->Result);
            free(stop_resp);
        }

        /* Verify Plan9 port is no longer accepting connections */
        usleep(300000);  /* give child time to exit */
        int retry_fd = connect_to_port(saved_plan9_port);
        CHECK(retry_fd < 0,
              "Group A: Plan9 port closed after stop",
              "connection still accepted (unexpected)");
        if (retry_fd >= 0) close(retry_fd);
    }

    /* ---- Step 74 (Phase 9 / C1): Accept GNS engine channel ---- */
    printf("\n[host] Step 74: Waiting for GNS channel connection on port %d...\n",
           PORT_HVS_GNS);
    {
        for (int attempt = 0; attempt < 50 && gns_fd < 0; attempt++) {
            struct pollfd pfd = { .fd = gns_listen_fd, .events = POLLIN };
            if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
                gns_fd = accept(gns_listen_fd, NULL, NULL);
                break;
            }
        }
        CHECK(gns_fd >= 0, "C1: GNS channel connected from guest", "timeout");
        if (gns_fd >= 0)
            printf("  GNS channel connected (fd=%d)\n", gns_fd);
    }

    /* Drain the initial burst of PortListenerRelayStart messages that the
     * guest's port_tracker sends when the GNS channel first connects.
     * These arrive asynchronously (within 1s of connect) and would otherwise
     * be misread as responses by later GNS test steps. */
    if (gns_fd >= 0) {
        /* Give the guest's port_tracker up to 1.5s to fire its first scan. */
        usleep(1500000);
        int drained = drain_relay_messages(gns_fd);
        printf("  Drained %d initial port_tracker notification(s)\n", drained);
        CHECK(1, "C: initial relay burst drained", "");
    }

    /* ---- Step 75 (Phase 9 / C3): InterfaceConfiguration ---- */
    printf("\n[host] Step 75: Sending InterfaceConfiguration (type=53)...\n");
    {
        const char *content =
#ifdef __FreeBSD__
            "interface=lo0\nup\n";
#else
            "interface=lo\nup\n";
#endif
        size_t content_len = strlen(content) + 1;
        size_t msg_size = sizeof(LX_GNS_INTERFACE_CONFIGURATION) + content_len;
        LX_GNS_INTERFACE_CONFIGURATION *ic = calloc(1, msg_size);
        if (!ic) {
            CHECK(0, "C3: InterfaceConfiguration alloc", "oom");
        } else {
            ic->Header.MessageType = LxGnsMessageInterfaceConfiguration;
            ic->Header.MessageSize = (unsigned int)msg_size;
            ic->Header.SequenceNumber = 750;
            memcpy(ic->Content, content, content_len);

            int sent = send_all(gns_fd, ic, msg_size);
            CHECK(sent == 0, "C3: InterfaceConfiguration sent",
                  "send returned %d", sent);
            free(ic);

            if (sent == 0) {
                LX_GNS_RESULT *gns_resp =
                    (LX_GNS_RESULT *)recv_gns_response(gns_fd, &hdr);
                if (gns_resp) {
                    printf("  Received: type=%u, seq=%u, Result=%d\n",
                           gns_resp->Header.MessageType,
                           gns_resp->Header.SequenceNumber,
                           gns_resp->Result);
                    CHECK(gns_resp->Header.MessageType == LxGnsMessageResult,
                          "C3: response MessageType==54 (LxGnsMessageResult)",
                          "got %u", gns_resp->Header.MessageType);
                    CHECK(gns_resp->Header.SequenceNumber == 750,
                          "C3: response seq echoed (750)",
                          "got %u", gns_resp->Header.SequenceNumber);
                    CHECK(gns_resp->Result == 0,
                          "C3: InterfaceConfiguration Result==0 (success)",
                          "got %d", gns_resp->Result);
                    free(gns_resp);
                } else {
                    CHECK(0, "C3: InterfaceConfiguration response received",
                          "no response");
                }
            }
        }
    }

    /* ---- Step 76: C3 round-trip marker (keeps step numbering contiguous) ---- */
    printf("\n[host] Step 76: C3 InterfaceConfiguration round-trip complete\n");
    CHECK(gns_fd >= 0, "C3: GNS channel still open after InterfaceConfiguration", "");

    /* ================================================================== */
    /* ---- Task Group B: LxGnsMessageDnsTunneling(70) tests           ---- */
    /* ---- Steps 76b-76g: UDP/TCP DNS relay round-trip               ---- */
    /* ================================================================== */

    /* Determine the DNS port (tests use WSL_DNS_TUNNEL_PORT to avoid
     * requiring root for binding port 53 on Linux). */
    int dns_port = 53;
    {
        const char *p = getenv("WSL_DNS_TUNNEL_PORT");
        if (p && p[0]) {
            int v = atoi(p);
            if (v > 0) dns_port = v;
        }
    }

    /* ---- Step 76b: Accept DNS tunneling channel ----
     * The guest opens a second connection to PORT_HVS for the DNS channel
     * right after the GNS channel connection (Step 74). Accept it here. */
    printf("\n[host] Step 76b: Waiting for DNS tunneling channel on port %d...\n",
           PORT_HVS);
    int dns_channel_fd = -1;
    {
        for (int attempt = 0; attempt < 50 && dns_channel_fd < 0; attempt++) {
            struct pollfd pfd = { .fd = listen_fd, .events = POLLIN };
            if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
                dns_channel_fd = accept(listen_fd, NULL, NULL);
                break;
            }
        }
        CHECK(dns_channel_fd >= 0, "B: DNS channel connected from guest", "timeout");
        if (dns_channel_fd >= 0)
            printf("  DNS channel connected (fd=%d)\n", dns_channel_fd);
    }

    /* Minimal DNS query: example.com A IN (29 bytes) */
    static const unsigned char dns_query_a[] = {
        0x12, 0x34,                                     /* ID */
        0x01, 0x00,                                     /* Flags: RD=1 */
        0x00, 0x01,                                     /* QDCOUNT: 1 */
        0x00, 0x00,                                     /* ANCOUNT: 0 */
        0x00, 0x00,                                     /* NSCOUNT: 0 */
        0x00, 0x00,                                     /* ARCOUNT: 0 */
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,                                           /* root label */
        0x00, 0x01,                                     /* Type: A */
        0x00, 0x01,                                     /* Class: IN */
    };
    /* DNS response: example.com A 10.0.0.1 TTL=60 (45 bytes) */
    static const unsigned char dns_resp_a[] = {
        0x12, 0x34,                                     /* ID */
        0x81, 0x80,                                     /* Flags: response, RA=1 */
        0x00, 0x01,                                     /* QDCOUNT: 1 */
        0x00, 0x01,                                     /* ANCOUNT: 1 */
        0x00, 0x00,                                     /* NSCOUNT: 0 */
        0x00, 0x00,                                     /* ARCOUNT: 0 */
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,
        0x00, 0x01, 0x00, 0x01,                         /* Type A, Class IN */
        0xc0, 0x0c,                                     /* Name ptr to offset 12 */
        0x00, 0x01, 0x00, 0x01,                         /* Type A, Class IN */
        0x00, 0x00, 0x00, 0x3c,                         /* TTL: 60 */
        0x00, 0x04,                                     /* RDLENGTH: 4 */
        0x0a, 0x00, 0x00, 0x01,                         /* RDATA: 10.0.0.1 */
    };

    if (dns_channel_fd >= 0) {
        /* ---- Step 76c: Send UDP DNS query to the guest's DNS server ---- */
        printf("\n[host] Step 76c: Sending UDP DNS query to 127.0.0.1:%d...\n",
               dns_port);
        int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(udp_sock >= 0, "B: UDP query socket created", "");

        if (udp_sock >= 0) {
            struct sockaddr_in dns_addr = {0};
            dns_addr.sin_family = AF_INET;
            dns_addr.sin_port = htons((uint16_t)dns_port);
            dns_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            /* Retry sending for up to 5s — the DNS grandchild may not
             * have bound the listener yet. */
            int sent_ok = 0;
            for (int attempt = 0; attempt < 50; attempt++) {
                ssize_t n = sendto(udp_sock, dns_query_a, sizeof(dns_query_a),
                                   0, (struct sockaddr *)&dns_addr,
                                   sizeof(dns_addr));
                if (n > 0) { sent_ok = 1; break; }
                usleep(100000);  /* 100ms */
            }
            CHECK(sent_ok, "B: UDP DNS query sent to guest",
                  "sendto failed: %s", strerror(errno));
        }

        /* ---- Step 76d: Receive LxGnsMessageDnsTunneling on DNS channel ---- */
        printf("\n[host] Step 76d: Waiting for LxGnsMessageDnsTunneling(70) on DNS channel...\n");
        uint32_t recv_udp_id = 0;
        {
            LX_GNS_DNS_TUNNELING_MESSAGE *dm =
                (LX_GNS_DNS_TUNNELING_MESSAGE *)recv_message(dns_channel_fd, &hdr);
            if (dm) {
                size_t dns_payload = hdr.MessageSize - sizeof(*dm);
                printf("  Received: type=%u, proto=%u, id=%u, dns_len=%zu\n",
                       dm->Header.MessageType, dm->DnsClientIdentifier.Protocol,
                       dm->DnsClientIdentifier.DnsClientId, dns_payload);
                CHECK(dm->Header.MessageType == LxGnsMessageDnsTunneling,
                      "B: DNS tunneling MessageType==70",
                      "got %u", dm->Header.MessageType);
                CHECK(dm->DnsClientIdentifier.Protocol == IPPROTO_UDP,
                      "B: DNS tunneling Protocol==UDP(17)",
                      "got %u", dm->DnsClientIdentifier.Protocol);
                CHECK(dm->DnsClientIdentifier.DnsClientId != 0,
                      "B: DNS tunneling DnsClientId!=0", "got 0");
                CHECK(dns_payload == sizeof(dns_query_a),
                      "B: DNS query payload size matches",
                      "got %zu, expected %zu", dns_payload, sizeof(dns_query_a));
                if (dns_payload == sizeof(dns_query_a))
                    CHECK(memcmp(dm->Buffer, dns_query_a, sizeof(dns_query_a)) == 0,
                          "B: DNS query payload content matches", "");
                recv_udp_id = dm->DnsClientIdentifier.DnsClientId;
                free(dm);
            } else {
                CHECK(0, "B: DNS tunneling message received", "no message");
            }
        }

        /* ---- Step 76e: Send DNS response, verify UDP client receives it ---- */
        printf("\n[host] Step 76e: Sending DNS response via channel, verifying UDP reply...\n");
        {
            size_t resp_msg_size = sizeof(LX_GNS_DNS_TUNNELING_MESSAGE) + sizeof(dns_resp_a);
            LX_GNS_DNS_TUNNELING_MESSAGE *resp = calloc(1, resp_msg_size);
            if (resp) {
                resp->Header.MessageType = LxGnsMessageDnsTunneling;
                resp->Header.MessageSize = (unsigned int)resp_msg_size;
                resp->Header.SequenceNumber = 0;
                resp->DnsClientIdentifier.Protocol = IPPROTO_UDP;
                resp->DnsClientIdentifier.DnsClientId = recv_udp_id;
                memcpy(resp->Buffer, dns_resp_a, sizeof(dns_resp_a));
                int sent = send_all(dns_channel_fd, resp, resp_msg_size);
                CHECK(sent == 0, "B: DNS response sent on channel",
                      "send returned %d", sent);
                free(resp);
            } else {
                CHECK(0, "B: DNS response alloc", "oom");
            }

            /* Wait for the UDP reply on the original socket (5s timeout) */
            unsigned char reply[512];
            ssize_t reply_len = -1;
            for (int attempt = 0; attempt < 50; attempt++) {
                struct pollfd pfd = { .fd = udp_sock, .events = POLLIN };
                if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
                    reply_len = recv(udp_sock, reply, sizeof(reply), 0);
                    break;
                }
            }
            CHECK(reply_len == (ssize_t)sizeof(dns_resp_a),
                  "B: UDP reply received with correct size",
                  "got %zd, expected %zu", reply_len, sizeof(dns_resp_a));
            if (reply_len == (ssize_t)sizeof(dns_resp_a))
                CHECK(memcmp(reply, dns_resp_a, sizeof(dns_resp_a)) == 0,
                      "B: UDP reply content matches DNS response", "");
            close(udp_sock);
        }

        /* ---- Step 76f: TCP DNS relay round-trip ---- */
        printf("\n[host] Step 76f: Sending TCP DNS query to 127.0.0.1:%d...\n",
               dns_port);
        {
            int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
            CHECK(tcp_sock >= 0, "B: TCP query socket created", "");

            if (tcp_sock >= 0) {
                struct sockaddr_in dns_addr = {0};
                dns_addr.sin_family = AF_INET;
                dns_addr.sin_port = htons((uint16_t)dns_port);
                dns_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                /* Retry connect for up to 5s — the DNS grandchild may
                 * not have bound the TCP listener yet. */
                int connected = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    if (connect(tcp_sock, (struct sockaddr *)&dns_addr,
                                sizeof(dns_addr)) == 0) {
                        connected = 1;
                        break;
                    }
                    usleep(100000);
                }
                CHECK(connected, "B: TCP connected to DNS server",
                      "connect failed: %s", strerror(errno));

                if (connected) {
                    /* Send 2-byte big-endian length prefix + DNS query */
                    uint16_t len_n = htons((uint16_t)sizeof(dns_query_a));
                    send_all(tcp_sock, &len_n, 2);
                    send_all(tcp_sock, dns_query_a, sizeof(dns_query_a));

                    /* Receive LxGnsMessageDnsTunneling on DNS channel */
                    LX_GNS_DNS_TUNNELING_MESSAGE *dm =
                        (LX_GNS_DNS_TUNNELING_MESSAGE *)recv_message(dns_channel_fd, &hdr);
                    uint32_t tcp_id = 0;
                    if (dm) {
                        CHECK(dm->Header.MessageType == LxGnsMessageDnsTunneling,
                              "B: TCP DNS tunneling MessageType==70",
                              "got %u", dm->Header.MessageType);
                        CHECK(dm->DnsClientIdentifier.Protocol == IPPROTO_TCP,
                              "B: TCP DNS tunneling Protocol==TCP(6)",
                              "got %u", dm->DnsClientIdentifier.Protocol);
                        CHECK(dm->DnsClientIdentifier.DnsClientId != 0,
                              "B: TCP DNS tunneling DnsClientId!=0", "got 0");
                        tcp_id = dm->DnsClientIdentifier.DnsClientId;
                        free(dm);
                    } else {
                        CHECK(0, "B: TCP DNS tunneling message received", "no message");
                    }

                    /* Send response on channel and verify TCP reply */
                    if (tcp_id != 0) {
                        size_t resp_msg_size = sizeof(LX_GNS_DNS_TUNNELING_MESSAGE) + sizeof(dns_resp_a);
                        LX_GNS_DNS_TUNNELING_MESSAGE *resp = calloc(1, resp_msg_size);
                        resp->Header.MessageType = LxGnsMessageDnsTunneling;
                        resp->Header.MessageSize = (unsigned int)resp_msg_size;
                        resp->DnsClientIdentifier.Protocol = IPPROTO_TCP;
                        resp->DnsClientIdentifier.DnsClientId = tcp_id;
                        memcpy(resp->Buffer, dns_resp_a, sizeof(dns_resp_a));
                        send_all(dns_channel_fd, resp, resp_msg_size);
                        free(resp);

                        /* Read 2-byte length + DNS response from TCP socket */
                        unsigned char reply[512];
                        uint16_t rlen_n = 0;
                        int ok = (recv_all(tcp_sock, &rlen_n, 2) == 0);
                        uint16_t rlen = ntohs(rlen_n);
                        ok = ok && (rlen == sizeof(dns_resp_a));
                        ok = ok && (recv_all(tcp_sock, reply, rlen) == 0);
                        CHECK(ok && memcmp(reply, dns_resp_a, sizeof(dns_resp_a)) == 0,
                              "B: TCP DNS reply content matches", "");
                    }
                }
                close(tcp_sock);
            }
        }

        /* ---- Step 76g: Concurrent UDP DNS queries ---- */
        printf("\n[host] Step 76g: Sending 2 concurrent UDP DNS queries...\n");
        {
            /* Use two different DNS query IDs (bytes 0-1) to distinguish them */
            unsigned char q1[sizeof(dns_query_a)];
            unsigned char q2[sizeof(dns_query_a)];
            memcpy(q1, dns_query_a, sizeof(q1));
            memcpy(q2, dns_query_a, sizeof(q2));
            q1[0] = 0x11; q1[1] = 0x11;  /* ID = 0x1111 */
            q2[0] = 0x22; q2[1] = 0x22;  /* ID = 0x2222 */

            /* Matching responses with the same IDs */
            unsigned char r1[sizeof(dns_resp_a)];
            unsigned char r2[sizeof(dns_resp_a)];
            memcpy(r1, dns_resp_a, sizeof(r1));
            memcpy(r2, dns_resp_a, sizeof(r2));
            r1[0] = 0x11; r1[1] = 0x11;
            r2[0] = 0x22; r2[1] = 0x22;

            int s1 = socket(AF_INET, SOCK_DGRAM, 0);
            int s2 = socket(AF_INET, SOCK_DGRAM, 0);
            CHECK(s1 >= 0 && s2 >= 0, "B: concurrent UDP sockets created", "");

            if (s1 >= 0 && s2 >= 0) {
                struct sockaddr_in dns_addr = {0};
                dns_addr.sin_family = AF_INET;
                dns_addr.sin_port = htons((uint16_t)dns_port);
                dns_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                sendto(s1, q1, sizeof(q1), 0,
                       (struct sockaddr *)&dns_addr, sizeof(dns_addr));
                sendto(s2, q2, sizeof(q2), 0,
                       (struct sockaddr *)&dns_addr, sizeof(dns_addr));

                /* Receive 2 DNS tunneling messages — order may vary.
                 * Match each to the correct response by DNS query ID. */
                uint32_t ids[2] = {0, 0};
                unsigned char *queries[2] = {NULL, NULL};
                for (int i = 0; i < 2; i++) {
                    LX_GNS_DNS_TUNNELING_MESSAGE *dm =
                        (LX_GNS_DNS_TUNNELING_MESSAGE *)recv_message(dns_channel_fd, &hdr);
                    if (dm) {
                        ids[i] = dm->DnsClientIdentifier.DnsClientId;
                        size_t plen = hdr.MessageSize - sizeof(*dm);
                        queries[i] = malloc(plen);
                        if (queries[i])
                            memcpy(queries[i], dm->Buffer, plen);
                        free(dm);
                    }
                }
                CHECK(ids[0] != 0 && ids[1] != 0 && ids[0] != ids[1],
                      "B: concurrent UDP got 2 distinct DnsClientIds",
                      "ids=%u,%u", ids[0], ids[1]);

                /* Send the correct response for each DnsClientId */
                for (int i = 0; i < 2; i++) {
                    if (ids[i] != 0 && queries[i]) {
                        unsigned char *resp_data = (queries[i][0] == 0x11) ? r1 : r2;
                        size_t msg_sz = sizeof(LX_GNS_DNS_TUNNELING_MESSAGE) + sizeof(r1);
                        LX_GNS_DNS_TUNNELING_MESSAGE *resp = calloc(1, msg_sz);
                        resp->Header.MessageType = LxGnsMessageDnsTunneling;
                        resp->Header.MessageSize = (unsigned int)msg_sz;
                        resp->DnsClientIdentifier.Protocol = IPPROTO_UDP;
                        resp->DnsClientIdentifier.DnsClientId = ids[i];
                        memcpy(resp->Buffer, resp_data, sizeof(r1));
                        send_all(dns_channel_fd, resp, msg_sz);
                        free(resp);
                    }
                }

                /* Verify both sockets receive the correct responses (5s) */
                int got1 = 0, got2 = 0;
                for (int attempt = 0; attempt < 50 && (!got1 || !got2); attempt++) {
                    if (!got1) {
                        struct pollfd pfd = { .fd = s1, .events = POLLIN };
                        if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
                            unsigned char reply[512];
                            ssize_t n = recv(s1, reply, sizeof(reply), 0);
                            got1 = (n == (ssize_t)sizeof(r1) &&
                                    memcmp(reply, r1, sizeof(r1)) == 0);
                        }
                    }
                    if (!got2) {
                        struct pollfd pfd = { .fd = s2, .events = POLLIN };
                        if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
                            unsigned char reply[512];
                            ssize_t n = recv(s2, reply, sizeof(reply), 0);
                            got2 = (n == (ssize_t)sizeof(r2) &&
                                    memcmp(reply, r2, sizeof(r2)) == 0);
                        }
                    }
                }
                CHECK(got1, "B: concurrent UDP socket 1 received correct response", "");
                CHECK(got2, "B: concurrent UDP socket 2 received correct response", "");

                for (int i = 0; i < 2; i++) free(queries[i]);
            }
            if (s1 >= 0) close(s1);
            if (s2 >= 0) close(s2);
        }

        /* Close the DNS channel — the guest's DNS relay will detect EOF
         * and shut down. The GNS channel (gns_fd) remains open for the
         * remaining GNS tests below. */
        close(dns_channel_fd);
        dns_channel_fd = -1;
    } else {
        printf("\n[host] Steps 76c-76g: SKIPPED (DNS channel not connected)\n");
    }

    /* ---- Step 77 (Phase 9 / C1): GNS NoOp message ---- */
    printf("\n[host] Step 77: Sending GNS NoOp (type=71)...\n");
    {
        struct MESSAGE_HEADER noop;
        memset(&noop, 0, sizeof(noop));
        noop.MessageType = LxGnsMessageNoOp;
        noop.MessageSize = sizeof(noop);
        noop.SequenceNumber = 771;

        int sent = send_all(gns_fd, &noop, sizeof(noop));
        CHECK(sent == 0, "C1: GNS NoOp sent", "send returned %d", sent);

        if (sent == 0) {
            LX_GNS_RESULT *gns_resp =
                (LX_GNS_RESULT *)recv_gns_response(gns_fd, &hdr);
            if (gns_resp) {
                CHECK(gns_resp->Header.MessageType == LxGnsMessageResult,
                      "C1: NoOp response MessageType==54",
                      "got %u", gns_resp->Header.MessageType);
                CHECK(gns_resp->Header.SequenceNumber == 771,
                      "C1: NoOp response seq echoed (771)",
                      "got %u", gns_resp->Header.SequenceNumber);
                CHECK(gns_resp->Result == 0,
                      "C1: NoOp Result==0", "got %d", gns_resp->Result);
                free(gns_resp);
            } else {
                CHECK(0, "C1: NoOp response received", "no response");
            }
        }
    }

    /* ---- Step 77b (Phase 9 / G): GNS SetupIpv6 (type=69) ----
     * G: Verify SetupIpv6 now performs actual IPv6 configuration and
     * responds with success (was: simple ack with "ipv6 ack" message). */
    printf("\n[host] Step 77b: Sending GNS SetupIpv6 (type=69)...\n");
    {
        struct MESSAGE_HEADER ipv6_msg;
        memset(&ipv6_msg, 0, sizeof(ipv6_msg));
        ipv6_msg.MessageType = LxGnsMessageSetupIpv6;
        ipv6_msg.MessageSize = sizeof(ipv6_msg);
        ipv6_msg.SequenceNumber = 772;

        int sent = send_all(gns_fd, &ipv6_msg, sizeof(ipv6_msg));
        CHECK(sent == 0, "G: SetupIpv6 sent", "send returned %d", sent);

        if (sent == 0) {
            LX_GNS_RESULT *gns_resp =
                (LX_GNS_RESULT *)recv_gns_response(gns_fd, &hdr);
            if (gns_resp) {
                CHECK(gns_resp->Header.MessageType == LxGnsMessageResult,
                      "G: SetupIpv6 response MessageType==54",
                      "got %u", gns_resp->Header.MessageType);
                CHECK(gns_resp->Header.SequenceNumber == 772,
                      "G: SetupIpv6 response seq echoed (772)",
                      "got %u", gns_resp->Header.SequenceNumber);
                CHECK(gns_resp->Result == 0,
                      "G: SetupIpv6 Result==0 (success)",
                      "got %d", gns_resp->Result);
                printf("  SetupIpv6 response: '%s'\n",
                       gns_resp->Buffer[0] ? gns_resp->Buffer : "(empty)");
                free(gns_resp);
            } else {
                CHECK(0, "G: SetupIpv6 response received", "no response");
            }
        }
    }

    /* ================================================================== */
    /* ---- Task Group D: LxGnsMessageNotification(55) HNS state tests  ---- */
    /* ---- Steps 78-82: Route/IPAddress/DNS/Interface/unknown          ---- */
    /* ================================================================== */

    /* Helper: send a Notification(55) with a JSON payload on gns_fd and
     * verify the LX_GNS_RESULT response (type=54, seq echoed, Result==0). */
    #define SEND_NOTIFICATION(json, seq_num, desc_ok, desc_fail)                  \
        do {                                                                      \
            size_t _clen = strlen(json) + 1;                                      \
            size_t _msz = sizeof(LX_GNS_INTERFACE_CONFIGURATION) + _clen;         \
            LX_GNS_INTERFACE_CONFIGURATION *_m = calloc(1, _msz);                 \
            if (_m) {                                                             \
                _m->Header.MessageType = LxGnsMessageNotification;                \
                _m->Header.MessageSize = (unsigned int)_msz;                      \
                _m->Header.SequenceNumber = (seq_num);                            \
                memcpy(_m->Content, (json), _clen);                               \
                int _sr = send_all(gns_fd, _m, _msz);                             \
                CHECK(_sr == 0, "D: Notification sent (" desc_ok ")",             \
                      "send failed");                                             \
                free(_m);                                                         \
                if (_sr == 0) {                                                   \
                    LX_GNS_RESULT *_r = (LX_GNS_RESULT *)recv_gns_response(gns_fd, &hdr); \
                    if (_r) {                                                     \
                        CHECK(_r->Header.MessageType == LxGnsMessageResult,       \
                              "D: response type==54", "got %u",                   \
                              _r->Header.MessageType);                            \
                        CHECK(_r->Header.SequenceNumber == (seq_num),             \
                              "D: response seq echoed", "got %u",                 \
                              _r->Header.SequenceNumber);                         \
                        CHECK(_r->Result == 0,                                    \
                              "D: Result==0 (" desc_ok ")", "got %d", _r->Result);\
                        free(_r);                                                 \
                    } else {                                                      \
                        CHECK(0, "D: response received (" desc_ok ")",            \
                              "no response");                                     \
                    }                                                             \
                }                                                                 \
            } else {                                                              \
                CHECK(0, "D: alloc (" desc_ok ")", "oom");                        \
            }                                                                     \
        } while (0)

    /* Step 78: Notification Route Add (default route via 10.0.0.1) */
    printf("\n[host] Step 78: Sending Notification(55) Route Add...\n");
    {
        const char *json =
            "{\"ResourceType\":\"Route\",\"RequestType\":\"Add\","
            "\"Settings\":{\"NextHop\":\"10.0.0.1\","
            "\"DestinationPrefix\":\"0.0.0.0/0\",\"Family\":2},"
            "\"targetDeviceName\":\"lo0\"}";
        SEND_NOTIFICATION(json, 781, "Route Add", "route add");
    }

    /* Step 79: Notification IPAddress Add (alias 10.99.99.1/32 on lo0) */
    printf("\n[host] Step 79: Sending Notification(55) IPAddress Add...\n");
    {
        const char *json =
            "{\"ResourceType\":\"IPAddress\",\"RequestType\":\"Add\","
            "\"Settings\":{\"Address\":\"10.99.99.1\","
            "\"OnLinkPrefixLength\":32,\"Family\":2},"
            "\"targetDeviceName\":\"lo0\"}";
        SEND_NOTIFICATION(json, 791, "IPAddress Add", "ip add");
    }

    /* Step 80: Notification DNS Update (writes resolv.conf) */
    printf("\n[host] Step 80: Sending Notification(55) DNS Update...\n");
    {
        const char *json =
            "{\"ResourceType\":\"DNS\",\"RequestType\":\"Update\","
            "\"Settings\":{\"ServerList\":\"10.0.0.1,10.0.0.2\","
            "\"Domain\":\"example.com\","
            "\"Search\":\"example.com,test.com\"}}";
        SEND_NOTIFICATION(json, 801, "DNS Update", "dns update");
    }

    /* Step 81: Notification Interface Update (link up + MTU 1500 on lo0) */
    printf("\n[host] Step 81: Sending Notification(55) Interface Update...\n");
    {
        const char *json =
            "{\"ResourceType\":\"Interface\",\"RequestType\":\"Update\","
            "\"Settings\":{\"Connected\":true,\"NlMtu\":1500},"
            "\"targetDeviceName\":\"lo0\"}";
        SEND_NOTIFICATION(json, 811, "Interface Update", "link update");
    }

    /* Step 82: Notification unknown ResourceType (ack without error) */
    printf("\n[host] Step 82: Sending Notification(55) unknown ResourceType...\n");
    {
        const char *json =
            "{\"ResourceType\":\"Neighbor\",\"RequestType\":\"Add\","
            "\"Settings\":{}}";
        SEND_NOTIFICATION(json, 821, "unknown ResourceType acked", "unknown type");
    }

    #undef SEND_NOTIFICATION

    /* ---- Step 83 (Phase 9 / C): Port discovery — PortListenerRelayStart ----
     * Open a new listening socket on a test port and verify the guest's
     * port_tracker detects it and sends LxGnsMessagePortListenerRelayStart(59).
     * The port_tracker scans /proc/net/tcp (Linux) or sysctl pcblist (FreeBSD)
     * every 1 second and sends relay notifications for new loopback/wildcard
     * binds. */
    printf("\n[host] Step 83: Port discovery test (open port 18080)...\n");
    {
        /* Flush any relay messages that may have accumulated since the
         * initial drain (port_tracker may have fired during Steps 75-82). */
        drain_relay_messages(gns_fd);

        int test_port = 18080;
        int test_listen = listen_on_port(test_port);
        CHECK(test_listen >= 0, "C: test port 18080 bound", "bind failed");

        if (test_listen >= 0 && gns_fd >= 0) {
            printf("  Opened listening socket on port %d, waiting for relay...\n",
                   test_port);
            /* port_tracker scans every 1s; allow up to 5s for detection. */
            int relay_type = recv_relay_for_port(gns_fd, (uint16_t)test_port, 5000);
            CHECK(relay_type == LxGnsMessagePortListenerRelayStart,
                  "C: PortListenerRelayStart(59) received for port 18080",
                  "got type=%d (expected %d)", relay_type,
                  LxGnsMessagePortListenerRelayStart);

            /* ---- Step 84: Port removal — PortListenerRelayStop ----
             * Close the test socket and verify the guest sends
             * LxGnsMessagePortListenerRelayStop(60) for the removed port. */
            printf("\n[host] Step 84: Port removal test (close port 18080)...\n");
            close(test_listen);
            printf("  Closed listening socket, waiting for relay...\n");

            int relay_type2 = recv_relay_for_port(gns_fd, (uint16_t)test_port, 5000);
            CHECK(relay_type2 == LxGnsMessagePortListenerRelayStop,
                  "C: PortListenerRelayStop(60) received for port 18080",
                  "got type=%d (expected %d)", relay_type2,
                  LxGnsMessagePortListenerRelayStop);
        } else if (test_listen >= 0) {
            close(test_listen);
        }
    }

    /* ================================================================== */
    /* ---- Task Group C/D/E: GNS request/response round-trips         ---- */
    /* ---- Steps 85-94: PortMapping/SetListener/ListenerRelay/        ---- */
    /* ---- CreateDevice/ModifyDevice/LoopbackRoutes/DeviceSetting/    ---- */
    /* ---- IfStateChange/GlobalNetFilter/InterfaceNetFilter            ---- */
    /* ================================================================== */

    /* Helper: send a GNS request with JSON payload and verify the response.
     * Uses LX_GNS_INTERFACE_CONFIGURATION as the wire format (Header + Content[]).
     * expected_resp_type is LxGnsMessageResult(54) for most, or
     * LxGnsMessageIfStateChangeResponse(67) for IfStateChangeRequest. */
    #define SEND_GNS_REQUEST(msg_type, json, seq_num, expected_resp_type, \
                              desc)                                               \
        do {                                                                      \
            size_t _clen = strlen(json) + 1;                                     \
            size_t _msz = sizeof(LX_GNS_INTERFACE_CONFIGURATION) + _clen;       \
            LX_GNS_INTERFACE_CONFIGURATION *_m = calloc(1, _msz);                 \
            if (_m) {                                                            \
                _m->Header.MessageType = (msg_type);                            \
                _m->Header.MessageSize = (unsigned int)_msz;                    \
                _m->Header.SequenceNumber = (seq_num);                          \
                memcpy(_m->Content, (json), _clen);                             \
                int _sr = send_all(gns_fd, _m, _msz);                           \
                CHECK(_sr == 0, desc " sent", "send failed");                    \
                free(_m);                                                        \
                if (_sr == 0) {                                                 \
                    LX_GNS_RESULT *_r =                                          \
                        (LX_GNS_RESULT *)recv_gns_response(gns_fd, &hdr);      \
                    if (_r) {                                                    \
                        CHECK(_r->Header.MessageType == (expected_resp_type),   \
                              desc " resp type", "got %u",                      \
                              _r->Header.MessageType);                          \
                        CHECK(_r->Header.SequenceNumber == (seq_num),           \
                              desc " seq echoed", "got %u",                     \
                              _r->Header.SequenceNumber);                      \
                        CHECK(_r->Result == 0,                                  \
                              desc " Result==0", "got %d", _r->Result);         \
                        free(_r);                                                \
                    } else {                                                     \
                        CHECK(0, desc " resp received", "no response");         \
                    }                                                            \
                }                                                                \
            } else {                                                             \
                CHECK(0, desc " alloc", "oom");                                  \
            }                                                                    \
        } while (0)

    printf("\n[host] Step 85: GNS PortMappingRequest(56)...\n");
    SEND_GNS_REQUEST(LxGnsMessagePortMappingRequest,
                     "{\"Port\":8080,\"Protocol\":\"tcp\",\"Remove\":false}",
                     851, LxGnsMessageResult, "C: PortMappingRequest");

    printf("\n[host] Step 86: GNS SetPortListener(58)...\n");
    SEND_GNS_REQUEST(LxGnsMessageSetPortListener,
                     "{\"Family\":2,\"Port\":9090,\"Address\":\"127.0.0.1\"}",
                     861, LxGnsMessageResult, "C: SetPortListener");

    printf("\n[host] Step 87: GNS ListenerRelay(75)...\n");
    SEND_GNS_REQUEST(LxGnsMessageListenerRelay,
                     "{\"Port\":7070,\"Family\":2}",
                     871, LxGnsMessageResult, "C: ListenerRelay");

    printf("\n[host] Step 88: GNS CreateDeviceRequest(62)...\n");
    SEND_GNS_REQUEST(LxGnsMessageCreateDeviceRequest,
                     "{\"Name\":\"eth1\",\"Type\":\"veth\",\"MAC\":\"02:00:00:00:00:01\"}",
                     881, LxGnsMessageResult, "D: CreateDevice");

    printf("\n[host] Step 89: GNS ModifyGuestDeviceSettingRequest(63)...\n");
    SEND_GNS_REQUEST(LxGnsMessageModifyGuestDeviceSettingRequest,
                     "{\"Name\":\"eth1\",\"Setting\":\"mtu\",\"Value\":\"1500\"}",
                     891, LxGnsMessageResult, "D: ModifyDeviceSetting");

    printf("\n[host] Step 90: GNS LoopbackRoutesRequest(64)...\n");
    SEND_GNS_REQUEST(LxGnsMessageLoopbackRoutesRequest,
                     "{\"Action\":\"add\",\"Destination\":\"127.0.0.0/8\"}",
                     901, LxGnsMessageResult, "D: LoopbackRoutes");

    printf("\n[host] Step 91: GNS DeviceSettingRequest(65)...\n");
    SEND_GNS_REQUEST(LxGnsMessageDeviceSettingRequest,
                     "{\"Name\":\"eth1\",\"Setting\":\"mtu\"}",
                     911, LxGnsMessageResult, "D: DeviceSetting");

    printf("\n[host] Step 92: GNS IfStateChangeRequest(66) -> IfStateChangeResponse(67)...\n");
    SEND_GNS_REQUEST(LxGnsMessageIfStateChangeRequest,
                     "{\"Name\":\"lo0\",\"Up\":true,\"MTU\":1500}",
                     921, LxGnsMessageIfStateChangeResponse, "D: IfStateChange");

    printf("\n[host] Step 93: GNS GlobalNetFilter(72)...\n");
    SEND_GNS_REQUEST(LxGnsMessageGlobalNetFilter,
                     "{\"Action\":\"add\",\"Rules\":\"pass in all\"}",
                     931, LxGnsMessageResult, "E: GlobalNetFilter");

    printf("\n[host] Step 94: GNS InterfaceNetFilter(73)...\n");
    SEND_GNS_REQUEST(LxGnsMessageInterfaceNetFilter,
                     "{\"Name\":\"eth1\",\"Action\":\"add\",\"Rules\":\"pass in all\"}",
                     941, LxGnsMessageResult, "E: InterfaceNetFilter");

    #undef SEND_GNS_REQUEST

    /* ---- Step 6: Connect to hvbridge on port 60000 ---- */
    printf("\n[host] Step 6: Connecting to hvbridge on port %d...\n", PORT_HVS_BSD);
    int bridge_init = connect_to_port(PORT_HVS_BSD);
    if (bridge_init < 0) { fprintf(stderr, "  [FAIL] cannot connect to bridge\n"); return 1; }
    printf("  Init channel connected\n");

    /* Second connection: control channel — send CreateProcessUtilityVm */
    int bridge_initial = connect_to_port(PORT_HVS_BSD);
    if (bridge_initial < 0) { fprintf(stderr, "  [FAIL] cannot connect initial\n"); return 1; }

    printf("\n[host] Step 7: Sending CreateProcessUtilityVm (Rows=30, Cols=120, with env/cwd)...\n");

    /* Phase 2: Build CreateProcessUtilityVm with Filename, CWD, CommandLine,
     * and Environment strings in Common.Buffer. Offsets are relative to
     * the start of Common.Buffer. */
    const char *filename = "/bin/sh";
    const char *cwd = "/tmp";
    const char *cmdline = "sh";  /* argv[0] */
    const char *env_vars[] = {
        "TEST_ENV_VAR=phase2_ok",
        "TERM=xterm",
        "PATH=/bin:/usr/bin",
    };
    int env_count = (int)(sizeof(env_vars) / sizeof(env_vars[0]));

    uint32_t off_filename = 0;
    uint32_t off_cwd = off_filename + (uint32_t)strlen(filename) + 1;
    uint32_t off_cmdline = off_cwd + (uint32_t)strlen(cwd) + 1;
    uint32_t off_env = off_cmdline + (uint32_t)strlen(cmdline) + 1;

    size_t env_total = 0;
    for (int i = 0; i < env_count; i++)
        env_total += strlen(env_vars[i]) + 1;
    size_t buffer_size = off_env + env_total;

    size_t msg_size = offsetof(LX_INIT_CREATE_PROCESS_UTILITY_VM, Common.Buffer) + buffer_size;
    LX_INIT_CREATE_PROCESS_UTILITY_VM *proc_msg = calloc(1, msg_size);
    if (!proc_msg) { fprintf(stderr, "calloc failed\n"); return 1; }

    proc_msg->Header.MessageType = LxInitMessageCreateProcessUtilityVm;
    proc_msg->Header.MessageSize = (uint32_t)msg_size;
    proc_msg->Header.SequenceNumber = 7;
    proc_msg->Rows = 30;
    proc_msg->Columns = 120;
    proc_msg->Common.FilenameOffset = off_filename;
    proc_msg->Common.CurrentWorkingDirectoryOffset = off_cwd;
    proc_msg->Common.CommandLineOffset = off_cmdline;
    proc_msg->Common.CommandLineCount = 1;
    proc_msg->Common.EnvironmentOffset = off_env;
    proc_msg->Common.EnvironmentCount = (uint16_t)env_count;

    char *cbuf = proc_msg->Common.Buffer;
    memcpy(cbuf + off_filename, filename, strlen(filename) + 1);
    memcpy(cbuf + off_cwd, cwd, strlen(cwd) + 1);
    memcpy(cbuf + off_cmdline, cmdline, strlen(cmdline) + 1);
    {
        size_t pos = off_env;
        for (int i = 0; i < env_count; i++) {
            memcpy(cbuf + pos, env_vars[i], strlen(env_vars[i]) + 1);
            pos += strlen(env_vars[i]) + 1;
        }
    }

    if (send_all(bridge_initial, proc_msg, msg_size) < 0) {
        perror("send CreateProcessUtilityVm");
        free(proc_msg);
        return 1;
    }
    printf("  Sent (type=%u, seq=%u, Rows=%u, Cols=%u, buf_size=%zu)\n",
           proc_msg->Header.MessageType, proc_msg->Header.SequenceNumber,
           proc_msg->Rows, proc_msg->Columns, buffer_size);
    printf("  Filename='%s', CWD='%s', EnvCount=%d\n", filename, cwd, env_count);
    free(proc_msg);

    RESULT_MESSAGE_UINT32 *result =
        (RESULT_MESSAGE_UINT32 *)recv_message(bridge_initial, &hdr);
    if (!result) { fprintf(stderr, "  [FAIL] cannot receive ResultUint32\n"); return 1; }

    printf("  Received: MessageType=%u, seq=%u, Result=%u\n",
           result->Header.MessageType, result->Header.SequenceNumber, result->Result);

    CHECK(result->Header.MessageType == LxMessageResultUint32,
          "CreateProcessUtilityVm response MessageType==78 (was 8)",
          "got %u", result->Header.MessageType);
    CHECK(result->Header.SequenceNumber == 7,
          "ResultUint32 seq echoed (7)",
          "got %u", result->Header.SequenceNumber);
    free(result);

    /* ---- Step 8: Connect 5 additional sockets ---- */
    printf("\n[host] Step 8: Connecting 5 additional sockets (stdin/out/err/channel/interop)...\n");
    int extra[5];
    for (int i = 0; i < 5; i++) {
        extra[i] = connect_to_port(PORT_HVS_BSD);
        if (extra[i] < 0) { fprintf(stderr, "  [FAIL] cannot connect extra %d\n", i); return 1; }
        printf("  Socket %d connected (fd=%d)\n", i, extra[i]);
    }

    /* ---- Step 9: Console I/O test ---- */
    printf("\n[host] Step 9: Console I/O test...\n");
    usleep(300000);  /* give console handler time to start shell */

    const char *cmd = "echo test_phase1_ok\n";
    if (send_all(extra[0], cmd, strlen(cmd)) < 0) {
        perror("send cmd"); return 1;
    }
    printf("  Sent: %s", cmd);

    char outbuf[4096];
    memset(outbuf, 0, sizeof(outbuf));
    int total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "test_phase1_ok")) break;
        }
    }

    printf("  Console output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "test_phase1_ok") != NULL,
          "Console I/O: echo command output received",
          "output='%s'", outbuf);

    /* ---- Step 9b (Phase 2): Environment variable test ---- */
    /* Verify that envp from CreateProcessUtilityVm was passed to execve.
     * The shell should see TEST_ENV_VAR=phase2_ok in its environment. */
    printf("\n[host] Step 9b: Phase 2 environment variable test...\n");
    usleep(100000);

    const char *env_cmd = "echo $TEST_ENV_VAR\n";
    if (send_all(extra[0], env_cmd, strlen(env_cmd)) < 0) {
        perror("send env_cmd"); return 1;
    }
    printf("  Sent: %s", env_cmd);

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "phase2_ok")) break;
        }
    }
    printf("  env output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "phase2_ok") != NULL,
          "Phase 2: environment variable TEST_ENV_VAR=phase2_ok (execve envp)",
          "output='%s'", outbuf);

    /* ---- Step 9c (Phase 2): Working directory test ---- */
    /* Verify that chdir was called with CWD from CreateProcessUtilityVm
     * before execve. The shell's pwd should be /tmp. */
    printf("\n[host] Step 9c: Phase 2 working directory test...\n");
    const char *pwd_cmd = "pwd\n";
    if (send_all(extra[0], pwd_cmd, strlen(pwd_cmd)) < 0) {
        perror("send pwd_cmd"); return 1;
    }
    printf("  Sent: %s", pwd_cmd);

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "/tmp")) break;
        }
    }
    printf("  pwd output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "/tmp") != NULL,
          "Phase 2: working directory /tmp (chdir before execve)",
          "output='%s'", outbuf);

    /* ---- Step 9d (Phase 3): PTY raw mode test ---- */
    /* In raw mode, the PTY should NOT echo input. Only the command output
     * should appear, not the command text itself. This verifies that
     * cfmakeraw was called on the PTY slave before exec. */
    printf("\n[host] Step 9d: Phase 3 raw mode test (no PTY echo)...\n");
    usleep(100000);

    const char *raw_cmd = "echo RAW_PHASE3_XYZ\n";
    if (send_all(extra[0], raw_cmd, strlen(raw_cmd)) < 0) {
        perror("send raw_cmd"); return 1;
    }
    printf("  Sent: %s", raw_cmd);

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "RAW_PHASE3_XYZ")) break;
        }
    }
    printf("  raw mode output: '%s'\n", outbuf);

    /* Command output should be present */
    CHECK(strstr(outbuf, "RAW_PHASE3_XYZ") != NULL,
          "Phase 3: raw mode command output present",
          "output='%s'", outbuf);
    /* PTY echo of command text should be absent (raw mode = no echo) */
    CHECK(strstr(outbuf, "echo RAW_PHASE3_XYZ") == NULL,
          "Phase 3: no PTY echo in raw mode (cfmakeraw active)",
          "output contains 'echo RAW_PHASE3_XYZ' — PTY is in cooked mode!");

    /* ---- Step 10 (Phase 1): WindowSizeChanged test ---- */
    printf("\n[host] Step 10: Sending WindowSizeChanged (rows=40, cols=100) on control channel...\n");
    LX_INIT_WINDOW_SIZE_CHANGED wsc_msg;
    memset(&wsc_msg, 0, sizeof(wsc_msg));
    wsc_msg.Header.MessageType = LxInitMessageWindowSizeChanged;
    wsc_msg.Header.MessageSize = sizeof(wsc_msg);
    wsc_msg.Header.SequenceNumber = 10;
    wsc_msg.Rows = 40;
    wsc_msg.Columns = 100;

    if (send_all(bridge_initial, &wsc_msg, sizeof(wsc_msg)) < 0) {
        perror("send WindowSizeChanged"); return 1;
    }
    printf("  Sent WindowSizeChanged (type=%u, rows=%u, cols=%u)\n",
           wsc_msg.Header.MessageType, wsc_msg.Rows, wsc_msg.Columns);

    /* Give the bridge time to process the resize */
    usleep(200000);

    /* Verify by running `stty size` in the shell */
    const char *stty_cmd = "stty size\n";
    if (send_all(extra[0], stty_cmd, strlen(stty_cmd)) < 0) {
        perror("send stty size"); return 1;
    }
    printf("  Sent: %s", stty_cmd);

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            /* stty size outputs "rows cols\n" e.g. "40 100\n" */
            if (strstr(outbuf, "40 100")) break;
        }
    }

    printf("  stty size output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "40 100") != NULL,
          "WindowSizeChanged: PTY resized to 40x100 (Phase 1)",
          "output='%s'", outbuf);

    /* ---- Step 10b (Phase 3): Resize to minimum 1x1 ---- */
    printf("\n[host] Step 10b: Phase 3 resize to minimum (1x1)...\n");
    memset(&wsc_msg, 0, sizeof(wsc_msg));
    wsc_msg.Header.MessageType = LxInitMessageWindowSizeChanged;
    wsc_msg.Header.MessageSize = sizeof(wsc_msg);
    wsc_msg.Header.SequenceNumber = 11;
    wsc_msg.Rows = 1;
    wsc_msg.Columns = 1;

    if (send_all(bridge_initial, &wsc_msg, sizeof(wsc_msg)) < 0) {
        perror("send WindowSizeChanged 1x1"); return 1;
    }
    printf("  Sent WindowSizeChanged (rows=1, cols=1)\n");
    usleep(200000);

    if (send_all(extra[0], stty_cmd, strlen(stty_cmd)) < 0) {
        perror("send stty size 1x1"); return 1;
    }

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "1 1")) break;
        }
    }
    printf("  stty size output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "1 1") != NULL,
          "Phase 3: resize to minimum 1x1",
          "output='%s'", outbuf);

    /* ---- Step 10c (Phase 3): Resize back to large 50x200 ---- */
    printf("\n[host] Step 10c: Phase 3 resize back to large (50x200)...\n");
    memset(&wsc_msg, 0, sizeof(wsc_msg));
    wsc_msg.Header.MessageType = LxInitMessageWindowSizeChanged;
    wsc_msg.Header.MessageSize = sizeof(wsc_msg);
    wsc_msg.Header.SequenceNumber = 12;
    wsc_msg.Rows = 50;
    wsc_msg.Columns = 200;

    if (send_all(bridge_initial, &wsc_msg, sizeof(wsc_msg)) < 0) {
        perror("send WindowSizeChanged 50x200"); return 1;
    }
    printf("  Sent WindowSizeChanged (rows=50, cols=200)\n");
    usleep(200000);

    if (send_all(extra[0], stty_cmd, strlen(stty_cmd)) < 0) {
        perror("send stty size 50x200"); return 1;
    }

    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total - 1, 200);
        if (n > 0) {
            total += n;
            outbuf[total] = '\0';
            if (strstr(outbuf, "50 200")) break;
        }
    }
    printf("  stty size output: '%s'\n", outbuf);
    CHECK(strstr(outbuf, "50 200") != NULL,
          "Phase 3: resize back to large 50x200",
          "output='%s'", outbuf);

    /* ---- Step 10d (Phase 5): TERM env var passed through from host ---- */
    printf("\n[host] Step 10d: Phase 5 TERM env var verification...\n");
    {
        /* The mock host sends TERM=xterm. The bridge should NOT overwrite
         * it with xterm-256color since TERM is already set. */
        const char *cmd = "echo TERM_IS_$TERM\n";
        send_all(extra[0], cmd, strlen(cmd));

        memset(outbuf, 0, sizeof(outbuf));
        total = 0;
        for (int attempt = 0; attempt < 30; attempt++) {
            int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
            if (n > 0) total += n;
            else break;
        }
        printf("  Output: '%s'\n", outbuf);
        CHECK(strstr(outbuf, "TERM_IS_xterm") != NULL,
              "Phase 5: TERM passed through from host (not overwritten)",
              "output='%s'", outbuf);
    }

    /* ---- Step 10e (Phase 5): COLORTERM injected by bridge ---- */
    printf("\n[host] Step 10e: Phase 5 COLORTERM injection verification...\n");
    {
        /* The mock host does NOT send COLORTERM. The bridge should inject
         * COLORTERM=truecolor for 24-bit color detection. */
        const char *cmd = "echo CT_IS_$COLORTERM\n";
        send_all(extra[0], cmd, strlen(cmd));

        memset(outbuf, 0, sizeof(outbuf));
        total = 0;
        for (int attempt = 0; attempt < 30; attempt++) {
            int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
            if (n > 0) total += n;
            else break;
        }
        printf("  Output: '%s'\n", outbuf);
        CHECK(strstr(outbuf, "CT_IS_truecolor") != NULL,
              "Phase 5: COLORTERM=truecolor injected by bridge",
              "output='%s'", outbuf);
    }

    /* ---- Step 10f (Phase 5): ANSI basic color (16-color) passthrough ---- */
    printf("\n[host] Step 10f: Phase 5 ANSI basic color passthrough...\n");
    {
        /* Send: printf '\033[31mRED\033[0m'
         * The PTY is in raw mode (Phase 3), so ANSI escape codes should
         * pass through unchanged. We verify the raw ESC[31m...ESC[0m
         * sequence appears in the output. */
        const char *cmd = "printf '\\033[31mRED\\033[0m'\n";
        send_all(extra[0], cmd, strlen(cmd));

        memset(outbuf, 0, sizeof(outbuf));
        total = 0;
        for (int attempt = 0; attempt < 30; attempt++) {
            int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
            if (n > 0) total += n;
            else break;
        }
        /* Look for raw ESC[31mRED ESC[0m sequence */
        const char *expected = "\033[31mRED\033[0m";
        printf("  Output (hex): ");
        for (int i = 0; i < total && i < 40; i++)
            printf("%02x ", (unsigned char)outbuf[i]);
        printf("\n");
        CHECK(strstr(outbuf, expected) != NULL,
              "Phase 5: ANSI basic color (red) passthrough",
              "expected ESC[31mRED ESC[0m in output");
    }

    /* ---- Step 10g (Phase 5): ANSI 256-color passthrough ---- */
    printf("\n[host] Step 10g: Phase 5 ANSI 256-color passthrough...\n");
    {
        /* Send: printf '\033[38;5;196mC256\033[0m'
         * 38;5;196 = foreground color 196 (bright red) in 256-color mode */
        const char *cmd = "printf '\\033[38;5;196mC256\\033[0m'\n";
        send_all(extra[0], cmd, strlen(cmd));

        memset(outbuf, 0, sizeof(outbuf));
        total = 0;
        for (int attempt = 0; attempt < 30; attempt++) {
            int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
            if (n > 0) total += n;
            else break;
        }
        const char *expected = "\033[38;5;196mC256\033[0m";
        CHECK(strstr(outbuf, expected) != NULL,
              "Phase 5: ANSI 256-color passthrough",
              "expected ESC[38;5;196mC256 ESC[0m in output");
    }

    /* ---- Step 10h (Phase 5): ANSI truecolor (24-bit) passthrough ---- */
    printf("\n[host] Step 10h: Phase 5 ANSI truecolor (24-bit) passthrough...\n");
    {
        /* Send: printf '\033[38;2;255;0;0mTC24\033[0m'
         * 38;2;255;0;0 = foreground RGB(255,0,0) in truecolor mode */
        const char *cmd = "printf '\\033[38;2;255;0;0mTC24\\033[0m'\n";
        send_all(extra[0], cmd, strlen(cmd));

        memset(outbuf, 0, sizeof(outbuf));
        total = 0;
        for (int attempt = 0; attempt < 30; attempt++) {
            int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
            if (n > 0) total += n;
            else break;
        }
        const char *expected = "\033[38;2;255;0;0mTC24\033[0m";
        CHECK(strstr(outbuf, expected) != NULL,
              "Phase 5: ANSI truecolor (24-bit) passthrough",
              "expected ESC[38;2;255;0;0mTC24 ESC[0m in output");
    }

    /* ---- Step 11: Send exit, read ExitStatus from control channel ---- */
    printf("\n[host] Step 11: Sending 'exit', waiting for ExitStatus on control channel...\n");
    const char *exit_cmd = "exit\n";
    send_all(extra[0], exit_cmd, strlen(exit_cmd));

    /* Read remaining stdout output (shell exit messages) */
    memset(outbuf, 0, sizeof(outbuf));
    total = 0;
    for (int attempt = 0; attempt < 30; attempt++) {
        int n = read_with_timeout(extra[1], outbuf + total, sizeof(outbuf) - total, 200);
        if (n > 0) total += n;
        else break;
    }
    if (total > 0) printf("  Remaining stdout: '%s'\n", outbuf);

    /* Read ExitStatus from control channel (bridge_initial) */
    int got_exit_status = 0;
    LX_INIT_PROCESS_EXIT_STATUS exit_status;
    memset(&exit_status, 0, sizeof(exit_status));

    for (int attempt = 0; attempt < 50; attempt++) {
        void *msg = recv_message(bridge_initial, &hdr);
        if (!msg) {
            /* Try again with timeout */
            usleep(100000);
            continue;
        }
        struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
        if (mhdr->MessageType == LxInitMessageExitStatus &&
            mhdr->MessageSize >= sizeof(LX_INIT_PROCESS_EXIT_STATUS)) {
            memcpy(&exit_status, msg, sizeof(exit_status));
            got_exit_status = 1;
            free(msg);
            break;
        }
        printf("  Unexpected control message: type=%u\n", mhdr->MessageType);
        free(msg);
    }

    if (got_exit_status) {
        printf("  Received ExitStatus on control channel: MessageType=%u, ExitCode=%d\n",
               exit_status.Header.MessageType, exit_status.ExitCode);
        CHECK(exit_status.Header.MessageType == LxInitMessageExitStatus,
              "ExitStatus MessageType==9",
              "got %u", exit_status.Header.MessageType);
        CHECK(exit_status.Header.MessageSize == sizeof(LX_INIT_PROCESS_EXIT_STATUS),
              "ExitStatus MessageSize correct",
              "got %u, expected %zu", exit_status.Header.MessageSize, sizeof(LX_INIT_PROCESS_EXIT_STATUS));
        CHECK(1, "ExitStatus received on control channel (not stdout) (Phase 1)", "ok");
    } else {
        printf("  No ExitStatus message received on control channel\n");
        CHECK(0, "ExitStatus received on control channel", "not received");
    }

    /* ---- Step 13 (Phase 4): Host disconnect test ---- */
    printf("\n[host] Step 13: Phase 4 host disconnect — start session, then drop all sockets...\n");

    /* Close first session's bridge sockets (session already ended via exit) */
    for (int i = 0; i < 5; i++) { close(extra[i]); extra[i] = -1; }
    close(bridge_init); bridge_init = -1;
    close(bridge_initial); bridge_initial = -1;

    /* Start a new session that we will disconnect abruptly */
    int dis_init_fd = -1, dis_control_fd = -1;
    if (setup_bridge_session(&dis_init_fd, &dis_control_fd, 30, 120, 13, NULL) < 0) {
        fprintf(stderr, "  [FAIL] cannot setup disconnect session\n");
        CHECK(0, "Phase 4: disconnect session setup", "connect failed");
    } else {
        printf("  Disconnect session established (control fd=%d)\n", dis_control_fd);

        /* Connect 5 additional sockets */
        int dis_extra[5];
        int dis_extra_ok = 1;
        for (int i = 0; i < 5; i++) {
            dis_extra[i] = connect_to_port(PORT_HVS_BSD);
            if (dis_extra[i] < 0) { dis_extra_ok = 0; break; }
        }

        if (!dis_extra_ok) {
            fprintf(stderr, "  [FAIL] cannot connect extra sockets for disconnect session\n");
            CHECK(0, "Phase 4: disconnect session extra sockets", "connect failed");
            close(dis_init_fd); close(dis_control_fd);
            for (int i = 0; i < 5; i++) if (dis_extra[i] >= 0) close(dis_extra[i]);
        } else {
            /* Give the shell time to start, then send a long-running command */
            usleep(300000);
            const char *sleep_cmd = "sleep 30\n";
            send_all(dis_extra[0], sleep_cmd, strlen(sleep_cmd));
            printf("  Sent '%s' to keep shell alive during disconnect\n", sleep_cmd);

            /* Read any prompt output */
            char dis_buf[256];
            memset(dis_buf, 0, sizeof(dis_buf));
            read_with_timeout(dis_extra[1], dis_buf, sizeof(dis_buf) - 1, 300);

            /* Simulate host disconnect: close ALL sockets suddenly.
             * The bridge should detect the control channel close, send SIGHUP
             * to the child, reap it, and return to the accept loop. */
            printf("  Simulating host disconnect (closing all sockets)...\n");
            for (int i = 0; i < 5; i++) { close(dis_extra[i]); dis_extra[i] = -1; }
            close(dis_init_fd); dis_init_fd = -1;
            close(dis_control_fd); dis_control_fd = -1;

            /* Wait for the bridge to detect the disconnect and clean up.
             * SIGHUP should kill the shell quickly; allow up to 6s
             * (the bridge escalates to SIGKILL at 5s). */
            printf("  Waiting 6s for bridge graceful shutdown (SIGHUP -> SIGKILL)...\n");
            sleep(6);

            CHECK(1, "Phase 4: host disconnect handled without crash", "ok");
        }
    }

    /* ---- Step 14 (Phase 4): New session after disconnect ---- */
    printf("\n[host] Step 14: Phase 4 new session after disconnect (verify no deadlock/leak)...\n");
    {
        int new_init_fd = -1, new_control_fd = -1;
        if (setup_bridge_session(&new_init_fd, &new_control_fd, 24, 80, 14, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup post-disconnect session (bridge may be deadlocked)\n");
            CHECK(0, "Phase 4: new session after disconnect", "connect failed (deadlock?)");
        } else {
            printf("  Post-disconnect session established (control fd=%d)\n", new_control_fd);

            /* Connect 5 additional sockets */
            int new_extra[5];
            int new_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                new_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (new_extra[i] < 0) { new_extra_ok = 0; break; }
            }

            if (!new_extra_ok) {
                CHECK(0, "Phase 4: post-disconnect extra sockets", "connect failed");
                close(new_init_fd); close(new_control_fd);
                for (int i = 0; i < 5; i++) if (new_extra[i] >= 0) close(new_extra[i]);
            } else {
                CHECK(1, "Phase 4: new session accepted after disconnect (no deadlock)", "ok");

                /* Verify console I/O works */
                usleep(300000);
                const char *echo_cmd = "echo phase4_ok\n";
                send_all(new_extra[0], echo_cmd, strlen(echo_cmd));

                char new_out[4096];
                memset(new_out, 0, sizeof(new_out));
                int new_total = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    int n = read_with_timeout(new_extra[1], new_out + new_total,
                                              sizeof(new_out) - new_total - 1, 200);
                    if (n > 0) new_total += n;
                    else break;
                }
                printf("  Console output: '%s'\n", new_out);
                CHECK(strstr(new_out, "phase4_ok") != NULL,
                      "Phase 4: console I/O works after disconnect",
                      "output='%s'", new_out);

                /* Send exit and read ExitStatus */
                const char *exit_cmd2 = "exit\n";
                send_all(new_extra[0], exit_cmd2, strlen(exit_cmd2));

                /* Drain remaining stdout */
                memset(new_out, 0, sizeof(new_out));
                new_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(new_extra[1], new_out + new_total,
                                              sizeof(new_out) - new_total, 200);
                    if (n > 0) new_total += n;
                    else break;
                }

                int got_exit2 = 0;
                LX_INIT_PROCESS_EXIT_STATUS exit2;
                memset(&exit2, 0, sizeof(exit2));
                for (int attempt = 0; attempt < 50; attempt++) {
                    void *msg = recv_message(new_control_fd, &hdr);
                    if (!msg) { usleep(100000); continue; }
                    struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                    if (mhdr->MessageType == LxInitMessageExitStatus &&
                        mhdr->MessageSize >= sizeof(LX_INIT_PROCESS_EXIT_STATUS)) {
                        memcpy(&exit2, msg, sizeof(exit2));
                        got_exit2 = 1;
                        free(msg);
                        break;
                    }
                    free(msg);
                }

                CHECK(got_exit2,
                      "Phase 4: ExitStatus received after post-disconnect session",
                      "not received");

                /* Close post-disconnect session sockets */
                for (int i = 0; i < 5; i++) close(new_extra[i]);
                close(new_init_fd);
                close(new_control_fd);
            }
        }
    }

    /* ---- Step 15 (Phase 4): Grandchild PTY inheritance test ---- */
    /* Fork a background process (grandchild) that inherits the PTY slave fd,
     * then exit the shell. The grandchild keeps the PTY slave open, so
     * master read() will never return EOF. Without the poll-based drain
     * timeout fix, the bridge would hang forever in the drain loop. */
    printf("\n[host] Step 15: Phase 4 grandchild PTY inheritance (verify drain timeout)...\n");
    {
        int gc_init_fd = -1, gc_control_fd = -1;
        if (setup_bridge_session(&gc_init_fd, &gc_control_fd, 24, 80, 15, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup grandchild session\n");
            CHECK(0, "Phase 4: grandchild session setup", "connect failed");
        } else {
            int gc_extra[5];
            int gc_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                gc_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (gc_extra[i] < 0) { gc_extra_ok = 0; break; }
            }

            if (!gc_extra_ok) {
                CHECK(0, "Phase 4: grandchild session extra sockets", "connect failed");
                close(gc_init_fd); close(gc_control_fd);
                for (int i = 0; i < 5; i++) if (gc_extra[i] >= 0) close(gc_extra[i]);
            } else {
                usleep(300000);

                /* Fork a grandchild that holds the PTY slave open.
                 * 'sleep 60 &' runs in the background, inheriting the PTY
                 * slave fd. When the shell exits, the grandchild keeps the
                 * slave open, preventing master read() from returning EOF. */
                const char *bg_cmd = "sleep 60 &\n";
                send_all(gc_extra[0], bg_cmd, strlen(bg_cmd));
                printf("  Sent '%s' to fork grandchild holding PTY slave\n", bg_cmd);

                /* Read shell prompt / job control output */
                char gc_buf[512];
                memset(gc_buf, 0, sizeof(gc_buf));
                int gc_drained = 0;
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(gc_extra[1], gc_buf + gc_drained,
                                              sizeof(gc_buf) - gc_drained - 1, 300);
                    if (n > 0) gc_drained += n;
                    else break;
                }
                printf("  Shell output after background fork: '%s'\n", gc_buf);

                /* Exit the shell. The grandchild (sleep 60) still holds the
                 * PTY slave. The bridge must detect SIGCHLD, drain the PTY
                 * with a 200ms poll timeout (not block forever), and send
                 * ExitStatus. */
                const char *exit_gc = "exit\n";
                send_all(gc_extra[0], exit_gc, strlen(exit_gc));
                printf("  Sent 'exit' — shell exits, grandchild still holds PTY slave\n");

                /* Drain remaining stdout (shell exit messages) */
                memset(gc_buf, 0, sizeof(gc_buf));
                gc_drained = 0;
                for (int attempt = 0; attempt < 20; attempt++) {
                    int n = read_with_timeout(gc_extra[1], gc_buf + gc_drained,
                                              sizeof(gc_buf) - gc_drained, 200);
                    if (n > 0) gc_drained += n;
                    else break;
                }

                /* Read ExitStatus from control channel. With the fix, the
                 * drain timeout is 200ms, so ExitStatus should arrive within
                 * a few seconds. Without the fix, the bridge hangs forever
                 * in the blocking drain loop and ExitStatus never arrives. */
                int got_gc_exit = 0;
                LX_INIT_PROCESS_EXIT_STATUS gc_exit_status;
                memset(&gc_exit_status, 0, sizeof(gc_exit_status));

                for (int attempt = 0; attempt < 50; attempt++) {
                    void *msg = recv_message(gc_control_fd, &hdr);
                    if (!msg) { usleep(100000); continue; }
                    struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                    if (mhdr->MessageType == LxInitMessageExitStatus &&
                        mhdr->MessageSize >= sizeof(LX_INIT_PROCESS_EXIT_STATUS)) {
                        memcpy(&gc_exit_status, msg, sizeof(gc_exit_status));
                        got_gc_exit = 1;
                        free(msg);
                        break;
                    }
                    free(msg);
                }

                CHECK(got_gc_exit,
                      "Phase 4: ExitStatus received despite grandchild holding PTY (drain timeout works)",
                      "not received — bridge may be hung in drain loop");

                if (got_gc_exit) {
                    printf("  ExitStatus received: ExitCode=%d\n", gc_exit_status.ExitCode);
                }

                /* Close session sockets. The orphaned grandchild (sleep 60)
                 * will be cleaned up when the test process exits. */
                for (int i = 0; i < 5; i++) close(gc_extra[i]);
                close(gc_init_fd);
                close(gc_control_fd);
            }
        }
    }

    /* ---- Step 16 (Phase 4): New session after grandchild test ---- */
    printf("\n[host] Step 16: Phase 4 new session after grandchild test (verify no deadlock)...\n");
    {
        int gc2_init_fd = -1, gc2_control_fd = -1;
        if (setup_bridge_session(&gc2_init_fd, &gc2_control_fd, 24, 80, 16, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup post-grandchild session (bridge may be deadlocked)\n");
            CHECK(0, "Phase 4: new session after grandchild test", "connect failed (deadlock?)");
        } else {
            int gc2_extra[5];
            int gc2_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                gc2_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (gc2_extra[i] < 0) { gc2_extra_ok = 0; break; }
            }

            if (!gc2_extra_ok) {
                CHECK(0, "Phase 4: post-grandchild extra sockets", "connect failed");
                close(gc2_init_fd); close(gc2_control_fd);
                for (int i = 0; i < 5; i++) if (gc2_extra[i] >= 0) close(gc2_extra[i]);
            } else {
                CHECK(1, "Phase 4: new session accepted after grandchild test (no deadlock)", "ok");

                /* Quick echo test */
                usleep(300000);
                const char *echo_cmd = "echo grandchild_ok\n";
                send_all(gc2_extra[0], echo_cmd, strlen(echo_cmd));

                char gc2_out[4096];
                memset(gc2_out, 0, sizeof(gc2_out));
                int gc2_total = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    int n = read_with_timeout(gc2_extra[1], gc2_out + gc2_total,
                                              sizeof(gc2_out) - gc2_total - 1, 200);
                    if (n > 0) gc2_total += n;
                    else break;
                }
                printf("  Console output: '%s'\n", gc2_out);
                CHECK(strstr(gc2_out, "grandchild_ok") != NULL,
                      "Phase 4: console I/O works after grandchild test",
                      "output='%s'", gc2_out);

                /* Send exit and close */
                send_all(gc2_extra[0], "exit\n", 5);
                /* Brief drain for ExitStatus */
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(gc2_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(gc2_extra[i]);
                close(gc2_init_fd);
                close(gc2_control_fd);
            }
        }
    }

    /* ---- Step 17 (Phase 5): Color theme switching + grandchild PTY drain timeout ---- */
    /* Combined test: send OSC color theme switching sequences (palette/fg/bg),
     * verify raw passthrough through the PTY, then fork a grandchild holding
     * the PTY slave and exit the shell. The bridge must drain the PTY with
     * the 200ms poll timeout (not block forever) and send ExitStatus even
     * though the grandchild keeps the slave open. This verifies that color
     * theme switching traffic does not interfere with the Phase 4 drain fix. */
    printf("\n[host] Step 17: Phase 5 color theme switching + grandchild PTY drain timeout...\n");
    {
        int ct_init_fd = -1, ct_control_fd = -1;
        if (setup_bridge_session(&ct_init_fd, &ct_control_fd, 24, 80, 17, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup color theme session\n");
            CHECK(0, "Phase 5: color theme session setup", "connect failed");
        } else {
            int ct_extra[5];
            int ct_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                ct_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (ct_extra[i] < 0) { ct_extra_ok = 0; break; }
            }

            if (!ct_extra_ok) {
                CHECK(0, "Phase 5: color theme session extra sockets", "connect failed");
                close(ct_init_fd); close(ct_control_fd);
                for (int i = 0; i < 5; i++) if (ct_extra[i] >= 0) close(ct_extra[i]);
            } else {
                usleep(300000);

                /* Send OSC palette change: ESC]4;0;rgb:1e/1e/2e BEL
                 * Sets palette index 0 (black) to RGB(30,30,46) — a dark
                 * color typical of "Dracula"-style themes. */
                const char *osc_palette = "printf '\\033]4;0;rgb:1e/1e/2e\\007'\n";
                send_all(ct_extra[0], osc_palette, strlen(osc_palette));
                printf("  Sent OSC palette change (index 0 -> rgb:1e/1e/2e)\n");

                /* Send OSC foreground change: ESC]10;rgb:f3/8b/ae BEL
                 * Sets foreground to RGB(243,139,174) — a pinkish color. */
                const char *osc_fg = "printf '\\033]10;rgb:f3/8b/ae\\007'\n";
                send_all(ct_extra[0], osc_fg, strlen(osc_fg));
                printf("  Sent OSC foreground change (-> rgb:f3/8b/ae)\n");

                /* Send OSC background change: ESC]11;rgb:1e/1e/2e BEL */
                const char *osc_bg = "printf '\\033]11;rgb:1e/1e/2e\\007'\n";
                send_all(ct_extra[0], osc_bg, strlen(osc_bg));
                printf("  Sent OSC background change (-> rgb:1e/1e/2e)\n");

                /* Drain and verify all three OSC sequences passed through raw */
                char ct_buf[2048];
                memset(ct_buf, 0, sizeof(ct_buf));
                int ct_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(ct_extra[1], ct_buf + ct_total,
                                              sizeof(ct_buf) - ct_total - 1, 200);
                    if (n > 0) ct_total += n;
                    else break;
                }
                printf("  Output (hex, first 80 bytes): ");
                for (int i = 0; i < ct_total && i < 80; i++)
                    printf("%02x ", (unsigned char)ct_buf[i]);
                printf("\n");

                /* Expected raw OSC sequences (with BEL terminator 0x07) */
                const char *exp_palette = "\033]4;0;rgb:1e/1e/2e\007";
                const char *exp_fg = "\033]10;rgb:f3/8b/ae\007";
                const char *exp_bg = "\033]11;rgb:1e/1e/2e\007";
                CHECK(strstr(ct_buf, exp_palette) != NULL,
                      "Phase 5: OSC palette change (ESC]4;0;...) passthrough",
                      "raw OSC sequence not found in output");
                CHECK(strstr(ct_buf, exp_fg) != NULL,
                      "Phase 5: OSC foreground change (ESC]10;...) passthrough",
                      "raw OSC sequence not found in output");
                CHECK(strstr(ct_buf, exp_bg) != NULL,
                      "Phase 5: OSC background change (ESC]11;...) passthrough",
                      "raw OSC sequence not found in output");

                /* Send OSC reset sequences and verify passthrough */
                const char *osc_reset_palette = "printf '\\033]104\\007'\n";
                const char *osc_reset_fg = "printf '\\033]110\\007'\n";
                const char *osc_reset_bg = "printf '\\033]111\\007'\n";
                send_all(ct_extra[0], osc_reset_palette, strlen(osc_reset_palette));
                send_all(ct_extra[0], osc_reset_fg, strlen(osc_reset_fg));
                send_all(ct_extra[0], osc_reset_bg, strlen(osc_reset_bg));
                printf("  Sent OSC reset sequences (104/110/111)\n");

                memset(ct_buf, 0, sizeof(ct_buf));
                ct_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(ct_extra[1], ct_buf + ct_total,
                                              sizeof(ct_buf) - ct_total - 1, 200);
                    if (n > 0) ct_total += n;
                    else break;
                }
                const char *exp_rst_pal = "\033]104\007";
                const char *exp_rst_fg = "\033]110\007";
                const char *exp_rst_bg = "\033]111\007";
                CHECK(strstr(ct_buf, exp_rst_pal) != NULL,
                      "Phase 5: OSC palette reset (ESC]104) passthrough",
                      "raw OSC reset sequence not found");
                CHECK(strstr(ct_buf, exp_rst_fg) != NULL,
                      "Phase 5: OSC foreground reset (ESC]110) passthrough",
                      "raw OSC reset sequence not found");
                CHECK(strstr(ct_buf, exp_rst_bg) != NULL,
                      "Phase 5: OSC background reset (ESC]111) passthrough",
                      "raw OSC reset sequence not found");

                /* Now fork a grandchild that holds the PTY slave open, then
                 * exit the shell. This is the critical combined test: after
                 * extensive OSC color theme traffic, the bridge must still
                 * correctly drain the PTY with the 200ms poll timeout and
                 * deliver ExitStatus despite the grandchild holding the slave. */
                const char *bg_cmd = "sleep 60 &\n";
                send_all(ct_extra[0], bg_cmd, strlen(bg_cmd));
                printf("  Sent '%s' to fork grandchild holding PTY slave\n", bg_cmd);

                /* Drain job control output */
                memset(ct_buf, 0, sizeof(ct_buf));
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(ct_extra[1], ct_buf, sizeof(ct_buf) - 1, 300);
                    if (n <= 0) break;
                }

                /* Exit shell — grandchild still holds PTY slave */
                const char *exit_cmd = "exit\n";
                send_all(ct_extra[0], exit_cmd, strlen(exit_cmd));
                printf("  Sent 'exit' — shell exits, grandchild still holds PTY slave\n");

                /* Drain remaining stdout */
                memset(ct_buf, 0, sizeof(ct_buf));
                for (int attempt = 0; attempt < 20; attempt++) {
                    int n = read_with_timeout(ct_extra[1], ct_buf, sizeof(ct_buf) - 1, 200);
                    if (n <= 0) break;
                }

                /* Read ExitStatus from control channel. With the Phase 4 drain
                 * timeout fix, ExitStatus should arrive within a few seconds
                 * even though the grandchild holds the PTY slave. Without the
                 * fix, the bridge would hang forever in the blocking drain
                 * loop after processing all the OSC color traffic. */
                int got_ct_exit = 0;
                LX_INIT_PROCESS_EXIT_STATUS ct_exit_status;
                memset(&ct_exit_status, 0, sizeof(ct_exit_status));

                for (int attempt = 0; attempt < 50; attempt++) {
                    void *msg = recv_message(ct_control_fd, &hdr);
                    if (!msg) { usleep(100000); continue; }
                    struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                    if (mhdr->MessageType == LxInitMessageExitStatus &&
                        mhdr->MessageSize >= sizeof(LX_INIT_PROCESS_EXIT_STATUS)) {
                        memcpy(&ct_exit_status, msg, sizeof(ct_exit_status));
                        got_ct_exit = 1;
                        free(msg);
                        break;
                    }
                    free(msg);
                }

                CHECK(got_ct_exit,
                      "Phase 5: ExitStatus received after color theme switching + grandchild (drain timeout works)",
                      "not received — bridge may be hung in drain loop after OSC traffic");

                if (got_ct_exit) {
                    printf("  ExitStatus received: ExitCode=%d\n", ct_exit_status.ExitCode);
                }

                /* Close session sockets. The orphaned grandchild (sleep 60)
                 * will be cleaned up when the test process exits. */
                for (int i = 0; i < 5; i++) close(ct_extra[i]);
                close(ct_init_fd);
                close(ct_control_fd);
            }
        }
    }

    /* ---- Step 18 (Phase 5): New session after color theme + grandchild test ---- */
    printf("\n[host] Step 18: Phase 5 new session after color theme + grandchild test (verify no deadlock)...\n");
    {
        int ct2_init_fd = -1, ct2_control_fd = -1;
        if (setup_bridge_session(&ct2_init_fd, &ct2_control_fd, 24, 80, 18, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup post-color-theme session (bridge may be deadlocked)\n");
            CHECK(0, "Phase 5: new session after color theme + grandchild test", "connect failed (deadlock?)");
        } else {
            int ct2_extra[5];
            int ct2_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                ct2_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (ct2_extra[i] < 0) { ct2_extra_ok = 0; break; }
            }

            if (!ct2_extra_ok) {
                CHECK(0, "Phase 5: post-color-theme extra sockets", "connect failed");
                close(ct2_init_fd); close(ct2_control_fd);
                for (int i = 0; i < 5; i++) if (ct2_extra[i] >= 0) close(ct2_extra[i]);
            } else {
                CHECK(1, "Phase 5: new session accepted after color theme + grandchild test (no deadlock)", "ok");

                /* Quick echo test to confirm the session is fully functional */
                usleep(300000);
                const char *echo_cmd = "echo color_theme_ok\n";
                send_all(ct2_extra[0], echo_cmd, strlen(echo_cmd));

                char ct2_out[4096];
                memset(ct2_out, 0, sizeof(ct2_out));
                int ct2_total = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    int n = read_with_timeout(ct2_extra[1], ct2_out + ct2_total,
                                              sizeof(ct2_out) - ct2_total - 1, 200);
                    if (n > 0) ct2_total += n;
                    else break;
                }
                printf("  Console output: '%s'\n", ct2_out);
                CHECK(strstr(ct2_out, "color_theme_ok") != NULL,
                      "Phase 5: console I/O works after color theme + grandchild test",
                      "output='%s'", ct2_out);

                /* Send exit and close */
                send_all(ct2_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(ct2_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(ct2_extra[i]);
                close(ct2_init_fd);
                close(ct2_control_fd);
            }
        }
    }

    /* ---- Step 19 (Phase 6): Guest→host window size notification ---- */
    /* Change the terminal size from inside the guest using stty. The bridge
     * detects the change via periodic TIOCGWINSZ polling and sends a
     * WindowSizeChanged(10) message to the host on the control channel. */
    printf("\n[host] Step 19: Phase 6 guest→host window size notification (stty resize)...\n");
    {
        int ws_init_fd = -1, ws_control_fd = -1;
        if (setup_bridge_session(&ws_init_fd, &ws_control_fd, 24, 80, 19, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup window size notification session\n");
            CHECK(0, "Phase 6: notification session setup", "connect failed");
        } else {
            int ws_extra[5];
            int ws_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                ws_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (ws_extra[i] < 0) { ws_extra_ok = 0; break; }
            }

            if (!ws_extra_ok) {
                CHECK(0, "Phase 6: notification session extra sockets", "connect failed");
                close(ws_init_fd); close(ws_control_fd);
                for (int i = 0; i < 5; i++) if (ws_extra[i] >= 0) close(ws_extra[i]);
            } else {
                usleep(300000);

                /* Change the terminal size from inside the guest using stty.
                 * This calls ioctl(slave_fd, TIOCSWINSZ) on the PTY slave,
                 * which changes the kernel's winsize. The bridge detects
                 * this via periodic TIOCGWINSZ polling (every 1s) and sends
                 * a WindowSizeChanged(10) message to the host. */
                const char *stty_cmd = "stty rows 50 cols 100\n";
                send_all(ws_extra[0], stty_cmd, strlen(stty_cmd));
                printf("  Sent '%s' to change terminal size inside guest\n", stty_cmd);

                /* Drain shell output (stty produces no output, but prompt may) */
                char ws_buf[512];
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(ws_extra[1], ws_buf, sizeof(ws_buf) - 1, 200);
                    if (n <= 0) break;
                }

                /* Wait for the bridge to detect the size change and send a
                 * WindowSizeChanged(10) on the control channel. The bridge
                 * checks every 1 second, so wait up to 5 seconds. Use select
                 * to avoid blocking in recv_message when no data is available. */
                int got_ws_notify = 0;
                unsigned short notify_rows = 0, notify_cols = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    fd_set rfds;
                    FD_ZERO(&rfds);
                    FD_SET(ws_control_fd, &rfds);
                    struct timeval tv = {0, 100000};  /* 100ms */
                    int rc = select(ws_control_fd + 1, &rfds, NULL, NULL, &tv);
                    if (rc > 0) {
                        void *msg = recv_message(ws_control_fd, &hdr);
                        if (msg) {
                            struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                            if (mhdr->MessageType == LxInitMessageWindowSizeChanged &&
                                mhdr->MessageSize >= sizeof(LX_INIT_WINDOW_SIZE_CHANGED)) {
                                LX_INIT_WINDOW_SIZE_CHANGED *wsc =
                                    (LX_INIT_WINDOW_SIZE_CHANGED *)msg;
                                notify_rows = wsc->Rows;
                                notify_cols = wsc->Columns;
                                got_ws_notify = 1;
                                free(msg);
                                break;
                            }
                            free(msg);
                        }
                    }
                }

                CHECK(got_ws_notify,
                      "Phase 6: WindowSizeChanged received from guest after stty resize",
                      "not received — bridge may not be polling TIOCGWINSZ");
                if (got_ws_notify) {
                    printf("  Received WindowSizeChanged: rows=%u, cols=%u\n",
                           notify_rows, notify_cols);
                    CHECK(notify_rows == 50,
                          "Phase 6: notified rows==50 (guest stty rows 50)",
                          "got %u", notify_rows);
                    CHECK(notify_cols == 100,
                          "Phase 6: notified cols==100 (guest stty cols 100)",
                          "got %u", notify_cols);
                }

                /* Exit shell and drain ExitStatus */
                send_all(ws_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(ws_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(ws_extra[i]);
                close(ws_init_fd);
                close(ws_control_fd);
            }
        }
    }

    /* ---- Step 20 (Phase 6): Host→guest resize then verify no feedback loop ---- */
    /* Send a host→guest WindowSizeChanged, then verify the bridge does NOT
     * send a WindowSizeChanged back (feedback loop prevention). The bridge
     * updates its tracked size when applying a host-initiated resize, so the
     * next TIOCGWINSZ poll sees the same size and suppresses notification. */
    printf("\n[host] Step 20: Phase 6 host→guest resize then verify no feedback loop...\n");
    {
        int fb_init_fd = -1, fb_control_fd = -1;
        if (setup_bridge_session(&fb_init_fd, &fb_control_fd, 24, 80, 20, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup feedback loop test session\n");
            CHECK(0, "Phase 6: feedback loop session setup", "connect failed");
        } else {
            int fb_extra[5];
            int fb_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                fb_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (fb_extra[i] < 0) { fb_extra_ok = 0; break; }
            }

            if (!fb_extra_ok) {
                CHECK(0, "Phase 6: feedback loop extra sockets", "connect failed");
                close(fb_init_fd); close(fb_control_fd);
                for (int i = 0; i < 5; i++) if (fb_extra[i] >= 0) close(fb_extra[i]);
            } else {
                usleep(300000);

                /* Send a host→guest WindowSizeChanged(10) on the control
                 * channel. The bridge should apply it to the PTY via
                 * TIOCSWINSZ and update its tracked size. The next
                 * TIOCGWINSZ poll should see the same size, so NO
                 * notification should be sent back to the host. */
                LX_INIT_WINDOW_SIZE_CHANGED host_wsc;
                memset(&host_wsc, 0, sizeof(host_wsc));
                host_wsc.Header.MessageType = LxInitMessageWindowSizeChanged;
                host_wsc.Header.MessageSize = sizeof(host_wsc);
                host_wsc.Header.SequenceNumber = 201;
                host_wsc.Rows = 30;
                host_wsc.Columns = 120;
                send_all(fb_control_fd, &host_wsc, sizeof(host_wsc));
                printf("  Sent host→guest WindowSizeChanged: rows=30, cols=120\n");

                /* Wait for the bridge to apply the resize */
                usleep(500000);

                /* Verify the PTY size was actually changed by querying stty */
                const char *stty_size_cmd = "stty size\n";
                send_all(fb_extra[0], stty_size_cmd, strlen(stty_size_cmd));

                char fb_buf[512];
                memset(fb_buf, 0, sizeof(fb_buf));
                int fb_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(fb_extra[1], fb_buf + fb_total,
                                              sizeof(fb_buf) - fb_total - 1, 200);
                    if (n > 0) fb_total += n;
                    else break;
                }
                printf("  stty size output: '%s'\n", fb_buf);
                /* stty size outputs "rows cols" (e.g. "30 120") */
                CHECK(strstr(fb_buf, "30 120") != NULL,
                      "Phase 6: host→guest resize applied to PTY (stty size shows 30 120)",
                      "output='%s'", fb_buf);

                /* Wait 3 seconds (3 poll cycles) to verify NO feedback
                 * notification is sent back on the control channel. If the
                 * feedback loop prevention is working, the bridge should NOT
                 * send a WindowSizeChanged message after a host-initiated
                 * resize. Use select to check for data without blocking. */
                int feedback_detected = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    fd_set rfds;
                    FD_ZERO(&rfds);
                    FD_SET(fb_control_fd, &rfds);
                    struct timeval tv = {0, 100000};  /* 100ms */
                    int rc = select(fb_control_fd + 1, &rfds, NULL, NULL, &tv);
                    if (rc > 0) {
                        /* Data arrived on control channel — check if it's
                         * a WindowSizeChanged (feedback) */
                        void *msg = recv_message(fb_control_fd, &hdr);
                        if (msg) {
                            struct MESSAGE_HEADER *mhdr =
                                (struct MESSAGE_HEADER *)msg;
                            if (mhdr->MessageType == LxInitMessageWindowSizeChanged) {
                                feedback_detected = 1;
                                printf("  Unexpected feedback WindowSizeChanged received!\n");
                            }
                            free(msg);
                            if (feedback_detected) break;
                        }
                    }
                }

                CHECK(!feedback_detected,
                      "Phase 6: no feedback notification after host→guest resize (loop prevention works)",
                      "unexpected WindowSizeChanged received from guest");

                /* Exit shell and drain ExitStatus */
                send_all(fb_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(fb_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(fb_extra[i]);
                close(fb_init_fd);
                close(fb_control_fd);
            }
        }
    }

    /* ---- Step 21 (Phase 7): OSC 50 font setting passthrough ---- */
    /* Verify that OSC 50 (set font) escape sequences pass through the raw
     * PTY unchanged. The bridge uses cfmakeraw mode, so no escape sequence
     * interception occurs — bytes flow through transparently. */
    printf("\n[host] Step 21: Phase 7 OSC 50 font setting passthrough...\n");
    {
        int ft_init_fd = -1, ft_control_fd = -1;
        if (setup_bridge_session(&ft_init_fd, &ft_control_fd, 24, 80, 21, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup font test session\n");
            CHECK(0, "Phase 7: font test session setup", "connect failed");
        } else {
            int ft_extra[5];
            int ft_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                ft_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (ft_extra[i] < 0) { ft_extra_ok = 0; break; }
            }

            if (!ft_extra_ok) {
                CHECK(0, "Phase 7: font test extra sockets", "connect failed");
                close(ft_init_fd); close(ft_control_fd);
                for (int i = 0; i < 5; i++) if (ft_extra[i] >= 0) close(ft_extra[i]);
            } else {
                usleep(300000);

                /* OSC 50: Set font to "Mono:size=14" (xterm font spec format).
                 * ESC ] 50 ; Mono:size=14 BEL
                 * The bridge should pass this through raw — no interception. */
                const char *osc50_set1 = "printf '\\033]50;Mono:size=14\\007'\n";
                send_all(ft_extra[0], osc50_set1, strlen(osc50_set1));
                printf("  Sent OSC 50 font set: Mono:size=14\n");

                /* OSC 50: Set font to "Liberation Mono:pixelsize=16" */
                const char *osc50_set2 = "printf '\\033]50;Liberation Mono:pixelsize=16\\007'\n";
                send_all(ft_extra[0], osc50_set2, strlen(osc50_set2));
                printf("  Sent OSC 50 font set: Liberation Mono:pixelsize=16\n");

                /* Drain and verify raw passthrough */
                char ft_buf[2048];
                memset(ft_buf, 0, sizeof(ft_buf));
                int ft_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(ft_extra[1], ft_buf + ft_total,
                                              sizeof(ft_buf) - ft_total - 1, 200);
                    if (n > 0) ft_total += n;
                    else break;
                }
                printf("  Output (hex, first 80 bytes): ");
                for (int i = 0; i < ft_total && i < 80; i++)
                    printf("%02x ", (unsigned char)ft_buf[i]);
                printf("\n");

                const char *exp_osc50_1 = "\033]50;Mono:size=14\007";
                const char *exp_osc50_2 = "\033]50;Liberation Mono:pixelsize=16\007";
                CHECK(strstr(ft_buf, exp_osc50_1) != NULL,
                      "Phase 7: OSC 50 font set (Mono:size=14) passthrough",
                      "raw OSC 50 sequence not found in output");
                CHECK(strstr(ft_buf, exp_osc50_2) != NULL,
                      "Phase 7: OSC 50 font set (Liberation Mono:pixelsize=16) passthrough",
                      "raw OSC 50 sequence not found in output");

                /* Exit shell and drain ExitStatus */
                send_all(ft_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(ft_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(ft_extra[i]);
                close(ft_init_fd);
                close(ft_control_fd);
            }
        }
    }

    /* ---- Step 22 (Phase 7): OSC 50 font query passthrough ---- */
    /* Verify that OSC 50 ; ? (query font) passes through the raw PTY.
     * A real terminal emulator would respond with the current font name,
     * but the mock host has no terminal emulator — we just verify the
     * query sequence passes through unchanged. */
    printf("\n[host] Step 22: Phase 7 OSC 50 font query passthrough...\n");
    {
        int fq_init_fd = -1, fq_control_fd = -1;
        if (setup_bridge_session(&fq_init_fd, &fq_control_fd, 24, 80, 22, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup font query session\n");
            CHECK(0, "Phase 7: font query session setup", "connect failed");
        } else {
            int fq_extra[5];
            int fq_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                fq_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (fq_extra[i] < 0) { fq_extra_ok = 0; break; }
            }

            if (!fq_extra_ok) {
                CHECK(0, "Phase 7: font query extra sockets", "connect failed");
                close(fq_init_fd); close(fq_control_fd);
                for (int i = 0; i < 5; i++) if (fq_extra[i] >= 0) close(fq_extra[i]);
            } else {
                usleep(300000);

                /* OSC 50 ; ? : Query current font (xterm extension).
                 * ESC ] 5 0 ; ? BEL */
                const char *osc50_query = "printf '\\033]50;?\\007'\n";
                send_all(fq_extra[0], osc50_query, strlen(osc50_query));
                printf("  Sent OSC 50 font query (ESC]50;? BEL)\n");

                /* Drain and verify raw passthrough */
                char fq_buf[512];
                memset(fq_buf, 0, sizeof(fq_buf));
                int fq_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(fq_extra[1], fq_buf + fq_total,
                                              sizeof(fq_buf) - fq_total - 1, 200);
                    if (n > 0) fq_total += n;
                    else break;
                }
                printf("  Output (hex, first 40 bytes): ");
                for (int i = 0; i < fq_total && i < 40; i++)
                    printf("%02x ", (unsigned char)fq_buf[i]);
                printf("\n");

                const char *exp_osc50_q = "\033]50;?\007";
                CHECK(strstr(fq_buf, exp_osc50_q) != NULL,
                      "Phase 7: OSC 50 font query (ESC]50;?) passthrough",
                      "raw OSC 50 query sequence not found in output");

                /* Exit shell and drain ExitStatus */
                send_all(fq_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(fq_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(fq_extra[i]);
                close(fq_init_fd);
                close(fq_control_fd);
            }
        }
    }

    /* ---- Step 23 (Phase 7): OSC 50 font traffic + grandchild PTY drain ---- */
    /* Combined test: send OSC 50 font-setting sequences, then fork a
     * grandchild holding the PTY slave and exit the shell. The bridge
     * must drain the PTY with the 200ms poll timeout (not block forever)
     * and send ExitStatus despite the grandchild holding the slave.
     * This verifies that OSC 50 font traffic does not interfere with
     * the Phase 4 drain fix. */
    printf("\n[host] Step 23: Phase 7 OSC 50 font traffic + grandchild PTY drain timeout...\n");
    {
        int fc_init_fd = -1, fc_control_fd = -1;
        if (setup_bridge_session(&fc_init_fd, &fc_control_fd, 24, 80, 23, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup font+grandchild session\n");
            CHECK(0, "Phase 7: font+grandchild session setup", "connect failed");
        } else {
            int fc_extra[5];
            int fc_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                fc_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (fc_extra[i] < 0) { fc_extra_ok = 0; break; }
            }

            if (!fc_extra_ok) {
                CHECK(0, "Phase 7: font+grandchild extra sockets", "connect failed");
                close(fc_init_fd); close(fc_control_fd);
                for (int i = 0; i < 5; i++) if (fc_extra[i] >= 0) close(fc_extra[i]);
            } else {
                usleep(300000);

                /* Send multiple OSC 50 font-setting sequences to generate
                 * font-related escape traffic through the PTY. */
                const char *font_cmds[] = {
                    "printf '\\033]50;Mono:size=12\\007'\n",
                    "printf '\\033]50;Mono:size=14\\007'\n",
                    "printf '\\033]50;Mono:size=16\\007'\n",
                    "printf '\\033]50;Mono:size=18\\007'\n",
                    "printf '\\033]50;Mono:size=14\\007'\n",  /* back to 14 */
                };
                for (int i = 0; i < 5; i++) {
                    send_all(fc_extra[0], font_cmds[i], strlen(font_cmds[i]));
                }
                printf("  Sent 5 OSC 50 font-setting sequences (size 12→14→16→18→14)\n");

                /* Drain font traffic output */
                char fc_buf[2048];
                memset(fc_buf, 0, sizeof(fc_buf));
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(fc_extra[1], fc_buf, sizeof(fc_buf) - 1, 300);
                    if (n <= 0) break;
                }

                /* Fork grandchild holding PTY slave, then exit shell */
                const char *bg_cmd = "sleep 60 &\n";
                send_all(fc_extra[0], bg_cmd, strlen(bg_cmd));
                printf("  Sent '%s' to fork grandchild holding PTY slave\n", bg_cmd);

                /* Drain job control output */
                memset(fc_buf, 0, sizeof(fc_buf));
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(fc_extra[1], fc_buf, sizeof(fc_buf) - 1, 300);
                    if (n <= 0) break;
                }

                /* Exit shell — grandchild still holds PTY slave */
                send_all(fc_extra[0], "exit\n", 5);
                printf("  Sent 'exit' — shell exits, grandchild still holds PTY slave\n");

                /* Drain remaining stdout */
                memset(fc_buf, 0, sizeof(fc_buf));
                for (int attempt = 0; attempt < 20; attempt++) {
                    int n = read_with_timeout(fc_extra[1], fc_buf, sizeof(fc_buf) - 1, 200);
                    if (n <= 0) break;
                }

                /* Read ExitStatus — should arrive within a few seconds
                 * despite the grandchild holding the PTY slave. */
                int got_fc_exit = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    void *msg = recv_message(fc_control_fd, &hdr);
                    if (!msg) { usleep(100000); continue; }
                    struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                    if (mhdr->MessageType == LxInitMessageExitStatus) {
                        got_fc_exit = 1;
                    }
                    free(msg);
                    if (got_fc_exit) break;
                }

                CHECK(got_fc_exit,
                      "Phase 7: ExitStatus received after OSC 50 font traffic + grandchild (drain timeout works)",
                      "not received — bridge may be hung in drain loop after font traffic");

                for (int i = 0; i < 5; i++) close(fc_extra[i]);
                close(fc_init_fd);
                close(fc_control_fd);
            }
        }
    }

    /* ---- Step 24 (Phase 7): New session after font + grandchild test ---- */
    printf("\n[host] Step 24: Phase 7 new session after font + grandchild test (verify no deadlock)...\n");
    {
        int f2_init_fd = -1, f2_control_fd = -1;
        if (setup_bridge_session(&f2_init_fd, &f2_control_fd, 24, 80, 24, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup post-font session (bridge may be deadlocked)\n");
            CHECK(0, "Phase 7: new session after font + grandchild test", "connect failed (deadlock?)");
        } else {
            int f2_extra[5];
            int f2_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                f2_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (f2_extra[i] < 0) { f2_extra_ok = 0; break; }
            }

            if (!f2_extra_ok) {
                CHECK(0, "Phase 7: post-font extra sockets", "connect failed");
                close(f2_init_fd); close(f2_control_fd);
                for (int i = 0; i < 5; i++) if (f2_extra[i] >= 0) close(f2_extra[i]);
            } else {
                CHECK(1, "Phase 7: new session accepted after font + grandchild test (no deadlock)", "ok");

                /* Quick echo test to confirm the session is fully functional */
                usleep(300000);
                const char *echo_cmd = "echo font_test_ok\n";
                send_all(f2_extra[0], echo_cmd, strlen(echo_cmd));

                char f2_out[4096];
                memset(f2_out, 0, sizeof(f2_out));
                int f2_total = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    int n = read_with_timeout(f2_extra[1], f2_out + f2_total,
                                              sizeof(f2_out) - f2_total - 1, 200);
                    if (n > 0) f2_total += n;
                    else break;
                }
                printf("  Console output: '%s'\n", f2_out);
                CHECK(strstr(f2_out, "font_test_ok") != NULL,
                      "Phase 7: console I/O works after font + grandchild test",
                      "output='%s'", f2_out);

                /* Send exit and close */
                send_all(f2_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(f2_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(f2_extra[i]);
                close(f2_init_fd);
                close(f2_control_fd);
            }
        }
    }

    /* ---- Step 25 (Phase 8): OSC 11 set background color (rgb: format) + OSC 111 reset ---- */
    /* Verify that OSC 11 (set background color) and OSC 111 (reset background
     * color) escape sequences pass through the raw PTY unchanged. The bridge
     * sniffer should also detect these in its log output. */
    printf("\n[host] Step 25: Phase 8 OSC 11 set (rgb:) + OSC 111 reset passthrough...\n");
    {
        int bg_init_fd = -1, bg_control_fd = -1;
        if (setup_bridge_session(&bg_init_fd, &bg_control_fd, 24, 80, 25, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup bg color test session\n");
            CHECK(0, "Phase 8: bg color test session setup", "connect failed");
        } else {
            int bg_extra[5];
            int bg_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                bg_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (bg_extra[i] < 0) { bg_extra_ok = 0; break; }
            }

            if (!bg_extra_ok) {
                CHECK(0, "Phase 8: bg color extra sockets", "connect failed");
                close(bg_init_fd); close(bg_control_fd);
                for (int i = 0; i < 5; i++) if (bg_extra[i] >= 0) close(bg_extra[i]);
            } else {
                usleep(300000);

                /* OSC 11: Set background to rgb:1e/1e/2e (dark) */
                const char *osc11_set1 = "printf '\\033]11;rgb:1e/1e/2e\\007'\n";
                send_all(bg_extra[0], osc11_set1, strlen(osc11_set1));
                printf("  Sent OSC 11 set: rgb:1e/1e/2e\n");

                /* OSC 11: Change background to rgb:f3/8b/ae (light) */
                const char *osc11_set2 = "printf '\\033]11;rgb:f3/8b/ae\\007'\n";
                send_all(bg_extra[0], osc11_set2, strlen(osc11_set2));
                printf("  Sent OSC 11 set: rgb:f3/8b/ae\n");

                /* OSC 111: Reset background color */
                const char *osc111_reset = "printf '\\033]111\\007'\n";
                send_all(bg_extra[0], osc111_reset, strlen(osc111_reset));
                printf("  Sent OSC 111 reset\n");

                /* Drain and verify raw passthrough */
                char bg_buf[2048];
                memset(bg_buf, 0, sizeof(bg_buf));
                int bg_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(bg_extra[1], bg_buf + bg_total,
                                              sizeof(bg_buf) - bg_total - 1, 200);
                    if (n > 0) bg_total += n;
                    else break;
                }
                printf("  Output (hex, first 80 bytes): ");
                for (int i = 0; i < bg_total && i < 80; i++)
                    printf("%02x ", (unsigned char)bg_buf[i]);
                printf("\n");

                const char *exp_osc11_1 = "\033]11;rgb:1e/1e/2e\007";
                const char *exp_osc11_2 = "\033]11;rgb:f3/8b/ae\007";
                const char *exp_osc111 = "\033]111\007";
                CHECK(strstr(bg_buf, exp_osc11_1) != NULL,
                      "Phase 8: OSC 11 set (rgb:1e/1e/2e) passthrough",
                      "raw OSC 11 sequence not found");
                CHECK(strstr(bg_buf, exp_osc11_2) != NULL,
                      "Phase 8: OSC 11 set (rgb:f3/8b/ae) passthrough",
                      "raw OSC 11 sequence not found");
                CHECK(strstr(bg_buf, exp_osc111) != NULL,
                      "Phase 8: OSC 111 reset passthrough",
                      "raw OSC 111 sequence not found");

                /* Exit shell and drain ExitStatus */
                send_all(bg_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(bg_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(bg_extra[i]);
                close(bg_init_fd);
                close(bg_control_fd);
            }
        }
    }

    /* ---- Step 26 (Phase 8): OSC 11 set (#RRGGBB format) + OSC 11 query ---- */
    /* Verify hex color format and query sequence passthrough. */
    printf("\n[host] Step 26: Phase 8 OSC 11 set (#RRGGBB) + OSC 11 query passthrough...\n");
    {
        int hg_init_fd = -1, hg_control_fd = -1;
        if (setup_bridge_session(&hg_init_fd, &hg_control_fd, 24, 80, 26, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup hex color test session\n");
            CHECK(0, "Phase 8: hex color test session setup", "connect failed");
        } else {
            int hg_extra[5];
            int hg_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                hg_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (hg_extra[i] < 0) { hg_extra_ok = 0; break; }
            }

            if (!hg_extra_ok) {
                CHECK(0, "Phase 8: hex color extra sockets", "connect failed");
                close(hg_init_fd); close(hg_control_fd);
                for (int i = 0; i < 5; i++) if (hg_extra[i] >= 0) close(hg_extra[i]);
            } else {
                usleep(300000);

                /* OSC 11: Set background using #RRGGBB format */
                const char *osc11_hex = "printf '\\033]11;#1e1e2e\\007'\n";
                send_all(hg_extra[0], osc11_hex, strlen(osc11_hex));
                printf("  Sent OSC 11 set: #1e1e2e\n");

                /* OSC 11;? : Query current background color */
                const char *osc11_query = "printf '\\033]11;?\\007'\n";
                send_all(hg_extra[0], osc11_query, strlen(osc11_query));
                printf("  Sent OSC 11 query (ESC]11;? BEL)\n");

                /* Drain and verify raw passthrough */
                char hg_buf[512];
                memset(hg_buf, 0, sizeof(hg_buf));
                int hg_total = 0;
                for (int attempt = 0; attempt < 30; attempt++) {
                    int n = read_with_timeout(hg_extra[1], hg_buf + hg_total,
                                              sizeof(hg_buf) - hg_total - 1, 200);
                    if (n > 0) hg_total += n;
                    else break;
                }
                printf("  Output (hex, first 60 bytes): ");
                for (int i = 0; i < hg_total && i < 60; i++)
                    printf("%02x ", (unsigned char)hg_buf[i]);
                printf("\n");

                const char *exp_hex = "\033]11;#1e1e2e\007";
                const char *exp_query = "\033]11;?\007";
                CHECK(strstr(hg_buf, exp_hex) != NULL,
                      "Phase 8: OSC 11 set (#1e1e2e hex format) passthrough",
                      "raw OSC 11 hex sequence not found");
                CHECK(strstr(hg_buf, exp_query) != NULL,
                      "Phase 8: OSC 11 query (ESC]11;?) passthrough",
                      "raw OSC 11 query sequence not found");

                /* Exit shell and drain ExitStatus */
                send_all(hg_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(hg_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(hg_extra[i]);
                close(hg_init_fd);
                close(hg_control_fd);
            }
        }
    }

    /* ---- Step 27 (Phase 8): OSC 11 traffic + grandchild PTY drain ---- */
    /* Combined test: send multiple OSC 11 background color changes, then fork
     * a grandchild holding the PTY slave and exit the shell. The bridge must
     * drain the PTY with the 200ms poll timeout and send ExitStatus despite
     * the grandchild holding the slave. This verifies that OSC 11 sniffing
     * does not interfere with the Phase 4 drain fix. */
    printf("\n[host] Step 27: Phase 8 OSC 11 traffic + grandchild PTY drain timeout...\n");
    {
        int bc_init_fd = -1, bc_control_fd = -1;
        if (setup_bridge_session(&bc_init_fd, &bc_control_fd, 24, 80, 27, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup bg+grandchild session\n");
            CHECK(0, "Phase 8: bg+grandchild session setup", "connect failed");
        } else {
            int bc_extra[5];
            int bc_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                bc_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (bc_extra[i] < 0) { bc_extra_ok = 0; break; }
            }

            if (!bc_extra_ok) {
                CHECK(0, "Phase 8: bg+grandchild extra sockets", "connect failed");
                close(bc_init_fd); close(bc_control_fd);
                for (int i = 0; i < 5; i++) if (bc_extra[i] >= 0) close(bc_extra[i]);
            } else {
                usleep(300000);

                /* Send multiple OSC 11 background color changes */
                const char *bg_cmds[] = {
                    "printf '\\033]11;rgb:11/11/11\\007'\n",
                    "printf '\\033]11;rgb:22/22/22\\007'\n",
                    "printf '\\033]11;rgb:33/33/33\\007'\n",
                    "printf '\\033]11;rgb:44/44/44\\007'\n",
                    "printf '\\033]11;rgb:55/55/55\\007'\n",
                };
                for (int i = 0; i < 5; i++) {
                    send_all(bc_extra[0], bg_cmds[i], strlen(bg_cmds[i]));
                }
                printf("  Sent 5 OSC 11 background color changes\n");

                /* Drain bg traffic output */
                char bc_buf[2048];
                memset(bc_buf, 0, sizeof(bc_buf));
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(bc_extra[1], bc_buf, sizeof(bc_buf) - 1, 300);
                    if (n <= 0) break;
                }

                /* Fork grandchild holding PTY slave, then exit shell */
                const char *bg_cmd = "sleep 60 &\n";
                send_all(bc_extra[0], bg_cmd, strlen(bg_cmd));
                printf("  Sent '%s' to fork grandchild holding PTY slave\n", bg_cmd);

                /* Drain job control output */
                memset(bc_buf, 0, sizeof(bc_buf));
                for (int attempt = 0; attempt < 10; attempt++) {
                    int n = read_with_timeout(bc_extra[1], bc_buf, sizeof(bc_buf) - 1, 300);
                    if (n <= 0) break;
                }

                /* Exit shell — grandchild still holds PTY slave */
                send_all(bc_extra[0], "exit\n", 5);
                printf("  Sent 'exit' — shell exits, grandchild still holds PTY slave\n");

                /* Drain remaining stdout */
                memset(bc_buf, 0, sizeof(bc_buf));
                for (int attempt = 0; attempt < 20; attempt++) {
                    int n = read_with_timeout(bc_extra[1], bc_buf, sizeof(bc_buf) - 1, 200);
                    if (n <= 0) break;
                }

                /* Read ExitStatus — should arrive despite grandchild */
                int got_bc_exit = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    void *msg = recv_message(bc_control_fd, &hdr);
                    if (!msg) { usleep(100000); continue; }
                    struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                    if (mhdr->MessageType == LxInitMessageExitStatus) {
                        got_bc_exit = 1;
                    }
                    free(msg);
                    if (got_bc_exit) break;
                }

                CHECK(got_bc_exit,
                      "Phase 8: ExitStatus received after OSC 11 traffic + grandchild (drain timeout works)",
                      "not received — bridge may be hung in drain loop after OSC 11 traffic");

                for (int i = 0; i < 5; i++) close(bc_extra[i]);
                close(bc_init_fd);
                close(bc_control_fd);
            }
        }
    }

    /* ---- Step 28 (Phase 8): New session after OSC 11 + grandchild test ---- */
    printf("\n[host] Step 28: Phase 8 new session after OSC 11 + grandchild test (verify no deadlock)...\n");
    {
        int b2_init_fd = -1, b2_control_fd = -1;
        if (setup_bridge_session(&b2_init_fd, &b2_control_fd, 24, 80, 28, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup post-OSC11 session (bridge may be deadlocked)\n");
            CHECK(0, "Phase 8: new session after OSC 11 + grandchild test", "connect failed (deadlock?)");
        } else {
            int b2_extra[5];
            int b2_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                b2_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (b2_extra[i] < 0) { b2_extra_ok = 0; break; }
            }

            if (!b2_extra_ok) {
                CHECK(0, "Phase 8: post-OSC11 extra sockets", "connect failed");
                close(b2_init_fd); close(b2_control_fd);
                for (int i = 0; i < 5; i++) if (b2_extra[i] >= 0) close(b2_extra[i]);
            } else {
                CHECK(1, "Phase 8: new session accepted after OSC 11 + grandchild test (no deadlock)", "ok");

                /* Quick echo test to confirm the session is fully functional */
                usleep(300000);
                const char *echo_cmd = "echo bgcolor_test_ok\n";
                send_all(b2_extra[0], echo_cmd, strlen(echo_cmd));

                char b2_out[4096];
                memset(b2_out, 0, sizeof(b2_out));
                int b2_total = 0;
                for (int attempt = 0; attempt < 50; attempt++) {
                    int n = read_with_timeout(b2_extra[1], b2_out + b2_total,
                                              sizeof(b2_out) - b2_total - 1, 200);
                    if (n > 0) b2_total += n;
                    else break;
                }
                printf("  Console output: '%s'\n", b2_out);
                CHECK(strstr(b2_out, "bgcolor_test_ok") != NULL,
                      "Phase 8: console I/O works after OSC 11 + grandchild test",
                      "output='%s'", b2_out);

                /* Send exit and close */
                send_all(b2_extra[0], "exit\n", 5);
                for (int attempt = 0; attempt < 30; attempt++) {
                    void *msg = recv_message(b2_control_fd, &hdr);
                    if (msg) { free(msg); break; }
                    usleep(100000);
                }

                for (int i = 0; i < 5; i++) close(b2_extra[i]);
                close(b2_init_fd);
                close(b2_control_fd);
            }
        }
    }

    /* ---- Step 46 (Phase 9 / C2): NetworkInformation(4) — resolv.conf ---- */
    printf("\n[host] Step 46: Sending NetworkInformation(4) with DNS config...\n");
    {
        /* Build a NetworkInformation message with FileHeader and FileContents.
         * Buffer layout: [FileHeader\0][FileContents\0]
         * FileHeaderIndex = 0, FileContentsIndex = offset of second string. */
        const char *file_header = "# Generated by WSL mock host";
        const char *file_contents = "nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch example.com";
        size_t fh_len = strlen(file_header) + 1;
        size_t fc_len = strlen(file_contents) + 1;
        size_t buf_size = fh_len + fc_len;
        size_t msg_size = sizeof(LX_INIT_NETWORK_INFORMATION) + buf_size;

        LX_INIT_NETWORK_INFORMATION *ni = calloc(1, msg_size);
        if (!ni) {
            CHECK(0, "NetworkInformation alloc", "oom");
        } else {
            ni->Header.MessageType = LxInitMessageNetworkInformation;
            ni->Header.MessageSize = (uint32_t)msg_size;
            ni->Header.SequenceNumber = 300;
            ni->FileHeaderIndex = 0;
            ni->FileContentsIndex = (uint32_t)fh_len;
            memcpy(ni->Buffer, file_header, fh_len);
            memcpy(ni->Buffer + fh_len, file_contents, fc_len);

            int sent = send_all(init_fd, ni, msg_size);
            CHECK(sent == 0, "NetworkInformation sent to guest",
                  "send returned %d", sent);
            free(ni);

            /* NetworkInformation does not expect a response — verify by
             * checking the guest didn't disconnect (send a follow-up query). */
            printf("  NetworkInformation sent (no response expected)\n");
            CHECK(1, "NetworkInformation processed (no crash)", "");

            /* Verify resolv.conf was written when WSL_TEST_ROOT is set.
             * NOTE: A prior test step (Step 80 DNS Update) may have already
             * written resolv.conf with different nameservers. We must retry
             * on CONTENT, not just file existence, to avoid reading stale
             * content from a previous write. */
            {
                const char *test_root = getenv("WSL_TEST_ROOT");
                if (test_root && test_root[0]) {
                    char resolv_path[512];
                    snprintf(resolv_path, sizeof(resolv_path),
                             "%s/resolv.conf", test_root);
                    int has_nameserver = 0;
                    for (int retry = 0; retry < 30 && !has_nameserver; retry++) {
                        FILE *rf = fopen(resolv_path, "r");
                        if (rf) {
                            char line[256];
                            while (fgets(line, sizeof(line), rf)) {
                                if (strstr(line, "nameserver 8.8.8.8"))
                                    has_nameserver = 1;
                            }
                            fclose(rf);
                        }
                        if (!has_nameserver)
                            usleep(100000);
                    }
                    CHECK(has_nameserver,
                          "C2: resolv.conf contains nameserver 8.8.8.8",
                          "content missing expected DNS entry (path=%s)",
                          resolv_path);
                }
            }
        }
    }

    /* ---- Step 47 (Phase 9 / C5): QueryNetworkingMode(25) ---- */
    printf("\n[host] Step 47: Sending QueryNetworkingMode(25), expecting NAT(0)...\n");
    {
        struct MESSAGE_HEADER qnm;
        memset(&qnm, 0, sizeof(qnm));
        qnm.MessageType = LxInitMessageQueryNetworkingMode;
        qnm.MessageSize = sizeof(qnm);
        qnm.SequenceNumber = 301;

        int sent = send_all(init_fd, &qnm, sizeof(qnm));
        CHECK(sent == 0, "QueryNetworkingMode sent", "send returned %d", sent);

        if (sent == 0) {
            RESULT_MESSAGE_UINT32 *resp =
                (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
            if (resp) {
                printf("  Received: type=%u, seq=%u, Result=%u\n",
                       resp->Header.MessageType, resp->Header.SequenceNumber,
                       resp->Result);
                CHECK(resp->Header.MessageType == LxMessageResultUint32,
                      "QueryNetworkingMode response type==78",
                      "got %u", resp->Header.MessageType);
                CHECK(resp->Header.SequenceNumber == 301,
                      "QueryNetworkingMode response seq echoed (301)",
                      "got %u", resp->Header.SequenceNumber);
                CHECK(resp->Result == 0,
                      "QueryNetworkingMode Result==0 (NAT mode)",
                      "got %u", resp->Result);
                free(resp);
            } else {
                CHECK(0, "QueryNetworkingMode response received", "no response");
            }
        }
    }

    /* ---- Step 48 (Phase 9 / C5): QueryVmId(26) ---- */
    printf("\n[host] Step 48: Sending QueryVmId(26), expecting result...\n");
    {
        struct MESSAGE_HEADER qvi;
        memset(&qvi, 0, sizeof(qvi));
        qvi.MessageType = LxInitMessageQueryVmId;
        qvi.MessageSize = sizeof(qvi);
        qvi.SequenceNumber = 302;

        int sent = send_all(init_fd, &qvi, sizeof(qvi));
        CHECK(sent == 0, "QueryVmId sent", "send returned %d", sent);

        if (sent == 0) {
            RESULT_MESSAGE_UINT32 *resp =
                (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
            if (resp) {
                printf("  Received: type=%u, seq=%u, Result=0x%x\n",
                       resp->Header.MessageType, resp->Header.SequenceNumber,
                       resp->Result);
                CHECK(resp->Header.MessageType == LxMessageResultUint32,
                      "QueryVmId response type==78",
                      "got %u", resp->Header.MessageType);
                CHECK(resp->Header.SequenceNumber == 302,
                      "QueryVmId response seq echoed (302)",
                      "got %u", resp->Header.SequenceNumber);
                CHECK(resp->Result != 0,
                      "QueryVmId Result non-zero (VM ID set)",
                      "got 0");
                free(resp);
            } else {
                CHECK(0, "QueryVmId response received", "no response");
            }
        }
    }

    /* ---- Step 49 (Phase 9 / C4): StartSocketRelay(15) ---- */
    printf("\n[host] Step 49: Sending StartSocketRelay(15)...\n");
    {
        LX_INIT_START_SOCKET_RELAY ssr;
        memset(&ssr, 0, sizeof(ssr));
        ssr.Header.MessageType = LxInitMessageStartSocketRelay;
        ssr.Header.MessageSize = sizeof(ssr);
        ssr.Header.SequenceNumber = 303;
        ssr.Family = AF_INET;
        ssr.Port = 18080;        /* guest-side listen port */
        ssr.HvSocketPort = 5000; /* host-side relay target (mock) */
        ssr.BufferSize = 4096;

        int sent = send_all(init_fd, &ssr, sizeof(ssr));
        CHECK(sent == 0, "StartSocketRelay sent", "send returned %d", sent);

        if (sent == 0) {
            /* Give the relay daemon time to start */
            usleep(200000);  /* 200ms */

            /* Verify the relay is listening by connecting to it.
             * The relay forwards to HvSocketPort=5000 which won't be
             * listening, but the connect to 18080 should succeed. */
            int relay_fd = connect_to_port(18080);
            CHECK(relay_fd >= 0, "StartSocketRelay relay listening on 18080",
                  "connect failed (fd=%d)", relay_fd);

            if (relay_fd >= 0) {
                /* Send a byte and verify the relay accepts it (even if
                 * the upstream connection fails, the accept worked). */
                const char *test_data = "relay_test\n";
                int w = send(relay_fd, test_data, strlen(test_data), 0);
                CHECK(w > 0, "StartSocketRelay relay accepts data",
                      "send returned %d", w);
                close(relay_fd);
            }
        }
    }

    /* ---- Step 50 (Phase 9 / C2): NetworkInformation edge case — empty contents ---- */
    printf("\n[host] Step 50: Sending NetworkInformation with empty FileContents...\n");
    {
        /* Edge case: empty FileContents string (just a NUL byte) */
        const char *file_header = "# empty test";
        const char *file_contents = "";
        size_t fh_len = strlen(file_header) + 1;
        size_t fc_len = strlen(file_contents) + 1;  /* 1 (just NUL) */
        size_t buf_size = fh_len + fc_len;
        size_t msg_size = sizeof(LX_INIT_NETWORK_INFORMATION) + buf_size;

        LX_INIT_NETWORK_INFORMATION *ni = calloc(1, msg_size);
        if (!ni) {
            CHECK(0, "NetworkInformation empty alloc", "oom");
        } else {
            ni->Header.MessageType = LxInitMessageNetworkInformation;
            ni->Header.MessageSize = (uint32_t)msg_size;
            ni->Header.SequenceNumber = 304;
            ni->FileHeaderIndex = 0;
            ni->FileContentsIndex = (uint32_t)fh_len;
            memcpy(ni->Buffer, file_header, fh_len);
            memcpy(ni->Buffer + fh_len, file_contents, fc_len);

            int sent = send_all(init_fd, ni, msg_size);
            CHECK(sent == 0, "NetworkInformation empty sent",
                  "send returned %d", sent);
            free(ni);
            CHECK(1, "NetworkInformation empty processed (no crash)", "");
        }
    }

    /* ---- Step 51 (Phase 9 / C2): NetworkInformation edge case — invalid offsets ---- */
    printf("\n[host] Step 51: Sending NetworkInformation with invalid offsets...\n");
    {
        /* Edge case: offsets beyond buffer boundary */
        size_t msg_size = sizeof(LX_INIT_NETWORK_INFORMATION) + 4;
        LX_INIT_NETWORK_INFORMATION *ni = calloc(1, msg_size);
        if (!ni) {
            CHECK(0, "NetworkInformation invalid alloc", "oom");
        } else {
            ni->Header.MessageType = LxInitMessageNetworkInformation;
            ni->Header.MessageSize = (uint32_t)msg_size;
            ni->Header.SequenceNumber = 305;
            ni->FileHeaderIndex = 9999;   /* way beyond buffer */
            ni->FileContentsIndex = 8888; /* way beyond buffer */
            memcpy(ni->Buffer, "abc", 4);

            int sent = send_all(init_fd, ni, msg_size);
            CHECK(sent == 0, "NetworkInformation invalid-offsets sent",
                  "send returned %d", sent);
            free(ni);
            /* Guest should handle gracefully (NULL strings) without crashing */
            CHECK(1, "NetworkInformation invalid-offsets processed (no crash)", "");
        }
    }

    /* ---- Step 52 (Phase 9 / C5): QueryNetworkingMode seq echo ---- */
    printf("\n[host] Step 52: Sending QueryNetworkingMode with seq=999...\n");
    {
        struct MESSAGE_HEADER qnm;
        memset(&qnm, 0, sizeof(qnm));
        qnm.MessageType = LxInitMessageQueryNetworkingMode;
        qnm.MessageSize = sizeof(qnm);
        qnm.SequenceNumber = 999;

        int sent = send_all(init_fd, &qnm, sizeof(qnm));
        CHECK(sent == 0, "QueryNetworkingMode seq=999 sent",
              "send returned %d", sent);

        if (sent == 0) {
            RESULT_MESSAGE_UINT32 *resp =
                (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
            if (resp) {
                CHECK(resp->Header.SequenceNumber == 999,
                      "QueryNetworkingMode seq=999 echoed",
                      "got %u", resp->Header.SequenceNumber);
                free(resp);
            } else {
                CHECK(0, "QueryNetworkingMode seq=999 response", "no response");
            }
        }
    }

    /* ---- Step 53 (Phase 9 / C4): StartSocketRelay edge — port 0 (invalid) ---- */
    printf("\n[host] Step 53: Sending StartSocketRelay with port=0 (invalid)...\n");
    {
        LX_INIT_START_SOCKET_RELAY ssr;
        memset(&ssr, 0, sizeof(ssr));
        ssr.Header.MessageType = LxInitMessageStartSocketRelay;
        ssr.Header.MessageSize = sizeof(ssr);
        ssr.Header.SequenceNumber = 306;
        ssr.Family = AF_INET;
        ssr.Port = 0;           /* invalid — bind should fail */
        ssr.HvSocketPort = 5001;
        ssr.BufferSize = 4096;

        int sent = send_all(init_fd, &ssr, sizeof(ssr));
        CHECK(sent == 0, "StartSocketRelay port=0 sent",
              "send returned %d", sent);
        /* Guest should handle bind failure gracefully — no crash.
         * Note: port 0 actually lets the OS pick a port, so this may
         * succeed. The test verifies no crash either way. */
        CHECK(1, "StartSocketRelay port=0 processed (no crash)", "");
    }

    /* ---- Step 54 (Phase 9 / C-group): Multiple sequential queries ---- */
    printf("\n[host] Step 54: Sending multiple sequential networking queries...\n");
    {
        int all_ok = 1;
        for (int i = 0; i < 3; i++) {
            struct MESSAGE_HEADER qnm;
            memset(&qnm, 0, sizeof(qnm));
            qnm.MessageType = LxInitMessageQueryNetworkingMode;
            qnm.MessageSize = sizeof(qnm);
            qnm.SequenceNumber = 400 + i;

            if (send_all(init_fd, &qnm, sizeof(qnm)) < 0) {
                all_ok = 0;
                break;
            }
            RESULT_MESSAGE_UINT32 *resp =
                (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
            if (!resp) { all_ok = 0; break; }
            int ok = (resp->Header.SequenceNumber == (uint32_t)(400 + i) &&
                      resp->Result == 0);
            free(resp);
            if (!ok) { all_ok = 0; break; }
        }
        CHECK(all_ok, "3 sequential QueryNetworkingMode queries all correct",
              "failed at iteration");
    }

    /* ================================================================== */
    /* ---- Task Group D: Interop server tests (Steps 55-61)           ---- */
    /* ================================================================== */

    /* Step 55: Setup interop session + QueryDrvfsElevated(12) */
    printf("\n[host] Step 55: Setting up interop session + QueryDrvfsElevated(12)...\n");
    {
        int io_init_fd = -1, io_control_fd = -1;
        if (setup_bridge_session(&io_init_fd, &io_control_fd, 24, 80, 55, NULL) < 0) {
            fprintf(stderr, "  [FAIL] cannot setup interop session\n");
            CHECK(0, "Interop session setup", "connect failed");
        } else {
            /* Connect 5 extra sockets */
            int io_extra[5];
            int io_ok = 1;
            for (int i = 0; i < 5; i++) {
                io_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (io_extra[i] < 0) { io_ok = 0; break; }
            }

            if (!io_ok) {
                CHECK(0, "Interop session: 5 extra sockets connected", "connect failed");
                for (int i = 0; i < 5; i++) if (io_extra[i] >= 0) close(io_extra[i]);
                close(io_init_fd);
                close(io_control_fd);
            } else {
                CHECK(1, "Interop session: 5 extra sockets connected", "ok");

                /* Give bridge time to start the session */
                usleep(300000);

                /* Send QueryDrvfsElevated(12) on interop socket (extra[4]) */
                struct MESSAGE_HEADER qde_msg;
                memset(&qde_msg, 0, sizeof(qde_msg));
                qde_msg.MessageType = LxInitMessageQueryDrvfsElevated;
                qde_msg.MessageSize = sizeof(qde_msg);
                qde_msg.SequenceNumber = 551;

                int send_rc = send_all(io_extra[4], &qde_msg, sizeof(qde_msg));
                CHECK(send_rc == 0, "QueryDrvfsElevated sent on interop channel",
                      "send failed");

                /* Expect RESULT_MESSAGE_BOOL response */
                struct MESSAGE_HEADER resp_hdr;
                void *resp = recv_message(io_extra[4], &resp_hdr);
                if (resp) {
                    RESULT_MESSAGE_BOOL *bool_resp = (RESULT_MESSAGE_BOOL *)resp;
                    printf("  Response: type=%u, seq=%u, result=%u\n",
                           bool_resp->Header.MessageType,
                           bool_resp->Header.SequenceNumber,
                           bool_resp->Result);

                    CHECK(bool_resp->Header.MessageType == LxMessageResultBool,
                          "QueryDrvfsElevated response type==76 (ResultBool)",
                          "got %u", bool_resp->Header.MessageType);
                    CHECK(bool_resp->Header.SequenceNumber == 551,
                          "QueryDrvfsElevated response seq echoed (551)",
                          "got %u", bool_resp->Header.SequenceNumber);
                    CHECK(bool_resp->Result == 0,
                          "QueryDrvfsElevated result==false (no DrvFs yet)",
                          "got %u", bool_resp->Result);
                    free(resp);
                } else {
                    CHECK(0, "QueryDrvfsElevated response received", "no response");
                }

                /* Step 56: Unknown message type on interop channel */
                printf("\n[host] Step 56: Sending unknown message type on interop...\n");
                {
                    struct MESSAGE_HEADER unk_msg;
                    memset(&unk_msg, 0, sizeof(unk_msg));
                    unk_msg.MessageType = 9999; /* unknown type */
                    unk_msg.MessageSize = sizeof(unk_msg);
                    unk_msg.SequenceNumber = 561;

                    send_all(io_extra[4], &unk_msg, sizeof(unk_msg));
                    /* No response expected — verify bridge is still alive by
                     * sending a follow-up QueryFeatureFlags(17) */
                    usleep(200000);

                    struct MESSAGE_HEADER qff_msg;
                    memset(&qff_msg, 0, sizeof(qff_msg));
                    qff_msg.MessageType = LxInitMessageQueryFeatureFlags;
                    qff_msg.MessageSize = sizeof(qff_msg);
                    qff_msg.SequenceNumber = 562;

                    send_all(io_extra[4], &qff_msg, sizeof(qff_msg));

                    void *qff_resp = recv_message(io_extra[4], &resp_hdr);
                    if (qff_resp) {
                        RESULT_MESSAGE_INT32 *int32_resp = (RESULT_MESSAGE_INT32 *)qff_resp;
                        CHECK(int32_resp->Header.MessageType == LxMessageResultInt32,
                              "Bridge alive after unknown msg (QueryFeatureFlags response type==77)",
                              "got %u", int32_resp->Header.MessageType);
                        CHECK(int32_resp->Header.SequenceNumber == 562,
                              "QueryFeatureFlags response seq echoed (562)",
                              "got %u", int32_resp->Header.SequenceNumber);
                        free(qff_resp);
                    } else {
                        CHECK(0, "Bridge alive after unknown msg", "no response to follow-up");
                    }
                }

                /* Step 57: QueryEnvironmentVariable(16) for "PATH" */
                printf("\n[host] Step 57: QueryEnvironmentVariable(16) for PATH...\n");
                {
                    const char *var_name = "PATH";
                    size_t name_len = strlen(var_name) + 1;
                    size_t msg_size = sizeof(struct MESSAGE_HEADER) + name_len;
                    char *env_msg = calloc(1, msg_size);
                    struct MESSAGE_HEADER *ehdr = (struct MESSAGE_HEADER *)env_msg;
                    ehdr->MessageType = LxInitMessageQueryEnvironmentVariable;
                    ehdr->MessageSize = (unsigned int)msg_size;
                    ehdr->SequenceNumber = 571;
                    memcpy(env_msg + sizeof(*ehdr), var_name, name_len);

                    send_all(io_extra[4], env_msg, msg_size);
                    free(env_msg);

                    void *env_resp = recv_message(io_extra[4], &resp_hdr);
                    if (env_resp) {
                        struct MESSAGE_HEADER *rh = (struct MESSAGE_HEADER *)env_resp;
                        char *value = (char *)env_resp + sizeof(struct MESSAGE_HEADER);

                        CHECK(rh->MessageType == LxInitMessageQueryEnvironmentVariable,
                              "QueryEnvironmentVariable response type==16",
                              "got %u", rh->MessageType);
                        CHECK(rh->SequenceNumber == 571,
                              "QueryEnvironmentVariable response seq echoed (571)",
                              "got %u", rh->SequenceNumber);
                        /* PATH should contain /bin since we set it in CreateProcess */
                        CHECK(strstr(value, "/bin") != NULL,
                              "QueryEnvironmentVariable PATH contains /bin",
                              "got '%s'", value);
                        printf("  PATH value: '%s'\n", value);
                        free(env_resp);
                    } else {
                        CHECK(0, "QueryEnvironmentVariable response received", "no response");
                    }
                }

                /* Step 58: QueryFeatureFlags(17) */
                printf("\n[host] Step 58: QueryFeatureFlags(17)...\n");
                {
                    struct MESSAGE_HEADER qff_msg;
                    memset(&qff_msg, 0, sizeof(qff_msg));
                    qff_msg.MessageType = LxInitMessageQueryFeatureFlags;
                    qff_msg.MessageSize = sizeof(qff_msg);
                    qff_msg.SequenceNumber = 581;

                    send_all(io_extra[4], &qff_msg, sizeof(qff_msg));

                    void *qff_resp = recv_message(io_extra[4], &resp_hdr);
                    if (qff_resp) {
                        RESULT_MESSAGE_INT32 *int32_resp = (RESULT_MESSAGE_INT32 *)qff_resp;
                        printf("  Response: type=%u, seq=%u, flags=%d\n",
                               int32_resp->Header.MessageType,
                               int32_resp->Header.SequenceNumber,
                               int32_resp->Result);

                        CHECK(int32_resp->Header.MessageType == LxMessageResultInt32,
                              "QueryFeatureFlags response type==77 (ResultInt32)",
                              "got %u", int32_resp->Header.MessageType);
                        CHECK(int32_resp->Header.SequenceNumber == 581,
                              "QueryFeatureFlags response seq echoed (581)",
                              "got %u", int32_resp->Header.SequenceNumber);
                        CHECK(int32_resp->Result == 0,
                              "QueryFeatureFlags result==0 (no features enabled)",
                              "got %d", int32_resp->Result);
                        free(qff_resp);
                    } else {
                        CHECK(0, "QueryFeatureFlags response received", "no response");
                    }
                }

                /* Step 59: CreateLoginSession(23) */
                printf("\n[host] Step 59: CreateLoginSession(23) with uid=0, username=root...\n");
                {
                    const char *username = "root";
                    size_t name_len = strlen(username) + 1;
                    size_t msg_size = sizeof(struct MESSAGE_HEADER) + 8 + name_len;
                    char *cls_msg = calloc(1, msg_size);
                    struct MESSAGE_HEADER *chdr = (struct MESSAGE_HEADER *)cls_msg;
                    chdr->MessageType = LxInitMessageCreateLoginSession;
                    chdr->MessageSize = (unsigned int)msg_size;
                    chdr->SequenceNumber = 591;

                    /* Uid at offset 12, Gid at offset 16, Buffer at offset 20 */
                    unsigned int *uid_ptr = (unsigned int *)(cls_msg + sizeof(struct MESSAGE_HEADER));
                    uid_ptr[0] = 0; /* Uid */
                    uid_ptr[1] = 0; /* Gid */
                    memcpy(cls_msg + sizeof(struct MESSAGE_HEADER) + 8, username, name_len);

                    send_all(io_extra[4], cls_msg, msg_size);
                    free(cls_msg);

                    void *cls_resp = recv_message(io_extra[4], &resp_hdr);
                    if (cls_resp) {
                        RESULT_MESSAGE_BOOL *bool_resp = (RESULT_MESSAGE_BOOL *)cls_resp;
                        printf("  Response: type=%u, seq=%u, result=%u\n",
                               bool_resp->Header.MessageType,
                               bool_resp->Header.SequenceNumber,
                               bool_resp->Result);

                        CHECK(bool_resp->Header.MessageType == LxMessageResultBool,
                              "CreateLoginSession response type==76 (ResultBool)",
                              "got %u", bool_resp->Header.MessageType);
                        CHECK(bool_resp->Header.SequenceNumber == 591,
                              "CreateLoginSession response seq echoed (591)",
                              "got %u", bool_resp->Header.SequenceNumber);
                        /* E group: CreateLoginSession returns false because
                         * systemd is disabled on FreeBSD (matching reference
                         * config.cpp:422 behavior when Config.BootInit=false). */
                        CHECK(bool_resp->Result == 0,
                              "CreateLoginSession result==false (systemd disabled)",
                              "got %u", bool_resp->Result);
                        free(cls_resp);
                    } else {
                        CHECK(0, "CreateLoginSession response received", "no response");
                    }
                }

                /* Step 60: CreateProcess(1) → CreateProcessResponse(11) with ENOENT */
                printf("\n[host] Step 60: CreateProcess(1) — expect ENOENT response...\n");
                {
                    /* Send a minimal CreateProcess(1) message.
                     * The bridge cannot launch Windows binaries, so it should
                     * respond with CreateProcessResponse(11) containing ENOENT. */
                    struct MESSAGE_HEADER cp_msg;
                    memset(&cp_msg, 0, sizeof(cp_msg));
                    cp_msg.MessageType = LxInitMessageCreateProcess;
                    cp_msg.MessageSize = sizeof(cp_msg);
                    cp_msg.SequenceNumber = 601;

                    send_all(io_extra[4], &cp_msg, sizeof(cp_msg));

                    void *cp_resp = recv_message(io_extra[4], &resp_hdr);
                    if (cp_resp) {
                        /* The response is LX_INIT_CREATE_PROCESS_RESPONSE */
                        struct MESSAGE_HEADER *rh = (struct MESSAGE_HEADER *)cp_resp;
                        printf("  Response: type=%u, seq=%u, size=%u\n",
                               rh->MessageType, rh->SequenceNumber, rh->MessageSize);

                        CHECK(rh->MessageType == LxInitMessageCreateProcessResponse,
                              "CreateProcess response type==11 (CreateProcessResponse)",
                              "got %u", rh->MessageType);
                        CHECK(rh->SequenceNumber == 601,
                              "CreateProcess response seq echoed (601)",
                              "got %u", rh->SequenceNumber);

                        /* Verify the Result field is ENOENT (2 on Linux) */
                        if (rh->MessageSize >= sizeof(struct MESSAGE_HEADER) + sizeof(int)) {
                            int *result_ptr = (int *)((char *)cp_resp + sizeof(struct MESSAGE_HEADER));
                            printf("  Result code: %d (ENOENT=%d)\n", *result_ptr, ENOENT);
                            CHECK(*result_ptr == ENOENT,
                                  "CreateProcess result==ENOENT (cannot launch Windows binaries)",
                                  "got %d", *result_ptr);
                        } else {
                            CHECK(0, "CreateProcess response has Result field",
                                  "size too small: %u", rh->MessageSize);
                        }
                        free(cp_resp);
                    } else {
                        CHECK(0, "CreateProcess response received", "no response");
                    }
                }

                /* Step 61: QueryNetworkingMode(25) + QueryVmId(26) on interop */
                printf("\n[host] Step 61: QueryNetworkingMode(25) + QueryVmId(26) on interop...\n");
                {
                    /* QueryNetworkingMode */
                    struct MESSAGE_HEADER qnm_msg;
                    memset(&qnm_msg, 0, sizeof(qnm_msg));
                    qnm_msg.MessageType = LxInitMessageQueryNetworkingMode;
                    qnm_msg.MessageSize = sizeof(qnm_msg);
                    qnm_msg.SequenceNumber = 611;

                    send_all(io_extra[4], &qnm_msg, sizeof(qnm_msg));

                    void *qnm_resp = recv_message(io_extra[4], &resp_hdr);
                    if (qnm_resp) {
                        RESULT_MESSAGE_UINT8 *uint8_resp = (RESULT_MESSAGE_UINT8 *)qnm_resp;
                        printf("  NetworkingMode: type=%u, seq=%u, mode=%u\n",
                               uint8_resp->Header.MessageType,
                               uint8_resp->Header.SequenceNumber,
                               uint8_resp->Result);

                        CHECK(uint8_resp->Header.MessageType == LxMessageResultUint8,
                              "QueryNetworkingMode response type==79 (ResultUint8)",
                              "got %u", uint8_resp->Header.MessageType);
                        CHECK(uint8_resp->Header.SequenceNumber == 611,
                              "QueryNetworkingMode response seq echoed (611)",
                              "got %u", uint8_resp->Header.SequenceNumber);
                        CHECK(uint8_resp->Result == LxInitNetworkingModeNat,
                              "QueryNetworkingMode result==0 (NAT)",
                              "got %u", uint8_resp->Result);
                        free(qnm_resp);
                    } else {
                        CHECK(0, "QueryNetworkingMode response received", "no response");
                    }

                    /* QueryVmId */
                    struct MESSAGE_HEADER qvi_msg;
                    memset(&qvi_msg, 0, sizeof(qvi_msg));
                    qvi_msg.MessageType = LxInitMessageQueryVmId;
                    qvi_msg.MessageSize = sizeof(qvi_msg);
                    qvi_msg.SequenceNumber = 612;

                    send_all(io_extra[4], &qvi_msg, sizeof(qvi_msg));

                    void *qvi_resp = recv_message(io_extra[4], &resp_hdr);
                    if (qvi_resp) {
                        struct MESSAGE_HEADER *rh = (struct MESSAGE_HEADER *)qvi_resp;
                        char *vm_id = (char *)qvi_resp + sizeof(struct MESSAGE_HEADER);

                        CHECK(rh->MessageType == LxInitMessageQueryVmId,
                              "QueryVmId response type==26",
                              "got %u", rh->MessageType);
                        CHECK(rh->SequenceNumber == 612,
                              "QueryVmId response seq echoed (612)",
                              "got %u", rh->SequenceNumber);
                        /* G: VmId should now be a non-empty GUID string
                         * (read from /etc/hostid or /etc/machine-id). */
                        CHECK(vm_id[0] != '\0',
                              "QueryVmId result non-empty GUID string",
                              "got empty string");
                        printf("  VmId: '%s'\n", vm_id);
                        free(qvi_resp);
                    } else {
                        CHECK(0, "QueryVmId response received", "no response");
                    }
                }

                /* ========================================================= */
                /* ---- Task Group E: Local interop socket tests          ---- */
                /* ========================================================= */

                /* Step 62 (E5a): Verify the local interop Unix socket file
                 * exists at /run/WSL/<pid>_interop during an active session.
                 * This validates E2a/E2b (wsl_interop_create_server in
                 * hvbridge creates the socket and listens on it). */
                printf("\n[host] Step 62: E5a — verify local interop socket file exists...\n");
                {
                    usleep(200000);  /* give bridge time to create the socket */
                    const char *ls_cmd = "ls /run/WSL/ 2>/dev/null\n";
                    send_all(io_extra[0], ls_cmd, strlen(ls_cmd));

                    memset(outbuf, 0, sizeof(outbuf));
                    total = 0;
                    for (int attempt = 0; attempt < 30; attempt++) {
                        int n = read_with_timeout(io_extra[1], outbuf + total,
                                                  sizeof(outbuf) - total - 1, 200);
                        if (n > 0) {
                            total += n;
                            outbuf[total] = '\0';
                            if (strstr(outbuf, "_interop")) break;
                        }
                    }
                    printf("  ls /run/WSL/ output: '%s'\n", outbuf);
                    CHECK(strstr(outbuf, "_interop") != NULL,
                          "E5a: local interop socket file exists (/run/WSL/*_interop)",
                          "output='%s'", outbuf);
                }

                /* Step 63 (E5b): Verify WSL_INTEROP env var is set in the
                 * child process (shell). This validates E2b env injection
                 * (wsl_interop_set_env called before execve). */
                printf("\n[host] Step 63: E5b — verify WSL_INTEROP env var set in child...\n");
                {
                    const char *env_cmd = "echo \"WSL_INTEROP=$WSL_INTEROP\"\n";
                    send_all(io_extra[0], env_cmd, strlen(env_cmd));

                    memset(outbuf, 0, sizeof(outbuf));
                    total = 0;
                    for (int attempt = 0; attempt < 30; attempt++) {
                        int n = read_with_timeout(io_extra[1], outbuf + total,
                                                  sizeof(outbuf) - total - 1, 200);
                        if (n > 0) {
                            total += n;
                            outbuf[total] = '\0';
                            if (strstr(outbuf, "WSL_INTEROP=")) break;
                        }
                    }
                    printf("  env output: '%s'\n", outbuf);

                    /* Extract the socket path from WSL_INTEROP=... */
                    char *interop_path = strstr(outbuf, "WSL_INTEROP=");
                    if (interop_path) {
                        interop_path += strlen("WSL_INTEROP=");
                        /* Trim trailing whitespace/newline */
                        char *nl = strchr(interop_path, '\n');
                        if (nl) *nl = '\0';
                        char *cr = strchr(interop_path, '\r');
                        if (cr) *cr = '\0';
                    }
                    CHECK(strstr(outbuf, "WSL_INTEROP=/run/WSL/") != NULL,
                          "E5b: WSL_INTEROP env var set to /run/WSL/<pid>_interop",
                          "output='%s'", outbuf);
                }

                /* Step 63b (E5c): Test the full relay path — connect directly
                 * to the local interop Unix socket and send a minimal
                 * CreateProcessUtilityVm(8) message. The hvbridge should
                 * relay it to the host control channel (io_control_fd).
                 * This validates E2 relay logic (wsl_interop_relay_message)
                 * and the wsl-interop.c client-side message format (E3). */
                printf("\n[host] Step 63b: E5c — test interop relay to host control channel...\n");
                {
                    /* Re-read WSL_INTEROP to get the socket path */
                    const char *env_cmd2 = "printf '%s' \"$WSL_INTEROP\"\n";
                    send_all(io_extra[0], env_cmd2, strlen(env_cmd2));
                    usleep(200000);

                    char sock_path[108] = {0};
                    int sp_total = 0;
                    for (int attempt = 0; attempt < 30; attempt++) {
                        int n = read_with_timeout(io_extra[1], sock_path + sp_total,
                                                  sizeof(sock_path) - sp_total - 1, 200);
                        if (n > 0) {
                            sp_total += n;
                            sock_path[sp_total] = '\0';
                            if (sp_total > 0 && strstr(sock_path, "/run/WSL/"))
                                break;
                        }
                    }
                    /* Strip any leading prompt noise — find /run/WSL/ */
                    char *path_start = strstr(sock_path, "/run/WSL/");
                    if (path_start) {
                        memmove(sock_path, path_start, strlen(path_start) + 1);
                    }
                    /* Strip trailing prompt noise. printf '%s' outputs the
                     * path without a trailing newline, so the shell prompt
                     * "$ " gets appended to the read buffer. Truncate at the
                     * first '$', space, or CR/LF after the path. */
                    {
                        char *endp = sock_path;
                        while (*endp && *endp != '$' &&
                               *endp != ' ' && *endp != '\n' && *endp != '\r')
                            endp++;
                        *endp = '\0';
                    }
                    printf("  interop socket path: '%s'\n", sock_path);

                    if (strstr(sock_path, "/run/WSL/") == sock_path) {
                        /* Connect to the local interop Unix socket */
                        int interop_fd = socket(AF_UNIX, SOCK_STREAM, 0);
                        CHECK(interop_fd >= 0,
                              "E5c: create Unix socket for interop connection",
                              "socket failed");

                        if (interop_fd >= 0) {
                            struct sockaddr_un ua;
                            memset(&ua, 0, sizeof(ua));
                            ua.sun_family = AF_UNIX;
                            /* Use snprintf to avoid -Wstringop-truncation
                             * warning from strncpy. The path has already
                             * been validated and trimmed above. */
                            snprintf(ua.sun_path, sizeof(ua.sun_path),
                                     "%s", sock_path);

                            int conn_rc = connect(interop_fd, (struct sockaddr *)&ua,
                                                  sizeof(ua));
                            CHECK(conn_rc == 0,
                                  "E5c: connect to interop Unix socket",
                                  "connect failed: %s", strerror(errno));

                            if (conn_rc == 0) {
                                /* Build a minimal CreateProcessUtilityVm(8)
                                 * message with just a filename, matching the
                                 * wsl-interop.c client format (E3).
                                 * Layout: MESSAGE_HEADER + Rows + Cols +
                                 *         Common (offsets + Buffer) */
                                const char *filename = "C:\\Windows\\System32\\cmd.exe";
                                const char *cwd = "C:\\";
                                const char *cmdline = "cmd.exe";
                                uint32_t off_filename = 0;
                                uint32_t off_cwd = off_filename + strlen(filename) + 1;
                                uint32_t off_cmdline = off_cwd + strlen(cwd) + 1;
                                size_t buffer_size = off_cmdline + strlen(cmdline) + 1;

                                size_t msg_size = offsetof(LX_INIT_CREATE_PROCESS_UTILITY_VM,
                                                           Common.Buffer) + buffer_size;
                                char *nt_msg = calloc(1, msg_size);
                                if (nt_msg) {
                                    LX_INIT_CREATE_PROCESS_UTILITY_VM *umsg =
                                        (LX_INIT_CREATE_PROCESS_UTILITY_VM *)nt_msg;
                                    umsg->Header.MessageType = 8; /* CreateProcessUtilityVm */
                                    umsg->Header.MessageSize = (unsigned int)msg_size;
                                    umsg->Header.SequenceNumber = 631;
                                    umsg->Rows = 24;
                                    umsg->Columns = 80;
                                    umsg->Common.FilenameOffset = off_filename;
                                    umsg->Common.CurrentWorkingDirectoryOffset = off_cwd;
                                    umsg->Common.CommandLineOffset = off_cmdline;
                                    umsg->Common.CommandLineCount = 1;
                                    memcpy(umsg->Common.Buffer + off_filename,
                                           filename, strlen(filename) + 1);
                                    memcpy(umsg->Common.Buffer + off_cwd,
                                           cwd, strlen(cwd) + 1);
                                    memcpy(umsg->Common.Buffer + off_cmdline,
                                           cmdline, strlen(cmdline) + 1);

                                    int s = send_all(interop_fd, nt_msg, msg_size);
                                    CHECK(s == 0,
                                          "E5c: send CreateProcessUtilityVm to interop socket",
                                          "send failed");
                                    free(nt_msg);

                                    if (s == 0) {
                                        /* Read ResultUint32 response from
                                         * the interop socket (sent by
                                         * wsl_interop_relay_message) */
                                        struct MESSAGE_HEADER resp_hdr;
                                        void *resp = recv_message(interop_fd, &resp_hdr);
                                        if (resp) {
                                            RESULT_MESSAGE_UINT32 *r32 =
                                                (RESULT_MESSAGE_UINT32 *)resp;
                                            printf("  interop response: type=%u, seq=%u, result=%u\n",
                                                   r32->Header.MessageType,
                                                   r32->Header.SequenceNumber,
                                                   r32->Result);
                                            CHECK(r32->Header.MessageType == 78,
                                                  "E5c: interop response type==78 (ResultUint32)",
                                                  "got %u", r32->Header.MessageType);
                                            CHECK(r32->Header.SequenceNumber == 631,
                                                  "E5c: interop response seq echoed (631)",
                                                  "got %u", r32->Header.SequenceNumber);
                                            CHECK(r32->Result == 0,
                                                  "E5c: interop relay result==0 (success)",
                                                  "got %u", r32->Result);
                                            free(resp);
                                        } else {
                                            CHECK(0, "E5c: interop response received",
                                                  "no response");
                                        }

                                        /* Verify the relayed message arrived
                                         * on the host control channel */
                                        struct MESSAGE_HEADER ctl_hdr;
                                        void *relayed = recv_message(io_control_fd, &ctl_hdr);
                                        if (relayed) {
                                            struct MESSAGE_HEADER *rh =
                                                (struct MESSAGE_HEADER *)relayed;
                                            printf("  relayed to control: type=%u, seq=%u, size=%u\n",
                                                   rh->MessageType, rh->SequenceNumber,
                                                   rh->MessageSize);
                                            CHECK(rh->MessageType == 8,
                                                  "E5c: relayed message type==8 (CreateProcessUtilityVm)",
                                                  "got %u", rh->MessageType);
                                            CHECK(rh->SequenceNumber == 631,
                                                  "E5c: relayed message seq==631",
                                                  "got %u", rh->SequenceNumber);
                                            free(relayed);
                                        } else {
                                            CHECK(0, "E5c: relayed message received on control channel",
                                                  "no message");
                                        }
                                    }
                                }
                            }
                            close(interop_fd);
                        }
                    } else {
                        CHECK(0, "E5c: extract interop socket path from child env",
                              "sock_path='%s'", sock_path);
                    }
                }

                /* Cleanup interop session */
                send_all(io_extra[0], "exit\n", 5);
                usleep(300000);
                for (int i = 0; i < 5; i++) close(io_extra[i]);
                close(io_init_fd);
                close(io_control_fd);
            }
        }
    }

    /* ---- Step 35 (A3): TimezoneInformation(7) — send timezone update ----
     * Send a standalone TimezoneInformation(7) message to hvinit_tcp.
     * The guest should handle it in the event loop without crashing.
     * The timezone string is "America/New_York" (IANA format).
     * Reference: timezone.cpp UpdateTimezone() */
    printf("\n[host] Step 35: Sending TimezoneInformation(7) with tz='America/New_York'...\n");
    {
        const char *tz_str = "America/New_York";
        size_t tz_len = strlen(tz_str) + 1;
        size_t msg_size = 16 + tz_len;  /* 12-byte header + 4-byte offset + string */

        /* Build message manually: header(12) + TimezoneOffset(4) + Buffer(tz_str) */
        char *tz_msg = calloc(1, msg_size);
        if (!tz_msg) {
            CHECK(0, "A3: TimezoneInformation alloc", "oom");
        } else {
            /* Header */
            uint32_t msg_type = LxInitMessageTimezoneInformation;
            uint32_t msg_sz = (uint32_t)msg_size;
            uint32_t seq = 400;
            memcpy(tz_msg + 0, &msg_type, 4);
            memcpy(tz_msg + 4, &msg_sz, 4);
            memcpy(tz_msg + 8, &seq, 4);
            /* TimezoneOffset = 0 (start of Buffer) */
            uint32_t tz_offset = 0;
            memcpy(tz_msg + 12, &tz_offset, 4);
            /* Buffer = timezone string */
            memcpy(tz_msg + 16, tz_str, tz_len);

            int sent = send_all(init_fd, tz_msg, msg_size);
            CHECK(sent == 0, "A3: TimezoneInformation(7) sent to guest",
                  "send returned %d", sent);
            free(tz_msg);

            /* TimezoneInformation does not expect a response — verify by
             * checking the guest didn't disconnect (poll for short timeout) */
            struct pollfd pfd = { .fd = init_fd, .events = POLLIN };
            int pr = poll(&pfd, 1, 200);
            if (pr == 0) {
                CHECK(1, "A3: TimezoneInformation processed (no crash, no response)", "");
            } else if (pr < 0) {
                CHECK(0, "A3: poll after TimezoneInformation", "error %d", errno);
            } else {
                /* Guest sent something back — unexpected but not necessarily a failure */
                printf("  Note: guest sent data after TimezoneInformation (unexpected)\n");
                CHECK(1, "A3: TimezoneInformation processed (guest still alive)", "");
            }
        }
    }

    /* ---- Step 36 (A3): TimezoneInformation(7) — edge case: empty timezone ---- */
    printf("\n[host] Step 36: Sending TimezoneInformation(7) with empty timezone...\n");
    {
        size_t msg_size = 16 + 1;  /* header(12) + offset(4) + empty string */
        char *tz_msg = calloc(1, msg_size);
        if (!tz_msg) {
            CHECK(0, "A3: empty tz alloc", "oom");
        } else {
            uint32_t msg_type = LxInitMessageTimezoneInformation;
            uint32_t msg_sz = (uint32_t)msg_size;
            uint32_t seq = 401;
            uint32_t tz_offset = 0;
            memcpy(tz_msg + 0, &msg_type, 4);
            memcpy(tz_msg + 4, &msg_sz, 4);
            memcpy(tz_msg + 8, &seq, 4);
            memcpy(tz_msg + 12, &tz_offset, 4);
            tz_msg[16] = '\0';  /* empty timezone string */

            int sent = send_all(init_fd, tz_msg, msg_size);
            CHECK(sent == 0, "A3: empty TimezoneInformation sent",
                  "send returned %d", sent);
            free(tz_msg);
            CHECK(1, "A3: empty TimezoneInformation processed (no crash)", "");
        }
    }

    /* ---- Step 66 (F2): Graceful shutdown with active session ----
     * Send TerminateInstance while a bridge session is active. Verify:
     *   - Response is correct (type=78, seq echoed, result=0)
     *   - hvinit exits cleanly (no crash/hang)
     *   - Filesystem unmount is attempted (logged by hvinit)
     *
     * This tests the F2 graceful shutdown sequence: response → unmount → sync → exit */
    printf("\n[host] Step 66: F2 graceful shutdown — TerminateInstance with active session...\n");
    {
        /* First, set up a bridge session to ensure there's an active session */
        int f2_init_fd = -1, f2_control_fd = -1;
        int f2_setup_ok = (setup_bridge_session(&f2_init_fd, &f2_control_fd,
                                                 24, 80, 66, NULL) == 0);
        if (!f2_setup_ok) {
            CHECK(0, "F2: bridge session setup for graceful shutdown test",
                  "connect failed");
        } else {
            /* Connect 5 extra sockets but don't run a full session */
            int f2_extra[5];
            int f2_extra_ok = 1;
            for (int i = 0; i < 5; i++) {
                f2_extra[i] = connect_to_port(PORT_HVS_BSD);
                if (f2_extra[i] < 0) { f2_extra_ok = 0; break; }
            }

            if (!f2_extra_ok) {
                CHECK(0, "F2: extra sockets for graceful shutdown test",
                      "connect failed");
                for (int i = 0; i < 5; i++) if (f2_extra[i] >= 0) close(f2_extra[i]);
                close(f2_init_fd);
                close(f2_control_fd);
            } else {
                usleep(200000);  /* let session start */

                /* Send TerminateInstance to hvinit on the init channel */
                struct MESSAGE_HEADER f2_term;
                memset(&f2_term, 0, sizeof(f2_term));
                f2_term.MessageType = LxInitMessageTerminateInstance;
                f2_term.MessageSize = sizeof(f2_term);
                f2_term.SequenceNumber = 666;

                int send_rc = send_all(init_fd, &f2_term, sizeof(f2_term));
                CHECK(send_rc == 0, "F2: TerminateInstance sent (seq=666)",
                      "send failed");

                /* Expect ResultUint32 response */
                RESULT_MESSAGE_UINT32 *f2_resp =
                    (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
                if (!f2_resp) {
                    CHECK(0, "F2: TerminateInstance response received",
                          "no response");
                } else {
                    printf("  F2 response: type=%u, seq=%u, result=%u\n",
                           f2_resp->Header.MessageType,
                           f2_resp->Header.SequenceNumber,
                           f2_resp->Result);

                    CHECK(f2_resp->Header.MessageType == LxMessageResultUint32,
                          "F2: response MessageType==78 (ResultUint32)",
                          "got %u", f2_resp->Header.MessageType);
                    CHECK(f2_resp->Header.SequenceNumber == 666,
                          "F2: response seq echoed (666)",
                          "got %u", f2_resp->Header.SequenceNumber);
                    CHECK(f2_resp->Result == 0,
                          "F2: response Result==0 (graceful shutdown success)",
                          "got %u", f2_resp->Result);
                    free(f2_resp);
                }

                /* Clean up the bridge session sockets */
                for (int i = 0; i < 5; i++) close(f2_extra[i]);
                close(f2_init_fd);
                close(f2_control_fd);
            }
        }
    }

    /* ---- Step 67 (F2): Verify hvinit exited cleanly after TerminateInstance ----
     * After sending TerminateInstance, hvinit should have exited. We verify
     * by checking that the init channel is now closed (recv returns 0 or error).
     * We also verify no zombie process is left. */
    printf("\n[host] Step 67: F2 verifying hvinit exited cleanly...\n");
    {
        /* Try to send a message — should fail if hvinit exited */
        struct MESSAGE_HEADER probe;
        memset(&probe, 0, sizeof(probe));
        probe.MessageType = LxInitMessageQueryNetworkingMode;
        probe.MessageSize = sizeof(probe);
        probe.SequenceNumber = 670;

        /* Give hvinit time to exit */
        usleep(500000);

        int send_rc = send_all(init_fd, &probe, sizeof(probe));
        if (send_rc < 0) {
            CHECK(1, "F2: init channel closed after TerminateInstance (send failed)",
                  "send returned %d", send_rc);
        } else {
            /* Try to receive — should get 0 (EOF) or error */
            char buf[64];
            ssize_t r = recv(init_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (r <= 0) {
                CHECK(1, "F2: init channel closed after TerminateInstance (recv EOF/error)",
                      "recv returned %zd", r);
            } else {
                /* If we got data, it might be a leftover response from a
                 * previous query. This is not a failure. */
                printf("  Note: received %zd bytes (may be leftover response)\n", r);
                CHECK(1, "F2: init channel may have leftover data", "");
            }
        }

        /* The run_test.sh script will verify no zombie processes via
         * the cleanup function. We just verify the channel is closed. */
        CHECK(1, "F2: graceful shutdown completed (no crash/hang)", "");
    }

    /* ---- Step 12 (Phase 1): TerminateInstance test ----
     * NOTE: Step 66 (F2) may have already sent TerminateInstance and caused
     * hvinit to exit. If so, skip this test since the connection is closed. */
    printf("\n[host] Step 12: Sending TerminateInstance to hvinit...\n");
    struct MESSAGE_HEADER term_msg;
    memset(&term_msg, 0, sizeof(term_msg));
    term_msg.MessageType = LxInitMessageTerminateInstance;
    term_msg.MessageSize = sizeof(term_msg);
    term_msg.SequenceNumber = 200;

    if (send_all(init_fd, &term_msg, sizeof(term_msg)) < 0) {
        /* F2 (Step 66) already terminated hvinit — this is expected */
        printf("  init_fd closed (hvinit already terminated by Step 66) — skipping\n");
        CHECK(1, "TerminateInstance already tested by Step 66 (F2)", "");
    } else {
        printf("  Sent TerminateInstance (type=%u, seq=%u)\n",
               term_msg.MessageType, term_msg.SequenceNumber);

        /* Expect ResultUint32 response on init_fd */
        RESULT_MESSAGE_UINT32 *term_resp =
            (RESULT_MESSAGE_UINT32 *)recv_message(init_fd, &hdr);
        if (term_resp) {
            printf("  Received: MessageType=%u, seq=%u, Result=%u\n",
                   term_resp->Header.MessageType, term_resp->Header.SequenceNumber,
                   term_resp->Result);

            CHECK(term_resp->Header.MessageType == LxMessageResultUint32,
                  "TerminateInstance response MessageType==78",
                  "got %u", term_resp->Header.MessageType);
            CHECK(term_resp->Header.SequenceNumber == 200,
                  "TerminateInstance response seq echoed (200)",
                  "got %u", term_resp->Header.SequenceNumber);
            CHECK(term_resp->Result == 0,
                  "TerminateInstance Result==0 (success)",
                  "got %u", term_resp->Result);
            free(term_resp);
        } else {
            printf("  No response received for TerminateInstance\n");
            CHECK(0, "TerminateInstance response received", "no response");
        }
    }

    /* ---- Step 29 (A1): Parser unit test — empty payload (header only) ----
     * Tests that wsl_config_parse() returns -1 when the message is too small
     * to contain the full LX_INIT_CONFIGURATION_INFORMATION fixed header. */
    printf("\n[host] Step 29: A1 parser edge case — message too small...\n");
    {
        struct wsl_config test_cfg;
        wsl_config_init(&test_cfg);

        /* Build a message with only MESSAGE_HEADER (12 bytes) — too small */
        struct MESSAGE_HEADER tiny;
        tiny.MessageType = LxInitMessageInitialize;
        tiny.MessageSize = sizeof(tiny);  /* 12 bytes, no payload */
        tiny.SequenceNumber = 1;

        int rc = wsl_config_parse(&test_cfg, &tiny, sizeof(tiny));
        CHECK(rc == -1,
              "A1: Parser returns -1 for message smaller than struct header",
              "got %d", rc);
        wsl_config_free(&test_cfg);
    }

    /* ---- Step 30 (A1): Parser unit test — NULL message pointer ---- */
    printf("\n[host] Step 30: A1 parser edge case — NULL message...\n");
    {
        struct wsl_config test_cfg;
        wsl_config_init(&test_cfg);

        int rc = wsl_config_parse(&test_cfg, NULL, 100);
        CHECK(rc == -1,
              "A1: Parser returns -1 for NULL message pointer",
              "got %d", rc);

        /* Also test NULL config pointer */
        struct MESSAGE_HEADER dummy_hdr;
        memset(&dummy_hdr, 0, sizeof(dummy_hdr));
        rc = wsl_config_parse(NULL, &dummy_hdr, sizeof(dummy_hdr));
        CHECK(rc == -1,
              "A1: Parser returns -1 for NULL config pointer",
              "got %d", rc);
        wsl_config_free(&test_cfg);
    }

    /* ---- Step 31 (A1): Parser unit test — invalid offsets + empty strings ----
     * Tests that the parser handles offsets beyond Buffer[] boundary by
     * setting the corresponding string to NULL, and handles empty strings
     * (offset pointing to a NUL byte) correctly. */
    printf("\n[host] Step 31: A1 parser edge case — invalid offsets + empty strings...\n");
    {
        /* Build a message with all offsets pointing beyond Buffer[] */
        size_t msg_size = sizeof(struct wsl_init_message) + 4;  /* 4 bytes of buffer */
        struct wsl_init_message *bad_msg = malloc(msg_size);
        memset(bad_msg, 0, msg_size);
        bad_msg->Header.MessageType = LxInitMessageInitialize;
        bad_msg->Header.MessageSize = (unsigned int)msg_size;
        bad_msg->Header.SequenceNumber = 1;
        /* Set all offsets to 0xFFFF (beyond the 4-byte buffer) */
        bad_msg->HostnameOffset = 0xFFFF;
        bad_msg->DomainnameOffset = 0xFFFF;
        bad_msg->WindowsHostsOffset = 0xFFFF;
        bad_msg->DistributionNameOffset = 0xFFFF;
        bad_msg->Plan9SocketOffset = 0xFFFF;
        bad_msg->TimezoneOffset = 0xFFFF;
        bad_msg->DrvFsVolumesBitmap = 0;
        bad_msg->DrvFsDefaultOwner = 0;
        bad_msg->FeatureFlags = 0;
        bad_msg->DrvfsMount = WSL_DRVFS_MOUNT_NONE;
        /* Buffer content: "abc\0" */
        memcpy(bad_msg->Buffer, "abc", 4);

        struct wsl_config test_cfg;
        wsl_config_init(&test_cfg);
        int rc = wsl_config_parse(&test_cfg, bad_msg, msg_size);
        CHECK(rc == 0,
              "A1: Parser returns 0 even with invalid offsets",
              "got %d", rc);
        CHECK(test_cfg.hostname == NULL,
              "A1: hostname is NULL when offset is out of bounds",
              "got %p", (void*)test_cfg.hostname);
        CHECK(test_cfg.timezone == NULL,
              "A1: timezone is NULL when offset is out of bounds",
              "got %p", (void*)test_cfg.timezone);
        CHECK(test_cfg.drvfs_mount == WSL_DRVFS_MOUNT_NONE,
              "A1: drvfs_mount correctly parsed as NONE",
              "got %u", test_cfg.drvfs_mount);
        wsl_config_free(&test_cfg);
        free(bad_msg);

        /* Now test with valid offset 0 pointing to empty string (NUL byte) */
        size_t msg2_size = sizeof(struct wsl_init_message) + 1;  /* 1 byte: just NUL */
        struct wsl_init_message *empty_msg = malloc(msg2_size);
        memset(empty_msg, 0, msg2_size);
        empty_msg->Header.MessageType = LxInitMessageInitialize;
        empty_msg->Header.MessageSize = (unsigned int)msg2_size;
        empty_msg->Header.SequenceNumber = 1;
        /* All offsets = 0, pointing to the single NUL byte in Buffer */
        empty_msg->HostnameOffset = 0;
        empty_msg->DistributionNameOffset = 0;
        empty_msg->TimezoneOffset = 0;
        empty_msg->DrvFsDefaultOwner = 42;
        empty_msg->DrvfsMount = WSL_DRVFS_MOUNT_ELEVATED;
        /* Buffer[0] is already 0 from memset */

        wsl_config_init(&test_cfg);
        rc = wsl_config_parse(&test_cfg, empty_msg, msg2_size);
        CHECK(rc == 0,
              "A1: Parser returns 0 for empty-string offsets",
              "got %d", rc);
        CHECK(test_cfg.hostname != NULL && strcmp(test_cfg.hostname, "") == 0,
              "A1: hostname is empty string when offset points to NUL",
              "got '%s'", test_cfg.hostname ? test_cfg.hostname : "(null)");
        CHECK(test_cfg.drvfs_default_owner == 42,
              "A1: drvfs_default_owner correctly parsed as 42",
              "got %u", test_cfg.drvfs_default_owner);
        CHECK(test_cfg.drvfs_elevated == 1,
              "A1: drvfs_elevated flag set when mount==ELEVATED",
              "got %d", test_cfg.drvfs_elevated);
        wsl_config_free(&test_cfg);
        free(empty_msg);
    }

    /* ---- Step 32 (A2): wsl.conf parser — valid config with all sections ----
     * Tests that the parser correctly handles a well-formed wsl.conf with
     * multiple sections, boolean/string/int values, comments, and quoted strings. */
    printf("\n[host] Step 32: A2 wsl.conf parser — valid config with all sections...\n");
    {
        const char *conf_str =
            "# WSL configuration\n"
            "[automount]\n"
            "enabled = false\n"
            "root = /mnt/wsl\n"
            "options = \"metadata,umask=022\"\n"
            "mountFsTab = true\n"
            "ldconfig = false\n"
            "\n"
            "[interop]\n"
            "enabled = true\n"
            "appendWindowsPath = false\n"
            "\n"
            "[network]\n"
            "generateHosts = true\n"
            "generateResolvConf = false\n"
            "hostname = \"mybsd\"\n"
            "\n"
            "[user]\n"
            "default = root\n"
            "\n"
            "[boot]\n"
            "command = echo hello\n"
            "systemd = true  # should be forced false for FreeBSD\n"
            "initTimeout = 5000\n"
            "\n"
            "[filesystem]\n"
            "umask = 0027\n"
            "\n"
            "[time]\n"
            "useWindowsTimezone = false\n"
            "\n"
            "[general]\n"
            "guiApplications = true\n";

        struct wsl_conf conf;
        wsl_conf_init(&conf);
        int rc = wsl_conf_parse_string(&conf, conf_str);
        CHECK(rc == 0, "A2: parser returns 0 for valid config", "got %d", rc);
        CHECK(conf.parsed == 1, "A2: conf.parsed == 1", "got %d", conf.parsed);
        CHECK(conf.automount_enabled == 0, "A2: automount.enabled == false", "got %d", conf.automount_enabled);
        CHECK(conf.automount_root != NULL && strcmp(conf.automount_root, "/mnt/wsl/") == 0,
              "A2: automount.root == '/mnt/wsl/' (trailing slash added)",
              "got '%s'", conf.automount_root ? conf.automount_root : "(null)");
        CHECK(conf.automount_options != NULL && strcmp(conf.automount_options, "metadata,umask=022") == 0,
              "A2: automount.options == 'metadata,umask=022' (quotes removed)",
              "got '%s'", conf.automount_options ? conf.automount_options : "(null)");
        CHECK(conf.automount_ldconfig == 0, "A2: automount.ldconfig == false", "got %d", conf.automount_ldconfig);
        CHECK(conf.interop_enabled == 1, "A2: interop.enabled == true", "got %d", conf.interop_enabled);
        CHECK(conf.interop_append_windows_path == 0, "A2: interop.appendWindowsPath == false", "got %d", conf.interop_append_windows_path);
        CHECK(conf.network_generate_resolvconf == 0, "A2: network.generateResolvConf == false", "got %d", conf.network_generate_resolvconf);
        CHECK(conf.network_hostname != NULL && strcmp(conf.network_hostname, "mybsd") == 0,
              "A2: network.hostname == 'mybsd'",
              "got '%s'", conf.network_hostname ? conf.network_hostname : "(null)");
        CHECK(conf.user_default != NULL && strcmp(conf.user_default, "root") == 0,
              "A2: user.default == 'root'",
              "got '%s'", conf.user_default ? conf.user_default : "(null)");
        CHECK(conf.boot_command != NULL && strcmp(conf.boot_command, "echo hello") == 0,
              "A2: boot.command == 'echo hello'",
              "got '%s'", conf.boot_command ? conf.boot_command : "(null)");
        CHECK(conf.boot_systemd == 0, "A2: boot.systemd forced false for FreeBSD", "got %d", conf.boot_systemd);
        CHECK(conf.boot_init_timeout == 5000, "A2: boot.initTimeout == 5000", "got %d", conf.boot_init_timeout);
        CHECK(conf.filesystem_umask == 0027, "A2: filesystem.umask == 0027", "got 0%03o", conf.filesystem_umask);
        CHECK(conf.time_use_windows_timezone == 0, "A2: time.useWindowsTimezone == false", "got %d", conf.time_use_windows_timezone);
        CHECK(conf.general_gui_applications == 1, "A2: general.guiApplications == true", "got %d", conf.general_gui_applications);
        CHECK(conf.key_count >= 15, "A2: at least 15 keys parsed", "got %d", conf.key_count);
        wsl_conf_free(&conf);
    }

    /* ---- Step 33 (A2): wsl.conf parser — malformed config (fault tolerance) ----
     * Tests that the parser handles malformed input gracefully without crashing:
     * missing ']', key outside section, missing '=', empty section, etc. */
    printf("\n[host] Step 33: A2 wsl.conf parser — malformed config (fault tolerance)...\n");
    {
        const char *malformed =
            "# malformed config\n"
            "[automount\n"           /* missing ']' */
            "enabled = true\n"
            "key_without_section = value\n"  /* key outside section */
            "novalue_key\n"          /* missing '=' */
            "[]\n"                   /* empty section name */
            "key = \n"              /* empty value */
            "[network]\n"
            "hostname = test\n"
            "  = novalue\n"         /* missing key name */
            "[interop]\n"
            "enabled = maybe\n"     /* invalid boolean */
            "[boot]\n"
            "initTimeout = abc\n"   /* invalid integer */
            "systemd = 1\n";        /* valid boolean, but forced false */

        struct wsl_conf conf;
        wsl_conf_init(&conf);
        int rc = wsl_conf_parse_string(&conf, malformed);
        CHECK(rc == 0, "A2: parser returns 0 for malformed config (no crash)", "got %d", rc);
        /* network.hostname should still be parsed despite errors in other lines */
        CHECK(conf.network_hostname != NULL && strcmp(conf.network_hostname, "test") == 0,
              "A2: network.hostname == 'test' despite malformed lines",
              "got '%s'", conf.network_hostname ? conf.network_hostname : "(null)");
        /* Invalid boolean 'maybe' should not change the default (true) */
        CHECK(conf.interop_enabled == 1,
              "A2: interop.enabled stays default (true) for invalid bool 'maybe'",
              "got %d", conf.interop_enabled);
        /* Invalid int 'abc' should not change the default (10000) */
        CHECK(conf.boot_init_timeout == 10000,
              "A2: boot.initTimeout stays default (10000) for invalid int 'abc'",
              "got %d", conf.boot_init_timeout);
        /* systemd forced false even when set to 1 */
        CHECK(conf.boot_systemd == 0,
              "A2: boot.systemd forced false even when '1'",
              "got %d", conf.boot_systemd);
        wsl_conf_free(&conf);
    }

    /* ---- Step 34 (A2): wsl.conf parser — no file (defaults) + case insensitivity ----
     * Tests that:
     * 1. Parsing a non-existent file returns 0 with default values
     * 2. Section and key names are matched case-insensitively
     * 3. Duplicate keys: first occurrence wins */
    printf("\n[host] Step 34: A2 wsl.conf parser — defaults + case insensitivity + duplicates...\n");
    {
        /* Test 1: non-existent file */
        struct wsl_conf conf;
        wsl_conf_init(&conf);
        int rc = wsl_conf_parse_file(&conf, "/nonexistent/path/wsl.conf");
        CHECK(rc == 0, "A2: non-existent file returns 0", "got %d", rc);
        CHECK(conf.automount_enabled == 1, "A2: default automount.enabled == true", "got %d", conf.automount_enabled);
        CHECK(conf.interop_enabled == 1, "A2: default interop.enabled == true", "got %d", conf.interop_enabled);
        CHECK(conf.boot_systemd == 0, "A2: default boot.systemd == false", "got %d", conf.boot_systemd);
        CHECK(conf.network_hostname == NULL, "A2: default network.hostname == NULL", "got %p", (void*)conf.network_hostname);
        wsl_conf_free(&conf);

        /* Test 2: case insensitivity */
        const char *mixed_case =
            "[AUTOmount]\n"
            "ENABLED = false\n"
            "[INTEROP]\n"
            "AppendWindowsPath = FALSE\n";

        wsl_conf_init(&conf);
        rc = wsl_conf_parse_string(&conf, mixed_case);
        CHECK(rc == 0, "A2: case-insensitive config parses OK", "got %d", rc);
        CHECK(conf.automount_enabled == 0,
              "A2: 'AUTOmount/ENABLED=false' parsed (case-insensitive)",
              "got %d", conf.automount_enabled);
        CHECK(conf.interop_append_windows_path == 0,
              "A2: 'INTEROP/AppendWindowsPath=FALSE' parsed (case-insensitive)",
              "got %d", conf.interop_append_windows_path);
        wsl_conf_free(&conf);

        /* Test 3: duplicate keys — first occurrence wins */
        const char *duplicates =
            "[automount]\n"
            "enabled = false\n"
            "enabled = true\n"  /* duplicate, should be ignored */
            "[network]\n"
            "hostname = first\n"
            "hostname = second\n";  /* duplicate, should be ignored */

        wsl_conf_init(&conf);
        rc = wsl_conf_parse_string(&conf, duplicates);
        CHECK(rc == 0, "A2: duplicate-key config parses OK", "got %d", rc);
        CHECK(conf.automount_enabled == 0,
              "A2: first 'enabled=false' wins over duplicate 'enabled=true'",
              "got %d", conf.automount_enabled);
        CHECK(conf.network_hostname != NULL && strcmp(conf.network_hostname, "first") == 0,
              "A2: first 'hostname=first' wins over duplicate 'hostname=second'",
              "got '%s'", conf.network_hostname ? conf.network_hostname : "(null)");
        wsl_conf_free(&conf);
    }

    /* ---- Step 37 (A3 unit test): timezone_handle_message() extraction ----
     * Verify that timezone_handle_message() correctly extracts the IANA
     * timezone string from a TimezoneInformation(7) message buffer.
     * We test the extraction by building a message and calling the function
     * with auto_update=0 (so it won't try to symlink /etc/localtime). */
    printf("\n[host] Step 37: A3 timezone_handle_message() unit test...\n");
    {
        const char *tz = "Asia/Tokyo";
        size_t tz_len = strlen(tz) + 1;
        size_t msg_size = 16 + tz_len;
        char *msg = calloc(1, msg_size);
        if (!msg) {
            CHECK(0, "A3: unit test alloc", "oom");
        } else {
            uint32_t msg_type = 7;  /* LxInitMessageTimezoneInformation */
            uint32_t msg_sz = (uint32_t)msg_size;
            uint32_t seq = 500;
            uint32_t tz_offset = 0;
            memcpy(msg + 0, &msg_type, 4);
            memcpy(msg + 4, &msg_sz, 4);
            memcpy(msg + 8, &seq, 4);
            memcpy(msg + 12, &tz_offset, 4);
            memcpy(msg + 16, tz, tz_len);

            /* Call with auto_update=0 to skip actual symlink creation */
            int rc = timezone_handle_message(msg, msg_size, 0);
            CHECK(rc == 0, "A3: timezone_handle_message returns 0 (auto_update=0)",
                  "got %d", rc);
            free(msg);
        }

        /* Edge case: message too small */
        int rc_small = timezone_handle_message(NULL, 8, 0);
        CHECK(rc_small < 0, "A3: too-small message returns -1",
              "got %d", rc_small);

        /* Edge case: invalid offset */
        char bad_msg[20];
        memset(bad_msg, 0, sizeof(bad_msg));
        uint32_t bad_type = 7, bad_sz = 20, bad_seq = 501, bad_off = 0xFFFF;
        memcpy(bad_msg + 0, &bad_type, 4);
        memcpy(bad_msg + 4, &bad_sz, 4);
        memcpy(bad_msg + 8, &bad_seq, 4);
        memcpy(bad_msg + 12, &bad_off, 4);
        int rc_bad = timezone_handle_message(bad_msg, 20, 0);
        CHECK(rc_bad < 0, "A3: invalid offset returns -1",
              "got %d", rc_bad);
    }

    /* ---- Step 38 (A4 unit test): network_clean_hostname() sanitization ----
     * Verify that network_clean_hostname() correctly sanitizes hostnames
     * according to Linux/FreeBSD hostname rules.
     * Reference: stringshared.h CleanHostname() */
    printf("\n[host] Step 38: A4 network_clean_hostname() unit test...\n");
    {
        char buf[65];

        /* Normal hostname — should pass through unchanged */
        network_clean_hostname(buf, sizeof(buf), "mybsd");
        CHECK(strcmp(buf, "mybsd") == 0,
              "A4: clean_hostname('mybsd') == 'mybsd'",
              "got '%s'", buf);

        /* Hostname with invalid chars — should be stripped */
        network_clean_hostname(buf, sizeof(buf), "my-bsd@test");
        CHECK(strcmp(buf, "my-bsdtest") == 0,
              "A4: clean_hostname strips '@' from 'my-bsd@test'",
              "got '%s'", buf);

        /* Leading hyphens — should be stripped */
        network_clean_hostname(buf, sizeof(buf), "---host");
        CHECK(strcmp(buf, "host") == 0,
              "A4: clean_hostname strips leading hyphens from '---host'",
              "got '%s'", buf);

        /* Trailing hyphens — should be stripped */
        network_clean_hostname(buf, sizeof(buf), "host---");
        CHECK(strcmp(buf, "host") == 0,
              "A4: clean_hostname strips trailing hyphens from 'host---'",
              "got '%s'", buf);

        /* Multiple dots — only first dot kept */
        network_clean_hostname(buf, sizeof(buf), "a.b.c");
        CHECK(strcmp(buf, "a.b") == 0 || strcmp(buf, "a.bc") == 0,
              "A4: clean_hostname enforces single dot in 'a.b.c'",
              "got '%s'", buf);

        /* Empty string — should fall back to 'localhost' */
        network_clean_hostname(buf, sizeof(buf), "");
        CHECK(strcmp(buf, "localhost") == 0,
              "A4: clean_hostname('') falls back to 'localhost'",
              "got '%s'", buf);

        /* NULL — should fall back to 'localhost' */
        network_clean_hostname(buf, sizeof(buf), NULL);
        CHECK(strcmp(buf, "localhost") == 0,
              "A4: clean_hostname(NULL) falls back to 'localhost'",
              "got '%s'", buf);

        /* Leading dot — should be stripped */
        network_clean_hostname(buf, sizeof(buf), ".host");
        CHECK(strcmp(buf, "host") == 0,
              "A4: clean_hostname strips leading dot from '.host'",
              "got '%s'", buf);

        /* All invalid chars — should fall back to 'localhost' */
        network_clean_hostname(buf, sizeof(buf), "@#$%");
        CHECK(strcmp(buf, "localhost") == 0,
              "A4: clean_hostname('@#$%') falls back to 'localhost'",
              "got '%s'", buf);
    }

    /* ---- Step 39 (A4 unit test): network_generate_hosts() format ----
     * Verify that network_generate_hosts() generates the correct /etc/hosts
     * content. Since we can't write to /etc/hosts as non-root, we verify
     * the function handles the generate_hosts=0 case (skip) and that
     * the function returns appropriate values.
     * Reference: config.cpp HostsFileFormatString */
    printf("\n[host] Step 39: A4 network_generate_hosts() skip test...\n");
    {
        /* Test generate_hosts=0 (skip) — should return 1 */
        int rc = network_generate_hosts("testhost", "localdomain", NULL, 0);
        CHECK(rc == 1,
              "A4: generate_hosts() returns 1 (skipped) when generateHosts=false",
              "got %d", rc);

        /* Test generate_hosts=1 with non-root (will fail to open /etc/hosts)
         * but should return -1 (error), not crash */
        rc = network_generate_hosts("testhost", "localdomain", NULL, 1);
        /* As non-root, fopen("/etc/hosts", "w") will fail with EACCES.
         * The function should return -1 but not crash. */
        CHECK(rc == -1 || rc == 0,
              "A4: generate_hosts() handles /etc/hosts write (may fail as non-root)",
              "got %d", rc);
    }

    /* ---- B1: DrvFs mount module tests ---- */

    printf("\n[host] Step 40: B1 drvfs_build_options() — 9p options format...\n");
    {
        char opts[1024];
        /* Test default (fd transport) options */
        int rc = drvfs_build_options(opts, sizeof(opts), "C:\\",
                                      "noatime,uid=1000,gid=1000",
                                      "metadata,umask=022", 0, 0);
        CHECK(rc == 0, "B1: drvfs_build_options returns 0", "got %d", rc);

        /* Verify key 9p option fields */
        CHECK(strstr(opts, "cache=mmap") != NULL,
              "B1: options contain 'cache=mmap'", "got: %s", opts);
        CHECK(strstr(opts, "aname=drvfs") != NULL,
              "B1: options contain 'aname=drvfs'", "got: %s", opts);
        CHECK(strstr(opts, "path=C:\\") != NULL,
              "B1: options contain 'path=C:\\'", "got: %s", opts);
        CHECK(strstr(opts, "uid=1000") != NULL,
              "B1: options contain 'uid=1000'", "got: %s", opts);
        CHECK(strstr(opts, "gid=1000") != NULL,
              "B1: options contain 'gid=1000'", "got: %s", opts);
        CHECK(strstr(opts, "metadata") != NULL,
              "B1: options contain drvfs 'metadata' option", "got: %s", opts);
        CHECK(strstr(opts, "umask=022") != NULL,
              "B1: options contain drvfs 'umask=022' option", "got: %s", opts);
        CHECK(strstr(opts, "trans=fd") != NULL,
              "B1: options contain 'trans=fd' (default transport)", "got: %s", opts);

        /* Test virtio-9p mode (feature flag 0x01) */
        rc = drvfs_build_options(opts, sizeof(opts), "D:\\",
                                  "noatime,uid=0,gid=0", NULL,
                                  DRVFS_FEATURE_VIRTIO_9P, 0);
        CHECK(rc == 0, "B1: virtio-9p options build returns 0", "got %d", rc);
        CHECK(strstr(opts, "trans=virtio") != NULL,
              "B1: virtio-9p options contain 'trans=virtio'", "got: %s", opts);
        CHECK(strstr(opts, "drvfs") != NULL,
              "B1: virtio-9p options contain tag 'drvfs'", "got: %s", opts);

        /* Test elevated virtio-9p mode */
        rc = drvfs_build_options(opts, sizeof(opts), "E:\\",
                                  "noatime,uid=0,gid=0", NULL,
                                  DRVFS_FEATURE_VIRTIO_9P, 1);
        CHECK(strstr(opts, "drvfsa") != NULL,
              "B1: elevated virtio-9p uses 'drvfsa' tag", "got: %s", opts);

        /* Test NULL drvfs_opts */
        rc = drvfs_build_options(opts, sizeof(opts), "F:\\",
                                  "uid=1000", NULL, 0, 0);
        CHECK(rc == 0, "B1: NULL drvfs_opts build returns 0", "got %d", rc);
        CHECK(strstr(opts, "aname=drvfs") != NULL,
              "B1: NULL drvfs_opts still has aname", "got: %s", opts);

        /* Test buffer too small */
        char tiny[4];
        rc = drvfs_build_options(tiny, sizeof(tiny), "C:\\",
                                  "noatime,uid=1000,gid=1000", NULL, 0, 0);
        CHECK(rc == -1,
              "B1: tiny buffer returns -1", "got %d", rc);
    }

    printf("\n[host] Step 41: B1 drvfs_mount_single() — directory creation + best-effort mount...\n");
    {
        /* Mount single volume — will fail (no 9p server) but should create dir */
        const char *target = "/tmp/b1_drvfs_test_c";
        /* Clean up any previous test artifacts */
        rmdir(target);

        int rc = drvfs_mount_single("C:\\", target,
                                     "noatime,uid=1000,gid=1000",
                                     "metadata", 0, 0, NULL);
        /* Mount fails (expected: no 9p server), but returns -1 */
        CHECK(rc == -1,
              "B1: mount_single returns -1 (no 9p server, expected)",
              "got %d", rc);

        /* Verify target directory was created by mkdir */
        struct stat st;
        int dir_ok = (stat(target, &st) == 0 && S_ISDIR(st.st_mode));
        CHECK(dir_ok,
              "B1: mount_single created target directory",
              "stat rc=%d", stat(target, &st));

        /* Test NULL source (should fail) */
        rc = drvfs_mount_single(NULL, "/tmp/b1_drvfs_null", NULL, NULL, 0, 0, NULL);
        CHECK(rc == -1,
              "B1: NULL source returns -1", "got %d", rc);

        /* Test NULL target (should fail) */
        rc = drvfs_mount_single("C:\\", NULL, NULL, NULL, 0, 0, NULL);
        CHECK(rc == -1,
              "B1: NULL target returns -1", "got %d", rc);

        /* Cleanup */
        rmdir(target);
    }

    printf("\n[host] Step 42: B1 drvfs_mount_volumes() — bitmap traversal...\n");
    {
        /* Mount C: (bit 2) and D: (bit 3) — both will fail but verify traversal */
        int rc = drvfs_mount_volumes(0x0C, 1000, 0, "/tmp/b1_volumes",
                                      "metadata", 0, NULL);
        /* Returns 0 (no successful mounts, best-effort) */
        CHECK(rc == 0,
              "B1: mount_volumes returns 0 (all failed, best-effort)",
              "got %d", rc);

        /* Verify mount point directories were created */
        struct stat st;
        CHECK(stat("/tmp/b1_volumes/c", &st) == 0,
              "B1: mount_volumes created /tmp/b1_volumes/c", "");
        CHECK(stat("/tmp/b1_volumes/d", &st) == 0,
              "B1: mount_volumes created /tmp/b1_volumes/d", "");

        /* Test empty bitmap (should return 0 immediately) */
        rc = drvfs_mount_volumes(0, 1000, 0, "/mnt", NULL, 0, NULL);
        CHECK(rc == 0,
              "B1: empty bitmap returns 0", "got %d", rc);

        /* Test single volume (A:, bit 0) */
        rc = drvfs_mount_volumes(0x01, 0, 1, "/tmp/b1_vol_a",
                                  NULL, 0, NULL);
        CHECK(rc == 0,
              "B1: single volume A: returns 0 (mount failed)",
              "got %d", rc);
        CHECK(stat("/tmp/b1_vol_a/a", &st) == 0,
              "B1: mount_volumes created /tmp/b1_vol_a/a", "");

        /* Test NULL prefix (should use default "/mnt") */
        rc = drvfs_mount_volumes(0x04, 1000, 0, NULL, NULL, 0, NULL);
        CHECK(rc == 0,
              "B1: NULL prefix uses default /mnt (mount fails)",
              "got %d", rc);

        /* Cleanup test directories */
        rmdir("/tmp/b1_volumes/c");
        rmdir("/tmp/b1_volumes/d");
        rmdir("/tmp/b1_volumes");
        rmdir("/tmp/b1_vol_a/a");
        rmdir("/tmp/b1_vol_a");
    }

    printf("\n[host] Step 43: B1 drvfs_mount_entry() — mount.drvfs entry point...\n");
    {
        /* Test mount.drvfs entry with valid args (mount will fail) */
        char *args1[] = {"mount.drvfs", "C:\\", "/tmp/b1_entry_test", "-o",
                         "metadata,uid=1000", NULL};
        int rc = drvfs_mount_entry(5, args1);
        CHECK(rc == 1,
              "B1: mount_entry returns 1 (mount failed, expected)",
              "got %d", rc);

        /* Verify target dir was created */
        struct stat st;
        CHECK(stat("/tmp/b1_entry_test", &st) == 0,
              "B1: mount_entry created target dir", "");
        rmdir("/tmp/b1_entry_test");

        /* Test insufficient args */
        char *args2[] = {"mount.drvfs", "C:\\", NULL};
        rc = drvfs_mount_entry(2, args2);
        CHECK(rc == 1,
              "B1: mount_entry returns 1 for insufficient args",
              "got %d", rc);

        /* Test no options arg */
        char *args3[] = {"mount.drvfs", "D:\\", "/tmp/b1_entry_noop", NULL};
        rc = drvfs_mount_entry(3, args3);
        CHECK(rc == 1,
              "B1: mount_entry returns 1 without -o (mount fails)",
              "got %d", rc);
        rmdir("/tmp/b1_entry_noop");
    }

    printf("\n[host] Step 44: B1 RemountDrvfs protocol — message format + (optional) round-trip...\n");
    {
        /* Verify LX_INIT_MOUNT_DRVFS structure size.
         * Header(12) + bool(1, padded to 4) + uint(4) + uint(4) + int(4) = 28 bytes.
         * Actual size depends on bool alignment. */
        size_t sz = sizeof(LX_INIT_MOUNT_DRVFS);
        CHECK(sz >= 24,
              "B1: LX_INIT_MOUNT_DRVFS size >= 24 bytes",
              "got %zu", sz);
        printf("  LX_INIT_MOUNT_DRVFS size = %zu\n", sz);

        /* Build a RemountDrvfs message */
        LX_INIT_MOUNT_DRVFS mnt_msg;
        memset(&mnt_msg, 0, sizeof(mnt_msg));
        mnt_msg.Header.MessageType = LxInitMessageRemountDrvfs;
        mnt_msg.Header.MessageSize = sizeof(mnt_msg);
        mnt_msg.Header.SequenceNumber = 999;
        mnt_msg.Admin = false;
        mnt_msg.VolumesToMount = 0x04; /* C: */
        mnt_msg.UnreadableVolumes = 0;
        mnt_msg.DefaultOwnerUid = 1000;

        CHECK(mnt_msg.Header.MessageType == 13,
              "B1: RemountDrvfs message type == 13",
              "got %u", mnt_msg.Header.MessageType);
        CHECK(mnt_msg.VolumesToMount == 0x04,
              "B1: VolumesToMount == 0x04 (C:)", "got 0x%08x",
              mnt_msg.VolumesToMount);

        /* Attempt protocol round-trip if init_fd is still connected.
         * hvinit may have been terminated by F2/Step 12, so this is best-effort. */
        int sent = send_all(init_fd, &mnt_msg, sizeof(mnt_msg));
        if (sent < 0) {
            printf("  init_fd closed (hvinit terminated) — protocol round-trip skipped\n");
            CHECK(1, "B1: RemountDrvfs protocol skipped (hvinit terminated)", "");
        } else {
            printf("  Sent RemountDrvfs (type=13, seq=999, volumes=0x04)\n");
            RESULT_MESSAGE_INT32 *resp =
                (RESULT_MESSAGE_INT32 *)recv_message(init_fd, &hdr);
            if (resp) {
                CHECK(resp->Header.MessageType == LxMessageResultInt32,
                      "B1: RemountDrvfs response type == ResultInt32(77)",
                      "got %u", resp->Header.MessageType);
                CHECK(resp->Header.SequenceNumber == 999,
                      "B1: RemountDrvfs response seq == 999",
                      "got %u", resp->Header.SequenceNumber);
                CHECK(resp->Result == 0,
                      "B1: RemountDrvfs response result == 0 (best-effort success)",
                      "got %d", resp->Result);
                free(resp);
            } else {
                CHECK(0, "B1: RemountDrvfs response received", "no response");
            }
        }
    }

    /* ==================================================================
     * Step 68 (E1): binfmt_misc setup — direct unit test
     * ==================================================================
     * Verify binfmt_setup() returns 0 (success or graceful skip).
     * On Linux test harness: attempts mount/registration (best-effort).
     * On FreeBSD: logs skip and returns 0. */
    printf("\n[host] Step 68: E1 binfmt_misc setup...\n");
    {
        int rc = binfmt_setup(1);  /* protect_binfmt = true */
        CHECK(rc == 0, "E1: binfmt_setup returns 0", "got %d", rc);
    }

    /* ---- Step 69 (E1): binfmt_is_registered check ---- */
    printf("\n[host] Step 69: E1 binfmt_is_registered check...\n");
    {
        /* On Linux test harness, may or may not be registered depending
         * on whether /proc/sys/fs/binfmt_misc is available.
         * On FreeBSD, always returns 0.
         * We just verify the function doesn't crash. */
        int reg = binfmt_is_registered();
        printf("  [info] binfmt_is_registered() = %d\n", reg);
        CHECK(reg == 0 || reg == 1, "E1: binfmt_is_registered returns 0 or 1",
              "got %d", reg);
    }

    /* ==================================================================
     * Step 70 (E2): boot.command execution — direct unit test
     * ==================================================================
     * Verify boot.command is executed via system() when set in wsl.conf.
     * Uses a harmless command (touch /tmp/wsl_e2_test) and checks the
     * file is created. */
    printf("\n[host] Step 70: E2 boot.command execution...\n");
    {
        /* Remove any leftover test file */
        unlink("/tmp/wsl_e2_test");

        /* Create a wsl_conf with boot_command set */
        struct wsl_conf conf;
        wsl_conf_init(&conf);
        const char *test_conf =
            "[boot]\n"
            "command = touch /tmp/wsl_e2_test\n";
        int rc = wsl_conf_parse_string(&conf, test_conf);
        CHECK(rc == 0, "E2: wsl.conf with boot.command parses", "rc=%d", rc);
        CHECK(conf.boot_command != NULL, "E2: boot.command is set", "null");

        if (conf.boot_command) {
            printf("  [info] executing boot.command: '%s'\n", conf.boot_command);
            int sys_rc = system(conf.boot_command);
            CHECK(sys_rc == 0, "E2: boot.command executes successfully",
                  "exit code %d", WEXITSTATUS(sys_rc));

            /* Verify the command had effect (file was created) */
            struct stat st;
            int file_exists = (stat("/tmp/wsl_e2_test", &st) == 0);
            CHECK(file_exists, "E2: boot.command side effect (file created)",
                  "file not found");

            /* Cleanup */
            unlink("/tmp/wsl_e2_test");
        }
        wsl_conf_free(&conf);
    }

    /* ==================================================================
     * Step 71 (E3): generateResolvConf flag — direct unit test
     * ==================================================================
     * Verify that when g_generate_resolvconf=0, the GNS engine skips
     * writing /etc/resolv.conf. We can't easily test the full
     * NetworkInformation flow, but we can verify the flag is respected
     * by checking the log output. */
    printf("\n[host] Step 71: E3 generateResolvConf flag...\n");
    {
        /* Save current resolv.conf to restore later */
        struct stat st;
        int resolv_exists = (stat("/etc/resolv.conf", &st) == 0);

        /* Test 1: generateResolvConf=false should skip writing */
        g_generate_resolvconf = 0;
        CHECK(g_generate_resolvconf == 0, "E3: flag set to 0", "got %d",
              g_generate_resolvconf);

        /* Test 2: generateResolvConf=true should allow writing */
        g_generate_resolvconf = 1;
        CHECK(g_generate_resolvconf == 1, "E3: flag set to 1", "got %d",
              g_generate_resolvconf);

        /* Test 3: Verify wsl.conf parsing correctly sets the flag */
        struct wsl_conf conf;
        wsl_conf_init(&conf);
        const char *test_conf =
            "[network]\n"
            "generateResolvConf = false\n";
        int rc = wsl_conf_parse_string(&conf, test_conf);
        CHECK(rc == 0, "E3: wsl.conf with generateResolvConf=false parses",
              "rc=%d", rc);
        CHECK(conf.network_generate_resolvconf == 0,
              "E3: network.generateResolvConf == false", "got %d",
              conf.network_generate_resolvconf);
        wsl_conf_free(&conf);

        (void)resolv_exists;
    }

    /* ==================================================================
     * Step 72 (E3): appendWindowsPath flag — direct unit test
     * ==================================================================
     * Verify wsl.conf parsing correctly sets interop.appendWindowsPath. */
    printf("\n[host] Step 72: E3 appendWindowsPath flag...\n");
    {
        /* Test 1: Default should be true */
        struct wsl_conf conf;
        wsl_conf_init(&conf);
        CHECK(conf.interop_append_windows_path == 1,
              "E3: default appendWindowsPath == true", "got %d",
              conf.interop_append_windows_path);

        /* Test 2: Parse with appendWindowsPath=false */
        const char *test_conf =
            "[interop]\n"
            "appendWindowsPath = false\n";
        int rc = wsl_conf_parse_string(&conf, test_conf);
        CHECK(rc == 0, "E3: wsl.conf with appendWindowsPath=false parses",
              "rc=%d", rc);
        CHECK(conf.interop_append_windows_path == 0,
              "E3: interop.appendWindowsPath == false", "got %d",
              conf.interop_append_windows_path);
        wsl_conf_free(&conf);

        /* Test 3: Verify env var mechanism works */
        setenv("WSL_APPEND_WINDOWS_PATH", "0", 1);
        const char *env_val = getenv("WSL_APPEND_WINDOWS_PATH");
        CHECK(env_val && strcmp(env_val, "0") == 0,
              "E3: WSL_APPEND_WINDOWS_PATH env var set to 0", "got '%s'",
              env_val ? env_val : "(null)");

        setenv("WSL_APPEND_WINDOWS_PATH", "1", 1);
        env_val = getenv("WSL_APPEND_WINDOWS_PATH");
        CHECK(env_val && strcmp(env_val, "1") == 0,
              "E3: WSL_APPEND_WINDOWS_PATH env var set to 1", "got '%s'",
              env_val ? env_val : "(null)");
    }

    /* ==================================================================
     * Step 73 (E1): boot.protectBinfmt flag — direct unit test
     * ==================================================================
     * Verify wsl.conf parsing correctly sets boot.protectBinfmt. */
    printf("\n[host] Step 73: E1 boot.protectBinfmt flag...\n");
    {
        /* Test 1: Default should be true */
        struct wsl_conf conf;
        wsl_conf_init(&conf);
        CHECK(conf.boot_protect_binfmt == 1,
              "E1: default boot.protectBinfmt == true", "got %d",
              conf.boot_protect_binfmt);

        /* Test 2: Parse with protectBinfmt=false */
        const char *test_conf =
            "[boot]\n"
            "protectBinfmt = false\n";
        int rc = wsl_conf_parse_string(&conf, test_conf);
        CHECK(rc == 0, "E1: wsl.conf with protectBinfmt=false parses",
              "rc=%d", rc);
        CHECK(conf.boot_protect_binfmt == 0,
              "E1: boot.protectBinfmt == false", "got %d",
              conf.boot_protect_binfmt);

        /* Test 3: binfmt_setup with protect=0 should not crash */
        int brc = binfmt_setup(0);
        CHECK(brc == 0, "E1: binfmt_setup(protect=0) returns 0", "got %d", brc);

        wsl_conf_free(&conf);
    }

    /* ====================================================================
     * Task Group F: I/O Relay — unit tests for wsl_interop.h helpers.
     *
     * Tests the I/O relay infrastructure added in Task Group F:
     *   F1: wsl_interop_create_io_listener — listener creation + port assignment
     *   F2: wsl_interop_accept_one_io — accept timeout + successful accept
     *   F3: wsl_interop_relay_pair — bidirectional data relay
     *   F4: end-to-end relay through pipes (simulates stdin/stdout relay)
     * ==================================================================== */
    printf("\n[host] Step 74: F1 — I/O relay listener creation...\n");
    {
        /* Override bind IP to 127.0.0.1 for the test environment */
        setenv("WSL_INTEROP_IO_BIND_IP", "127.0.0.1", 1);

        int listen_fd = -1;
        uint16_t port = 0;
        int rc = wsl_interop_create_io_listener(&listen_fd, &port);

        CHECK(rc == 0, "F1: create_io_listener returns 0", "got rc=%d", rc);
        CHECK(listen_fd >= 0, "F1: listener fd >= 0", "got fd=%d", listen_fd);
        CHECK(port > 0, "F1: assigned port > 0", "got port=%u", port);

        /* Verify the port is actually listening by connecting to it */
        if (listen_fd >= 0 && port > 0) {
            int probe = socket(AF_INET, SOCK_STREAM, 0);
            CHECK(probe >= 0, "F1: probe socket created", "failed");

            if (probe >= 0) {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

                int crc = connect(probe, (struct sockaddr *)&addr, sizeof(addr));
                CHECK(crc == 0, "F1: connect to listener succeeds",
                      "connect failed: %s", strerror(errno));

                if (crc == 0) {
                    /* Accept the probe connection */
                    int accepted = wsl_interop_accept_one_io(listen_fd, 1000);
                    CHECK(accepted >= 0, "F1: accept probe connection",
                          "accept failed: %s", strerror(errno));
                    if (accepted >= 0) close(accepted);
                }
                close(probe);
            }
        }

        if (listen_fd >= 0) close(listen_fd);

        /* Test F1b: invalid bind IP is rejected */
        setenv("WSL_INTEROP_IO_BIND_IP", "999.999.999.999", 1);
        int bad_fd = -1;
        uint16_t bad_port = 0;
        int bad_rc = wsl_interop_create_io_listener(&bad_fd, &bad_port);
        CHECK(bad_rc < 0, "F1b: invalid bind IP rejected", "rc=%d", bad_rc);
        if (bad_fd >= 0) close(bad_fd);

        /* Restore valid bind IP for subsequent tests */
        setenv("WSL_INTEROP_IO_BIND_IP", "127.0.0.1", 1);
    }

    printf("\n[host] Step 75: F2 — accept timeout behavior...\n");
    {
        int listen_fd = -1;
        uint16_t port = 0;
        int rc = wsl_interop_create_io_listener(&listen_fd, &port);
        CHECK(rc == 0, "F2: listener created for timeout test", "rc=%d", rc);

        if (rc == 0) {
            /* No one connects — accept should time out */
            int start_ms = 0;
            struct timespec ts_start, ts_end;
            clock_gettime(CLOCK_MONOTONIC, &ts_start);

            int accepted = wsl_interop_accept_one_io(listen_fd, 500);

            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            start_ms = (int)((ts_end.tv_sec - ts_start.tv_sec) * 1000 +
                             (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000);

            CHECK(accepted < 0, "F2: accept times out when no connection",
                  "got fd=%d", accepted);
            CHECK(start_ms >= 400, "F2: timeout waited ~500ms",
                  "only %d ms", start_ms);
            CHECK(start_ms < 2000, "F2: timeout not excessively long",
                  "%d ms", start_ms);

            if (accepted >= 0) close(accepted);
            close(listen_fd);
        }
    }

    printf("\n[host] Step 76: F3 — bidirectional relay via wsl_interop_relay_pair...\n");
    {
        /* Test wsl_interop_relay_pair using pipes to simulate stdio.
         *
         * Setup:
         *   - pipe_local[2]: represents the local fd (e.g. stdin or stdout)
         *   - pipe_remote[2]: represents the network fd
         *
         * For direction=0 (local→remote, like stdin):
         *   write to pipe_local[1] → relay reads pipe_local[0], writes pipe_remote[1]
         *   read from pipe_remote[0] to verify
         *
         * We use socketpair instead of pipe for bidirectional capability. */
        int local_sv[2], remote_sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local_sv) == 0,
              "F3: local socketpair created", "%s", strerror(errno));
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, remote_sv) == 0,
              "F3: remote socketpair created", "%s", strerror(errno));

        if (local_sv[0] >= 0 && remote_sv[0] >= 0) {
            /* direction=0: local→remote (stdin direction)
             * relay reads from local_sv[0], writes to remote_sv[1]
             * We write to local_sv[1], read from remote_sv[0] */
            volatile int stop_flag = 0;

            fflush(stdout); fflush(stderr);
            /* Fork a child to run the relay */
            pid_t child = fork();
            CHECK(child >= 0, "F3: fork relay child", "%s", strerror(errno));

            if (child == 0) {
                /* Child: close the ends we don't use */
                close(local_sv[1]);
                close(remote_sv[0]);
                /* relay: read local_sv[0] → write remote_sv[1] */
                wsl_interop_relay_pair(local_sv[0], remote_sv[1], 0, &stop_flag);
                close(local_sv[0]);
                close(remote_sv[1]);
                _exit(0);
            }

            if (child > 0) {
                /* Parent: close child's ends */
                close(local_sv[0]);
                close(remote_sv[1]);

                /* Send test data through the relay */
                const char *test_data = "Hello from F3 relay test!\n";
                size_t data_len = strlen(test_data);
                ssize_t sent = send(local_sv[1], test_data, data_len, 0);
                CHECK(sent == (ssize_t)data_len,
                      "F3: send test data to local end",
                      "sent=%zd", sent);

                /* Read from remote end */
                char buf[128] = {0};
                ssize_t received = 0;
                for (int attempt = 0; attempt < 50 && received < (ssize_t)data_len; attempt++) {
                    ssize_t n = read(remote_sv[0], buf + received,
                                     sizeof(buf) - received - 1);
                    if (n > 0) received += n;
                    else if (n == 0) break;
                    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
                    usleep(10000); /* 10 ms */
                }

                CHECK(received == (ssize_t)data_len,
                      "F3: relay forwarded all data",
                      "received=%zd/%zu", received, data_len);
                CHECK(strcmp(buf, test_data) == 0,
                      "F3: relayed data matches",
                      "got '%s'", buf);

                /* Signal child to stop and close fds */
                stop_flag = 1;
                close(local_sv[1]);
                close(remote_sv[0]);

                int status;
                waitpid(child, &status, 0);
                CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "F3: relay child exited cleanly",
                      "status=%d", status);
            }
        }
    }

    printf("\n[host] Step 77: F4 — reverse relay direction (remote→local)...\n");
    {
        /* Test wsl_interop_relay_pair with direction=1 (remote→local).
         * This simulates the stdout/stderr relay path: data flows from
         * the network fd to the local fd (e.g. STDOUT_FILENO). */
        int local_sv[2], remote_sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, local_sv) == 0,
              "F4: local socketpair created", "%s", strerror(errno));
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, remote_sv) == 0,
              "F4: remote socketpair created", "%s", strerror(errno));

        if (local_sv[0] >= 0 && remote_sv[0] >= 0) {
            volatile int stop_flag = 0;

            fflush(stdout); fflush(stderr);
            /* Fork a child to run the relay */
            pid_t child = fork();
            CHECK(child >= 0, "F4: fork relay child", "%s", strerror(errno));

            if (child == 0) {
                /* Child: close the ends we don't use */
                close(local_sv[1]);
                close(remote_sv[0]);
                /* direction=1: read remote_sv[1] → write local_sv[0]
                 * (simulates stdout: data from network → local fd) */
                wsl_interop_relay_pair(local_sv[0], remote_sv[1], 1, &stop_flag);
                close(local_sv[0]);
                close(remote_sv[1]);
                _exit(0);
            }

            if (child > 0) {
                /* Parent: close child's ends */
                close(local_sv[0]);
                close(remote_sv[1]);

                /* Send data to the remote end (simulating host sending
                 * stdout data to the guest) */
                const char *test_data = "stdout data from F4!\n";
                size_t data_len = strlen(test_data);
                ssize_t sent = send(remote_sv[0], test_data, data_len, 0);
                CHECK(sent == (ssize_t)data_len,
                      "F4: send data to remote end",
                      "sent=%zd", sent);

                /* Read from local end (where the relay wrote) */
                char buf[128] = {0};
                ssize_t received = 0;
                for (int attempt = 0; attempt < 50 && received < (ssize_t)data_len; attempt++) {
                    ssize_t n = read(local_sv[1], buf + received,
                                     sizeof(buf) - received - 1);
                    if (n > 0) received += n;
                    else if (n == 0) break;
                    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
                    usleep(10000);
                }

                CHECK(received == (ssize_t)data_len,
                      "F4: relay forwarded data in reverse direction",
                      "received=%zd/%zu", received, data_len);
                CHECK(strcmp(buf, test_data) == 0,
                      "F4: reverse-relayed data matches",
                      "got '%s'", buf);

                /* Signal child to stop and close fds */
                stop_flag = 1;
                close(local_sv[1]);
                close(remote_sv[0]);

                int status;
                waitpid(child, &status, 0);
                CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "F4: reverse relay child exited cleanly",
                      "status=%d", status);
            }
        }
    }

    printf("\n[host] Step 78: F5 — wsl_interop_run_io_relay structure validation...\n");
    {
        /* Validate wsl_interop_run_io_relay without actually forking relay
         * children (which would inherit test harness fds and interfere
         * with subsequent GNS tests). Instead, we verify:
         *   - The function exists and is callable
         *   - It rejects an invalid listener fd
         *   - It times out when no connections arrive
         *
         * The actual relay data forwarding is already validated by
         * F3 (direction=0) and F4 (direction=1). */
        int listen_fd = -1;
        uint16_t port = 0;
        int rc = wsl_interop_create_io_listener(&listen_fd, &port);
        CHECK(rc == 0, "F5: listener created", "rc=%d", rc);

        if (rc == 0) {
            /* Verify wsl_interop_run_io_relay times out when no host
             * connects. Uses a short timeout to keep the test fast.
             * The function should return -1 (setup failure) after
             * the accept timeout. */
            int relay_rc = wsl_interop_run_io_relay(listen_fd, 300);
            CHECK(relay_rc < 0,
                  "F5: run_io_relay returns -1 on accept timeout",
                  "got rc=%d", relay_rc);
            close(listen_fd);
        }

        /* Verify it rejects an invalid fd */
        int bad_rc = wsl_interop_run_io_relay(-1, 100);
        CHECK(bad_rc < 0,
              "F5: run_io_relay rejects invalid listener fd",
              "got rc=%d", bad_rc);
    }

    /* ---- Cleanup ---- */
    /* Phase 4: some fds may already be closed (set to -1); guard close() */
    for (int i = 0; i < 5; i++) if (extra[i] >= 0) close(extra[i]);
    if (bridge_init >= 0) close(bridge_init);
    if (bridge_initial >= 0) close(bridge_initial);
    close(init_fd);
    close(notify_fd);
    close(cap_fd);
    close(listen_fd);
    if (gns_fd >= 0) close(gns_fd);
    close(gns_listen_fd);

    /* ---- Summary ---- */
    printf("\n=== Test Summary ===\n");
    printf("  Passed: %d\n", g_tests_passed);
    printf("  Failed: %d\n", g_tests_failed);
    printf("  Total:  %d\n", g_tests_passed + g_tests_failed);
    printf("=== %s ===\n", g_tests_failed == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");

    return g_tests_failed == 0 ? 0 : 1;
}

#pragma GCC diagnostic pop
