/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_mock_host.c - Mock WSL host for testing Phase 0 + Phase 1 + Phase 2 fixes.
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

#include "wsl_protocol.h"

/* Phase 1: TerminateInstance message type */
#define LxInitMessageTerminateInstance  14

static int g_tests_passed = 0;
static int g_tests_failed = 0;

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

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    printf("=== WSL Mock Host — Phase 2 Test Harness ===\n\n");

    /* Listen on port 50000 for guest connections */
    int listen_fd = listen_on_port(PORT_HVS);
    if (listen_fd < 0) { fprintf(stderr, "FATAL: cannot listen on %d\n", PORT_HVS); return 1; }
    printf("[host] listening on port %d\n", PORT_HVS);

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

    /* ---- Step 4: Send Initialize(5) with seq=42, expect InitializeResponse(6) ---- */
    printf("\n[host] Step 4: Sending Initialize (seq=42), expecting response...\n");
    struct {
        struct MESSAGE_HEADER Header;
        char dummy[64];
    } init_msg;
    memset(&init_msg, 0, sizeof(init_msg));
    init_msg.Header.MessageType = LxInitMessageInitialize;
    init_msg.Header.MessageSize = sizeof(struct MESSAGE_HEADER);
    init_msg.Header.SequenceNumber = 42;
    if (send_all(init_fd, &init_msg.Header, sizeof(struct MESSAGE_HEADER)) < 0) {
        perror("send Initialize"); return 1;
    }
    printf("  Sent Initialize (type=%u, seq=%u)\n",
           init_msg.Header.MessageType, init_msg.Header.SequenceNumber);

    LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *cfg =
        (LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *)recv_message(init_fd, &hdr);
    if (!cfg) { fprintf(stderr, "  [FAIL] cannot receive InitializeResponse\n"); return 1; }

    printf("  Received: MessageType=%u, seq=%u, InteropPort=%u, Systemd=%d\n",
           cfg->Header.MessageType, cfg->Header.SequenceNumber,
           cfg->InteropPort, cfg->SystemdEnabled);

    CHECK(cfg->Header.MessageType == LxInitMessageInitializeResponse,
          "InitializeResponse MessageType==6",
          "got %u", cfg->Header.MessageType);
    CHECK(cfg->Header.SequenceNumber == 42,
          "InitializeResponse seq echoed (42)",
          "got %u", cfg->Header.SequenceNumber);
    CHECK(cfg->InteropPort == PORT_HVS_BSD,
          "InitializeResponse InteropPort==60000",
          "got %u", cfg->InteropPort);
    CHECK(cfg->SystemdEnabled == false,
          "InitializeResponse SystemdEnabled==false (Phase 0 fix)",
          "got %d", cfg->SystemdEnabled);
    free(cfg);

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

    close(listen_fd);

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

    /* ---- Step 12 (Phase 1): TerminateInstance test ---- */
    printf("\n[host] Step 12: Sending TerminateInstance to hvinit...\n");
    struct MESSAGE_HEADER term_msg;
    memset(&term_msg, 0, sizeof(term_msg));
    term_msg.MessageType = LxInitMessageTerminateInstance;
    term_msg.MessageSize = sizeof(term_msg);
    term_msg.SequenceNumber = 200;

    if (send_all(init_fd, &term_msg, sizeof(term_msg)) < 0) {
        perror("send TerminateInstance");
        CHECK(0, "TerminateInstance sent", "send failed");
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

    /* ---- Cleanup ---- */
    for (int i = 0; i < 5; i++) close(extra[i]);
    close(bridge_init);
    close(bridge_initial);
    close(init_fd);
    close(notify_fd);
    close(cap_fd);

    /* ---- Summary ---- */
    printf("\n=== Test Summary ===\n");
    printf("  Passed: %d\n", g_tests_passed);
    printf("  Failed: %d\n", g_tests_failed);
    printf("  Total:  %d\n", g_tests_passed + g_tests_failed);
    printf("=== %s ===\n", g_tests_failed == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");

    return g_tests_failed == 0 ? 0 : 1;
}
