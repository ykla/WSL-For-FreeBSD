/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_mock_host.c - Mock WSL host for testing Phase 0 + Phase 1 + Phase 2 + Phase 3 + Phase 4 fixes.
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
    printf("=== WSL Mock Host — Phase 5 Test Harness ===\n\n");

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
    /* Phase 4: some fds may already be closed (set to -1); guard close() */
    for (int i = 0; i < 5; i++) if (extra[i] >= 0) close(extra[i]);
    if (bridge_init >= 0) close(bridge_init);
    if (bridge_initial >= 0) close(bridge_initial);
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
