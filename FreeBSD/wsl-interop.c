/*
 * SPDX-License-Identifier: MIT
 *
 * wsl-interop.c — Userspace interop wrapper for FreeBSD (Task Group E3).
 *
 * On Linux WSL, binfmt_misc automatically intercepts PE binaries (MZ magic)
 * and invokes /init, which connects to the session leader's interop Unix
 * socket and sends a CreateNtProcessUtilityVm message to launch the Windows
 * process via the host.
 *
 * FreeBSD has no binfmt_misc. This wrapper replaces that mechanism with
 * explicit invocation:
 *
 *   wsl-interop <windows_path> [args...]
 *
 * It connects to the interop socket (found via WSL_INTEROP env var or parent
 * process tree search), builds an LX_INIT_CREATE_NT_PROCESS_UTILITY_VM message,
 * sends it, and relays stdin/stdout/stderr between the terminal and the host-
 * provided I/O sockets.
 *
 * Reference: src/linux/init/binfmt.cpp CreateNtProcessUtilityVm() (client side),
 *            src/linux/init/util.cpp UtilConnectToInteropServer() (socket find).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <poll.h>

/* Include shared interop definitions */
#include "wsl_interop.h"

/* WSL protocol constants */
#define LxInitMessageCreateProcessUtilityVm  8
#define LxMessageResultUint32                78

/* Message header (12 bytes) */
struct MESSAGE_HEADER {
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};

/* LX_INIT_CREATE_NT_PROCESS_COMMON (from lxinitshared.h) */
struct LX_INIT_CREATE_NT_PROCESS_COMMON {
    unsigned int FilenameOffset;
    unsigned int CurrentWorkingDirectoryOffset;
    unsigned int CommandLineOffset;
    unsigned short CommandLineCount;
    unsigned int EnvironmentOffset;
    unsigned short EnvironmentCount;
    unsigned int NtEnvironmentOffset;
    unsigned short NtEnvironmentCount;
    unsigned int NtPathOffset;
    unsigned int ShellOptions;
    unsigned int UsernameOffset;
    unsigned int DefaultUid;
    int Flags;
    char Buffer[];
};

/* LX_INIT_CREATE_NT_PROCESS_UTILITY_VM */
struct LX_INIT_CREATE_NT_PROCESS_UTILITY_VM {
    struct MESSAGE_HEADER Header;
    unsigned int Port;
    struct LX_INIT_CREATE_NT_PROCESS_COMMON Common;
};

/* Build a CreateNtProcessUtilityVm message.
 * Returns malloc'd buffer (caller frees) or NULL on failure.
 * Sets *out_size to the message size.
 * port: the I/O relay port to advertise (0 = no I/O relay). */
static char *build_create_nt_process_message(const char *filename,
                                              int argc, char **argv,
                                              uint32_t port,
                                              size_t *out_size)
{
    /* Calculate the base size (header + Port + Common up to Buffer[]) */
    size_t base = offsetof(struct LX_INIT_CREATE_NT_PROCESS_UTILITY_VM, Common.Buffer);

    /* Filename (Windows path) */
    size_t filename_len = strlen(filename) + 1;
    size_t cwd_len = 1; /* empty CWD for now */
    size_t env_len = 1;  /* empty environment */
    size_t total = base + filename_len + cwd_len + env_len;

    /* Command line args (argv[1..argc-1]) */
    for (int i = 1; i < argc; i++) {
        total += strlen(argv[i]) + 1;
    }

    if (total > 65536) {
        fprintf(stderr, "wsl-interop: message too large (%zu bytes)\n", total);
        return NULL;
    }

    char *msg = calloc(1, total);
    if (!msg) {
        perror("wsl-interop: calloc");
        return NULL;
    }

    struct LX_INIT_CREATE_NT_PROCESS_UTILITY_VM *m =
        (struct LX_INIT_CREATE_NT_PROCESS_UTILITY_VM *)msg;
    m->Header.MessageType = LxInitMessageCreateProcessUtilityVm;
    m->Header.MessageSize = (unsigned int)total;
    m->Header.SequenceNumber = 0;
    m->Port = port; /* I/O relay port (0 = no I/O relay, for backward compat) */

    size_t offset = 0;
    /* Filename */
    m->Common.FilenameOffset = (unsigned int)offset;
    memcpy(m->Common.Buffer + offset, filename, filename_len);
    offset += filename_len;

    /* CWD (empty) */
    m->Common.CurrentWorkingDirectoryOffset = (unsigned int)offset;
    m->Common.Buffer[offset] = '\0';
    offset += cwd_len;

    /* Environment (empty) */
    m->Common.EnvironmentOffset = (unsigned int)offset;
    m->Common.EnvironmentCount = 0;
    m->Common.Buffer[offset] = '\0';
    offset += env_len;

    /* Command line */
    m->Common.CommandLineOffset = (unsigned int)offset;
    m->Common.CommandLineCount = (unsigned short)(argc - 1);
    for (int i = 1; i < argc; i++) {
        size_t arg_len = strlen(argv[i]) + 1;
        memcpy(m->Common.Buffer + offset, argv[i], arg_len);
        offset += arg_len;
    }

    *out_size = total;
    return msg;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <windows_path> [args...]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Launches a Windows process via the WSL interop channel.\n");
    fprintf(stderr, "This is the FreeBSD equivalent of binfmt_misc WSLInterop.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The WSL_INTEROP environment variable must be set to the\n");
    fprintf(stderr, "interop socket path (done automatically by the bridge).\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *windows_path = argv[1];

    /* Find the interop socket */
    char sock_path[64];
    if (wsl_interop_find_socket(sock_path, sizeof(sock_path)) < 0) {
        fprintf(stderr, "wsl-interop: cannot find interop socket.\n");
        fprintf(stderr, "  Set WSL_INTEROP environment variable or run from"
                        " within a WSL session.\n");
        return 1;
    }

    printf("[wsl-interop] connecting to %s\n", sock_path);

    /* Connect to the interop Unix socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("wsl-interop: socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("wsl-interop: connect");
        close(fd);
        return 1;
    }

    printf("[wsl-interop] connected, sending CreateProcessUtilityVm for '%s'\n",
           windows_path);

    /* Task Group F: Create the I/O relay listener before sending the message.
     * The host will connect back to this port for stdin/stdout/stderr. */
    int io_listen_fd = -1;
    uint16_t io_port = 0;
    if (wsl_interop_create_io_listener(&io_listen_fd, &io_port) < 0) {
        fprintf(stderr, "wsl-interop: failed to create I/O relay listener; "
                        "falling back to Port=0 (no I/O)\n");
        /* Continue with Port=0 — host may still accept the message */
    } else {
        printf("[wsl-interop] I/O relay listener on port %u\n", io_port);
    }

    /* Build the CreateNtProcessUtilityVm message with the I/O port */
    size_t msg_size = 0;
    char *msg = build_create_nt_process_message(windows_path, argc, argv,
                                                  io_port, &msg_size);
    if (!msg) {
        if (io_listen_fd >= 0) close(io_listen_fd);
        close(fd);
        return 1;
    }

    /* Send the message */
    size_t total = 0;
    while (total < msg_size) {
        ssize_t n = send(fd, msg + total, msg_size - total, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            perror("wsl-interop: send");
            free(msg);
            if (io_listen_fd >= 0) close(io_listen_fd);
            close(fd);
            return 1;
        }
        total += (size_t)n;
    }
    free(msg);

    printf("[wsl-interop] message sent (%zu bytes, port=%u), waiting for response...\n",
           msg_size, io_port);

    /* Read the ResultUint32 response */
    struct {
        unsigned int MessageType;
        unsigned int MessageSize;
        unsigned int SequenceNumber;
        uint32_t Result;
    } resp;
    memset(&resp, 0, sizeof(resp));

    /* Set a timeout for the response */
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(fd, &resp, sizeof(resp), MSG_WAITALL);
    close(fd);

    if (n <= 0) {
        if (n == 0)
            fprintf(stderr, "wsl-interop: interop server closed connection\n");
        else
            perror("wsl-interop: recv");
        if (io_listen_fd >= 0) close(io_listen_fd);
        return 1;
    }

    if (n < (ssize_t)sizeof(resp)) {
        fprintf(stderr, "wsl-interop: short response (%zd bytes)\n", n);
        if (io_listen_fd >= 0) close(io_listen_fd);
        return 1;
    }

    printf("[wsl-interop] response: type=%u, result=%u\n",
           resp.MessageType, resp.Result);

    if (resp.MessageType != LxMessageResultUint32) {
        fprintf(stderr, "wsl-interop: unexpected response type %u\n",
                resp.MessageType);
        if (io_listen_fd >= 0) close(io_listen_fd);
        return 1;
    }

    if (resp.Result != 0) {
        fprintf(stderr, "wsl-interop: host returned error %u (%s)\n",
                resp.Result, strerror(resp.Result));
        if (io_listen_fd >= 0) close(io_listen_fd);
        return 1;
    }

    printf("[wsl-interop] Windows process launched successfully\n");

    /* Task Group F: If we advertised an I/O port, run the relay loop.
     * The host should connect back 3 times (stdin, stdout, stderr).
     * This blocks until the host closes the stdin connection. */
    if (io_listen_fd >= 0 && io_port > 0) {
        printf("[wsl-interop] starting I/O relay (port=%u)...\n", io_port);
        int relay_rc = wsl_interop_run_io_relay(io_listen_fd, 15000);
        if (relay_rc < 0) {
            fprintf(stderr, "wsl-interop: I/O relay failed\n");
            return 1;
        }
        printf("[wsl-interop] I/O relay complete\n");
    } else {
        /* Backward-compat mode: no I/O relay (Port=0).
         * Some host implementations relay I/O through the control channel. */
        printf("[wsl-interop] no I/O relay (Port=0)\n");
    }
    return 0;
}
