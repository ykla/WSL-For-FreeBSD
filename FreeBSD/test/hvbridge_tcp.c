/*
 * SPDX-License-Identifier: MIT
 *
 * hvbridge_tcp.c - TCP-adapted version of hvbridge.c for local testing.
 *
 * Phase 1 changes:
 *   - Single-process poll-based event loop (no forking for console)
 *   - WindowSizeChanged handling on control channel (initial_c)
 *   - ExitStatus sent on control channel (initial_c) instead of stdout
 *   - Multi-session loop (accept new connections after session ends)
 *   - SIGCHLD handling via self-pipe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <stddef.h>

#ifdef __linux__
#include <pty.h>
#else
#include <libutil.h>
#endif

#include "wsl_protocol.h"

/* Phase 1: also handle TerminateInstance on control channel */
#define LxInitMessageTerminateInstance  14

#define NUM_ADDITIONAL_SOCKETS 5
#define ACCEPT_TIMEOUT_MS 60000

/* Global storage for initial message */
static LX_INIT_CREATE_PROCESS_UTILITY_VM *g_initial_message = NULL;
static size_t g_initial_message_size = 0;

/* Phase 1: SIGCHLD self-pipe */
static int g_sigchld_pipe[2] = {-1, -1};

/* ---- Phase 2: CreateProcess info parsing ---- */
struct create_process_info {
    char *filename;
    char *cwd;
    char **argv;   /* NULL-terminated array */
    char **envp;   /* NULL-terminated array */
};

/* Parse the Common.Buffer from CreateProcessUtilityVm to extract
 * filename, cwd, argv (from CommandLine), and envp (from Environment).
 * Offsets are relative to Common.Buffer. Strings are NUL-terminated. */
static struct create_process_info *parse_create_process_info(
    LX_INIT_CREATE_PROCESS_UTILITY_VM *msg, size_t msg_size)
{
    if (!msg || msg_size < sizeof(*msg))
        return NULL;

    /* Buffer starts at the flexible array member at the end of Common */
    size_t buf_offset = offsetof(LX_INIT_CREATE_PROCESS_UTILITY_VM, Common.Buffer);
    if (msg_size <= buf_offset)
        return NULL;

    char *buffer = msg->Common.Buffer;
    size_t buffer_size = msg_size - buf_offset;

    struct create_process_info *info = calloc(1, sizeof(*info));
    if (!info) return NULL;

    /* Filename */
    if (msg->Common.FilenameOffset < buffer_size)
        info->filename = strdup(buffer + msg->Common.FilenameOffset);

    /* Current working directory */
    if (msg->Common.CurrentWorkingDirectoryOffset < buffer_size)
        info->cwd = strdup(buffer + msg->Common.CurrentWorkingDirectoryOffset);

    /* CommandLine -> argv (CommandLineCount consecutive NUL-terminated strings) */
    if (msg->Common.CommandLineCount > 0 &&
        msg->Common.CommandLineOffset < buffer_size) {
        info->argv = calloc((size_t)msg->Common.CommandLineCount + 1, sizeof(char *));
        if (info->argv) {
            char *p = buffer + msg->Common.CommandLineOffset;
            size_t remaining = buffer_size - msg->Common.CommandLineOffset;
            for (uint16_t i = 0; i < msg->Common.CommandLineCount && remaining > 0; i++) {
                info->argv[i] = strndup(p, remaining);
                size_t len = strnlen(p, remaining);
                if (len >= remaining) break;
                p += len + 1;
                remaining -= len + 1;
            }
        }
    }

    /* Environment -> envp (EnvironmentCount consecutive NUL-terminated "KEY=VALUE" strings) */
    if (msg->Common.EnvironmentCount > 0 &&
        msg->Common.EnvironmentOffset < buffer_size) {
        info->envp = calloc((size_t)msg->Common.EnvironmentCount + 1, sizeof(char *));
        if (info->envp) {
            char *p = buffer + msg->Common.EnvironmentOffset;
            size_t remaining = buffer_size - msg->Common.EnvironmentOffset;
            for (uint16_t i = 0; i < msg->Common.EnvironmentCount && remaining > 0; i++) {
                info->envp[i] = strndup(p, remaining);
                size_t len = strnlen(p, remaining);
                if (len >= remaining) break;
                p += len + 1;
                remaining -= len + 1;
            }
        }
    }

    printf("[bridge] parsed CreateProcess: filename='%s', cwd='%s', argv[0]='%s', env_count=%u\n",
           info->filename ? info->filename : "(null)",
           info->cwd ? info->cwd : "(null)",
           (info->argv && info->argv[0]) ? info->argv[0] : "(null)",
           msg->Common.EnvironmentCount);
    return info;
}

static void free_create_process_info(struct create_process_info *info)
{
    if (!info) return;
    free(info->filename);
    free(info->cwd);
    if (info->argv) {
        for (size_t i = 0; info->argv[i]; i++)
            free(info->argv[i]);
        free(info->argv);
    }
    if (info->envp) {
        for (size_t i = 0; info->envp[i]; i++)
            free(info->envp[i]);
        free(info->envp);
    }
    free(info);
}

static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_sigchld_pipe[1] >= 0) {
        char c = 'c';
        (void)write(g_sigchld_pipe[1], &c, 1);
    }
}

static int accept_with_poll(int listen_fd)
{
    struct pollfd pfd = { .fd = listen_fd, .events = POLLIN };
    int ret = poll(&pfd, 1, ACCEPT_TIMEOUT_MS);
    if (ret <= 0) return -1;
    return accept(listen_fd, NULL, NULL);
}

static int read_full(int fd, void *buf, size_t count)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < count) {
        ssize_t n = read(fd, p + got, count - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

/* Update PTY window size */
static int update_pty_winsize(int master_fd, unsigned short rows, unsigned short cols)
{
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = rows;
    ws.ws_col = cols;
    if (ioctl(master_fd, TIOCSWINSZ, &ws) < 0) {
        perror("[bridge] ioctl TIOCSWINSZ");
        return -1;
    }
    return 0;
}

/* FIX: write_all handles EAGAIN on non-blocking fds (e.g. PTY master). */
static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, 1000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Receive CreateProcessUtilityVm, store globally, reply with ResultUint32. */
static int receive_initial_message(int sock_fd)
{
    struct MESSAGE_HEADER header;
    if (read_full(sock_fd, &header, sizeof(header)) < 0) {
        perror("[bridge] read header");
        return -1;
    }
    printf("[bridge] received CreateProcessUtilityVm: type=%u, size=%u, seq=%u\n",
           header.MessageType, header.MessageSize, header.SequenceNumber);

    if (header.MessageSize < sizeof(header)) return -1;
    size_t body = header.MessageSize - sizeof(header);

    g_initial_message_size = header.MessageSize;
    g_initial_message = malloc(header.MessageSize);
    if (!g_initial_message) return -1;
    memcpy(&g_initial_message->Header, &header, sizeof(header));

    if (body > 0 && read_full(sock_fd, (char *)g_initial_message + sizeof(header), body) < 0) {
        perror("[bridge] read body");
        return -1;
    }

    printf("[bridge]   Rows=%u, Cols=%u\n",
           g_initial_message->Rows, g_initial_message->Columns);

    /* Reply with ResultUint32 (type 78), echoing host's seq */
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = header.SequenceNumber;
    resp.Result = PORT_HVS_BSD;

    if (send_all(sock_fd, &resp, sizeof(resp)) < 0) {
        perror("[bridge] send result");
        return -1;
    }
    printf("[bridge] sent ResultUint32 (type=%u, seq=%u, Result=%u)\n",
           resp.Header.MessageType, resp.Header.SequenceNumber, resp.Result);
    return 0;
}

/* ---- Phase 1: Control channel buffered reader ---- */
/* Reads WSL messages from the control channel (initial_c) non-blocking. */
struct control_reader {
    char buf[512];
    size_t len;
};

/* Returns: 1 = complete message ready (*out_msg points into cr->buf),
 *          0 = need more data,
 *         -1 = error / EOF */
static int control_try_read(int fd, struct control_reader *cr, void **out_msg)
{
    /* Read whatever is available */
    if (cr->len < sizeof(cr->buf)) {
        ssize_t n = recv(fd, cr->buf + cr->len, sizeof(cr->buf) - cr->len, 0);
        if (n > 0) {
            cr->len += (size_t)n;
        } else if (n == 0) {
            return -1;  /* EOF */
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
    }

    /* Check for complete message */
    if (cr->len < sizeof(struct MESSAGE_HEADER)) return 0;

    struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)cr->buf;
    if (hdr->MessageSize < sizeof(*hdr) || hdr->MessageSize > sizeof(cr->buf)) return -1;
    if (cr->len < hdr->MessageSize) return 0;

    *out_msg = cr->buf;
    return 1;
}

/* After processing a message, shift remaining data in the buffer. */
static void control_consume(struct control_reader *cr, size_t msg_size)
{
    if (cr->len > msg_size) {
        memmove(cr->buf, cr->buf + msg_size, cr->len - msg_size);
        cr->len -= msg_size;
    } else {
        cr->len = 0;
    }
}

/* ---- Phase 1: Run a single console session ---- */
/* Returns the shell exit code. */
static int run_session(int initial_c, int stdin_fd, int stdout_fd,
                       int channel_fd, int interop_fd,
                       struct create_process_info *info)
{
    int master_fd;
    pid_t pid;

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = 24;
    ws.ws_col = 80;
    if (g_initial_message &&
        g_initial_message_size >= offsetof(LX_INIT_CREATE_PROCESS_UTILITY_VM, Common)) {
        ws.ws_row = g_initial_message->Rows;
        ws.ws_col = g_initial_message->Columns;
        printf("[bridge] using terminal size: %u rows x %u cols\n",
               (unsigned)ws.ws_row, (unsigned)ws.ws_col);
    }

    /* FIX: Install SIGCHLD handler BEFORE forkpty to avoid race where
     * child exits before handler is set, causing lost signal and hang. */
    if (pipe(g_sigchld_pipe) < 0) {
        perror("[bridge] pipe");
        g_sigchld_pipe[0] = g_sigchld_pipe[1] = -1;
    } else {
        fcntl(g_sigchld_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(g_sigchld_pipe[1], F_SETFL, O_NONBLOCK);
        signal(SIGCHLD, sigchld_handler);
    }

    pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        perror("[bridge] forkpty");
        return -1;
    }

    if (pid == 0) {
        /* Child: start process using parsed CreateProcess info (Phase 2) */
        signal(SIGCHLD, SIG_DFL); /* restore default in child */

        if (info) {
            /* Phase 2: chdir to CWD from message */
            if (info->cwd) {
                if (chdir(info->cwd) < 0)
                    perror("[bridge] chdir");
            }
            /* Phase 2: execve with filename, argv, envp from message */
            if (info->filename && info->argv) {
                char *default_envp[] = { NULL };
                char **envp = info->envp ? info->envp : default_envp;
                execve(info->filename, info->argv, envp);
                perror("[bridge] execve");
                /* fall through to fallback on failure */
            }
        }

        /* Fallback: default shell */
        execlp("/bin/sh", "sh", (char *)NULL);
        perror("[bridge] execlp");
        _exit(127);
    }

    /* Parent: set non-blocking */
    fcntl(master_fd, F_SETFL, fcntl(master_fd, F_GETFL) | O_NONBLOCK);
    fcntl(stdin_fd, F_SETFL, fcntl(stdin_fd, F_GETFL) | O_NONBLOCK);
    fcntl(initial_c, F_SETFL, fcntl(initial_c, F_GETFL) | O_NONBLOCK);
    if (channel_fd >= 0)
        fcntl(channel_fd, F_SETFL, fcntl(channel_fd, F_GETFL) | O_NONBLOCK);
    if (interop_fd >= 0)
        fcntl(interop_fd, F_SETFL, fcntl(interop_fd, F_GETFL) | O_NONBLOCK);

    /* FIX: Check if child already exited before entering poll loop */
    {
        int early_status;
        pid_t w = waitpid(pid, &early_status, WNOHANG);
        if (w == pid) {
            printf("[bridge] child exited immediately (status=%d)\n", early_status);
            int exit_code = WIFEXITED(early_status) ? WEXITSTATUS(early_status) : -1;
            LX_INIT_PROCESS_EXIT_STATUS exit_msg;
            memset(&exit_msg, 0, sizeof(exit_msg));
            exit_msg.Header.MessageType = LxInitMessageExitStatus;
            exit_msg.Header.MessageSize = sizeof(exit_msg);
            exit_msg.Header.SequenceNumber = 1;
            exit_msg.ExitCode = exit_code;
            send_all(initial_c, &exit_msg, sizeof(exit_msg));
            close(master_fd);
            signal(SIGCHLD, SIG_DFL);
            if (g_sigchld_pipe[0] >= 0) close(g_sigchld_pipe[0]);
            if (g_sigchld_pipe[1] >= 0) close(g_sigchld_pipe[1]);
            g_sigchld_pipe[0] = g_sigchld_pipe[1] = -1;
            return exit_code;
        }
    }

    printf("[bridge] session started (shell pid=%d)\n", pid);

    struct control_reader cr;
    memset(&cr, 0, sizeof(cr));
    char buf[4096];
    int exit_code = -1;
    int session_done = 0;

    /* pollfd indices */
    enum { IDX_CONTROL, IDX_STDIN, IDX_PTY, IDX_SIGCHLD, IDX_CHANNEL, IDX_INTEROP, NFDS };

    while (!session_done) {
        struct pollfd pfds[NFDS];
        memset(pfds, 0, sizeof(pfds));

        pfds[IDX_CONTROL].fd = initial_c;          pfds[IDX_CONTROL].events = POLLIN;
        pfds[IDX_STDIN].fd = stdin_fd;             pfds[IDX_STDIN].events = POLLIN;
        pfds[IDX_PTY].fd = master_fd;              pfds[IDX_PTY].events = POLLIN;
        pfds[IDX_SIGCHLD].fd = g_sigchld_pipe[0];  pfds[IDX_SIGCHLD].events = POLLIN;
        pfds[IDX_CHANNEL].fd = channel_fd;         pfds[IDX_CHANNEL].events = POLLIN;
        pfds[IDX_INTEROP].fd = interop_fd;         pfds[IDX_INTEROP].events = POLLIN;

        int rc = poll(pfds, NFDS, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[bridge] poll");
            break;
        }

        /* SIGCHLD: child exited */
        if (pfds[IDX_SIGCHLD].revents & POLLIN) {
            char c;
            while (read(g_sigchld_pipe[0], &c, 1) > 0) {}

            int status;
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) {
                /* FIX: Drain PTY with blocking read — child has exited,
                 * slave is closed, so read will eventually return EOF.
                 * Temporarily set blocking to avoid EAGAIN truncation. */
                int fl = fcntl(master_fd, F_GETFL);
                fcntl(master_fd, F_SETFL, fl & ~O_NONBLOCK);
                ssize_t n;
                while ((n = read(master_fd, buf, sizeof(buf))) > 0)
                    send_all(stdout_fd, buf, (size_t)n);
                fcntl(master_fd, F_SETFL, fl);

                /* Phase 1 fix: send ExitStatus on control channel, not stdout */
                exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                LX_INIT_PROCESS_EXIT_STATUS exit_msg;
                memset(&exit_msg, 0, sizeof(exit_msg));
                exit_msg.Header.MessageType = LxInitMessageExitStatus;
                exit_msg.Header.MessageSize = sizeof(exit_msg);
                exit_msg.Header.SequenceNumber = 1;
                exit_msg.ExitCode = exit_code;
                send_all(initial_c, &exit_msg, sizeof(exit_msg));
                printf("[bridge] child exited (code=%d), ExitStatus sent on control channel\n",
                       exit_code);
                session_done = 1;
                break;
            }
        }

        /* Control channel: WindowSizeChanged and other messages */
        if (pfds[IDX_CONTROL].revents & POLLIN) {
            void *msg = NULL;
            int r = control_try_read(initial_c, &cr, &msg);
            if (r < 0) {
                printf("[bridge] control channel closed\n");
                session_done = 1;
                break;
            }
            if (r > 0 && msg) {
                struct MESSAGE_HEADER *mhdr = (struct MESSAGE_HEADER *)msg;
                switch (mhdr->MessageType) {
                case LxInitMessageWindowSizeChanged: {
                    if (mhdr->MessageSize >= sizeof(LX_INIT_WINDOW_SIZE_CHANGED)) {
                        LX_INIT_WINDOW_SIZE_CHANGED *wsc =
                            (LX_INIT_WINDOW_SIZE_CHANGED *)msg;
                        printf("[bridge] WindowSizeChanged: rows=%u, cols=%u\n",
                               wsc->Rows, wsc->Columns);
                        update_pty_winsize(master_fd, wsc->Rows, wsc->Columns);
                    }
                    break;
                }
                default:
                    printf("[bridge] control msg type=%u (size=%u, seq=%u)\n",
                           mhdr->MessageType, mhdr->MessageSize, mhdr->SequenceNumber);
                    break;
                }
                control_consume(&cr, mhdr->MessageSize);
            }
        }

        /* stdin -> PTY */
        if (pfds[IDX_STDIN].revents & POLLIN) {
            ssize_t n = recv(stdin_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                /* FIX: use write_all to handle partial writes / EAGAIN */
                write_all(master_fd, buf, (size_t)n);
            } else if (n == 0) {
                printf("[bridge] stdin closed\n");
                /* Don't end session on stdin close; shell may still be running */
            }
        }

        /* PTY -> stdout */
        if (pfds[IDX_PTY].revents & POLLIN) {
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n > 0) {
                send_all(stdout_fd, buf, (size_t)n);
            } else if (n == 0) {
                /* PTY closed */
            }
        }

        /* channel echo */
        if (channel_fd >= 0 && (pfds[IDX_CHANNEL].revents & POLLIN)) {
            ssize_t n = recv(channel_fd, buf, sizeof(buf), 0);
            if (n > 0) send_all(channel_fd, buf, (size_t)n);
        }

        /* interop echo */
        if (interop_fd >= 0 && (pfds[IDX_INTEROP].revents & POLLIN)) {
            ssize_t n = recv(interop_fd, buf, sizeof(buf), 0);
            if (n > 0) send_all(interop_fd, buf, (size_t)n);
        }
    }

    close(master_fd);
    signal(SIGCHLD, SIG_DFL);
    /* FIX: close pipe fds to avoid fd leak in multi-session loop */
    if (g_sigchld_pipe[0] >= 0) close(g_sigchld_pipe[0]);
    if (g_sigchld_pipe[1] >= 0) close(g_sigchld_pipe[1]);
    g_sigchld_pipe[0] = g_sigchld_pipe[1] = -1;

    return exit_code;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    printf("[bridge] hvbridge_tcp starting (pid=%d)\n", getpid());

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_HVS_BSD);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(s, 16) < 0) {
        perror("listen");
        return 1;
    }
    printf("[bridge] listening on port %d\n", PORT_HVS_BSD);

    /* Phase 1: multi-session loop */
    for (;;) {
        printf("\n[bridge] === waiting for new session ===\n");

        /* Accept first connection (init channel — accepted but unused) */
        int init_c = accept_with_poll(s);
        if (init_c < 0) {
            fprintf(stderr, "[bridge] accept init failed\n");
            break;
        }
        printf("[bridge] accepted init connection\n");

        /* Accept control channel (initial_c) */
        int initial_c = accept_with_poll(s);
        if (initial_c < 0) {
            fprintf(stderr, "[bridge] accept initial failed\n");
            close(init_c);
            break;
        }

        if (receive_initial_message(initial_c) < 0) {
            fprintf(stderr, "[bridge] FATAL: failed to receive initial message\n");
            close(init_c);
            close(initial_c);
            break;
        }

        /* Phase 2: parse CreateProcess info (filename, cwd, argv, envp) */
        struct create_process_info *proc_info =
            parse_create_process_info(g_initial_message, g_initial_message_size);

        /* Accept 5 additional sockets: stdin/stdout/stderr/channel/interop */
        int client_sockets[NUM_ADDITIONAL_SOCKETS];
        int accept_failed = 0;
        for (int i = 0; i < NUM_ADDITIONAL_SOCKETS; i++) {
            client_sockets[i] = accept_with_poll(s);
            if (client_sockets[i] < 0) {
                fprintf(stderr, "[bridge] accept additional %d failed\n", i);
                accept_failed = 1;
                break;
            }
            printf("[bridge] accepted additional socket %d\n", i);
        }

        if (accept_failed) {
            close(init_c);
            close(initial_c);
            for (int i = 0; i < NUM_ADDITIONAL_SOCKETS; i++)
                if (client_sockets[i] >= 0) close(client_sockets[i]);
            break;
        }

        /* Run the console session in this process (no forking) */
        int exit_code = run_session(initial_c,
                                    client_sockets[0],  /* stdin */
                                    client_sockets[1],  /* stdout */
                                    client_sockets[3],  /* channel */
                                    client_sockets[4],  /* interop */
                                    proc_info);

        printf("[bridge] session ended (exit_code=%d)\n", exit_code);

        /* Phase 2: free parsed CreateProcess info */
        free_create_process_info(proc_info);

        /* Close all session sockets */
        close(init_c);
        close(initial_c);
        for (int i = 0; i < NUM_ADDITIONAL_SOCKETS; i++)
            close(client_sockets[i]);

        /* Free initial message for next session */
        if (g_initial_message) {
            free(g_initial_message);
            g_initial_message = NULL;
            g_initial_message_size = 0;
        }

        printf("[bridge] ready for next session\n");
    }

    close(s);
    printf("[bridge] shutting down\n");
    return 0;
}
