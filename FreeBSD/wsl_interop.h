/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_interop.h — WSL interop Unix socket server (Task Group E2).
 *
 * Implements the session-leader-side interop server that accepts
 * CreateNtProcessUtilityVm(8) messages from child processes (e.g., the
 * wsl-interop wrapper) and relays them to the host control channel.
 *
 * On Linux, binfmt_misc automatically invokes /init for PE binaries, which
 * connects to this socket. On FreeBSD, binfmt_misc is unavailable, so the
 * user invokes the `wsl-interop` wrapper explicitly (see wsl-interop.c).
 *
 * Socket path format: /run/WSL/<pid>_interop
 *   (matches WSL_INTEROP_SOCKET_FORMAT in reference util.h:75)
 *
 * Environment variable: WSL_INTEROP=<path>
 *   (matches WSL_INTEROP_ENV in reference util.h:71)
 *   Set in the child process so that wsl-interop can find the socket.
 *
 * Reference: src/linux/init/util.cpp InteropServer::Create() (socket setup),
 *            src/linux/init/init.cpp:1957 (poll/accept),
 *            src/linux/init/config.cpp:372 (message relay).
 */
#ifndef WSL_INTEROP_H
#define WSL_INTEROP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

/* ---- Constants (matching reference util.h:71-78) ---- */
#ifndef WSL_INTEROP_ENV
#define WSL_INTEROP_ENV          "WSL_INTEROP"
#endif
#ifndef WSL_INTEROP_SOCKET_NAME
#define WSL_INTEROP_SOCKET_NAME  "interop"
#endif
#ifndef WSL_INTEROP_TEMP_FOLDER
#define WSL_INTEROP_TEMP_FOLDER  "/run/WSL"
#endif

/* Message types used by the interop relay */
#ifndef LxInitMessageCreateProcessUtilityVm
#define LxInitMessageCreateProcessUtilityVm  8
#endif

/* ---- Server-side: create the interop Unix socket listener ----
 *
 * Creates /run/WSL/<pid>_interop as an AF_UNIX SOCK_STREAM listener.
 * Also ensures /run/WSL exists with mode 0777 (WSL_TEMP_FOLDER_MODE).
 *
 * Parameters:
 *   pid       - the session leader's PID (typically getpid())
 *   path_buf  - output buffer for the socket path (must be >= 64 bytes)
 *   path_len  - size of path_buf
 *
 * Returns:
 *   listen fd on success, -1 on failure.
 *   path_buf is filled with the socket path on success. */
static inline int wsl_interop_create_server(pid_t pid, char *path_buf,
                                             size_t path_len)
{
    /* Ensure /run/WSL exists */
    if (mkdir(WSL_INTEROP_TEMP_FOLDER, 0777) < 0 && errno != EEXIST) {
        fprintf(stderr, "[interop] mkdir %s: %s\n",
                WSL_INTEROP_TEMP_FOLDER, strerror(errno));
        return -1;
    }
    /* Ensure mode is 0777 even if it already existed */
    chmod(WSL_INTEROP_TEMP_FOLDER, 0777);

    /* Build socket path: /run/WSL/<pid>_interop */
    snprintf(path_buf, path_len, "%s/%d_%s",
             WSL_INTEROP_TEMP_FOLDER, (int)pid, WSL_INTEROP_SOCKET_NAME);

    /* Remove any stale socket file */
    unlink(path_buf);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[interop] socket");
        return -1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path_buf, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[interop] bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("[interop] listen");
        close(fd);
        unlink(path_buf);
        return -1;
    }

    /* Allow any user to connect (reference: util.cpp:141 chmod 0777) */
    chmod(path_buf, 0777);

    printf("[interop] server listening at %s\n", path_buf);
    return fd;
}

/* ---- Set the WSL_INTEROP environment variable for child processes ----
 *
 * Called in the child process (after forkpty, before execve) so that
 * wsl-interop can find the socket via getenv("WSL_INTEROP").
 *
 * Reference: init.cpp:1640 sets the env var for the child process. */
static inline void wsl_interop_set_env(const char *path)
{
    if (path) {
        setenv(WSL_INTEROP_ENV, path, 1);
    }
}

/* ---- Relay a CreateNtProcessUtilityVm message from child to host ----
 *
 * Reads one message from conn_fd. If it is a CreateProcessUtilityVm(8),
 * forwards it verbatim to control_fd (the host control channel).
 * Sends a ResultUint32(78) response back to conn_fd with 0=success or
 * errno on failure.
 *
 * Parameters:
 *   conn_fd     - the accepted interop connection from a child process
 *   control_fd  - the host control channel (initial_c in hvbridge)
 *
 * Returns:
 *   0 on success (message relayed or non-relay message handled),
 *  -1 on error (read failure, connection closed). */
static inline int wsl_interop_relay_message(int conn_fd, int control_fd)
{
    /* Read the message header first */
    struct {
        unsigned int MessageType;
        unsigned int MessageSize;
        unsigned int SequenceNumber;
    } hdr;

    /* Set a receive timeout so we don't block forever */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(conn_fd, &hdr, sizeof(hdr), MSG_WAITALL);
    if (n <= 0) {
        if (n == 0)
            printf("[interop] child closed connection\n");
        else
            perror("[interop] recv header");
        return -1;
    }
    if (n < (ssize_t)sizeof(hdr)) {
        fprintf(stderr, "[interop] short read on header (%zd bytes)\n", n);
        return -1;
    }

    if (hdr.MessageSize < sizeof(hdr) || hdr.MessageSize > 65536) {
        fprintf(stderr, "[interop] invalid message size %u\n", hdr.MessageSize);
        return -1;
    }

    /* Read the rest of the message body */
    size_t body_len = hdr.MessageSize - sizeof(hdr);
    char *body = NULL;
    if (body_len > 0) {
        body = malloc(body_len);
        if (!body) {
            perror("[interop] malloc");
            return -1;
        }
        n = recv(conn_fd, body, body_len, MSG_WAITALL);
        if (n <= 0 || (size_t)n < body_len) {
            fprintf(stderr, "[interop] short read on body (%zd/%zu)\n", n, body_len);
            free(body);
            return -1;
        }
    }

    if (hdr.MessageType == LxInitMessageCreateProcessUtilityVm) {
        printf("[interop] relaying CreateProcessUtilityVm to host "
               "(size=%u, seq=%u)\n", hdr.MessageSize, hdr.SequenceNumber);

        /* Reassemble the full message and forward to control channel */
        char *full = malloc(hdr.MessageSize);
        if (!full) {
            perror("[interop] malloc full");
            free(body);
            return -1;
        }
        memcpy(full, &hdr, sizeof(hdr));
        if (body_len > 0)
            memcpy(full + sizeof(hdr), body, body_len);

        int send_rc = -1;
        if (control_fd >= 0) {
            /* Send the entire message to the host control channel */
            size_t total = 0;
            while (total < hdr.MessageSize) {
                ssize_t s = send(control_fd, full + total,
                                 hdr.MessageSize - total, 0);
                if (s <= 0) {
                    if (errno == EINTR) continue;
                    perror("[interop] send to control");
                    break;
                }
                total += (size_t)s;
            }
            send_rc = (total == hdr.MessageSize) ? 0 : -1;
        }
        free(full);

        /* Send ResultUint32 response back to the child */
        struct {
            unsigned int MessageType;
            unsigned int MessageSize;
            unsigned int SequenceNumber;
            uint32_t Result;
        } resp;
        memset(&resp, 0, sizeof(resp));
        resp.MessageType = 78; /* LxMessageResultUint32 */
        resp.MessageSize = sizeof(resp);
        resp.SequenceNumber = hdr.SequenceNumber;
        resp.Result = (send_rc == 0) ? 0 : (uint32_t)EIO;
        send(conn_fd, &resp, sizeof(resp), 0);

        free(body);
        return send_rc;
    }

    /* Non-relay message types: just acknowledge with ResultUint32(0) */
    printf("[interop] received message type=%u (not relayed, acked)\n",
           hdr.MessageType);
    struct {
        unsigned int MessageType;
        unsigned int MessageSize;
        unsigned int SequenceNumber;
        uint32_t Result;
    } resp;
    memset(&resp, 0, sizeof(resp));
    resp.MessageType = 78;
    resp.MessageSize = sizeof(resp);
    resp.SequenceNumber = hdr.SequenceNumber;
    resp.Result = 0;
    send(conn_fd, &resp, sizeof(resp), 0);

    free(body);
    return 0;
}

/* ---- Accept one interop connection and handle it ----
 *
 * Non-blocking accept — returns immediately if no connection is pending.
 * If a connection is accepted, reads and relays the message.
 *
 * Parameters:
 *   listen_fd   - the interop server's listen socket
 *   control_fd  - the host control channel for message relay
 *
 * Returns:
 *   1 if a connection was handled,
 *   0 if no connection was pending,
 *  -1 on accept error. */
static inline int wsl_interop_try_accept(int listen_fd, int control_fd)
{
    int conn = accept(listen_fd, NULL, NULL);
    if (conn < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        perror("[interop] accept");
        return -1;
    }
    fcntl(conn, F_SETFD, FD_CLOEXEC);

    printf("[interop] accepted connection from child process\n");
    int rc = wsl_interop_relay_message(conn, control_fd);
    close(conn);
    return (rc == 0) ? 1 : -1;
}

/* ---- Cleanup: remove the socket file ---- */
static inline void wsl_interop_cleanup(const char *path)
{
    if (path && path[0]) {
        unlink(path);
    }
}

/* ---- Client-side helper: find the interop socket path ----
 *
 * Checks WSL_INTEROP env var first, then searches parent process tree
 * for /run/WSL/<ppid>_interop (matching reference util.cpp:469-491).
 *
 * Returns: 0 on success (path_buf filled), -1 if not found. */
static inline int wsl_interop_find_socket(char *path_buf, size_t path_len)
{
    /* Check WSL_INTEROP env var first */
    const char *env_path = getenv(WSL_INTEROP_ENV);
    if (env_path && access(env_path, F_OK) == 0) {
        strncpy(path_buf, env_path, path_len - 1);
        path_buf[path_len - 1] = '\0';
        return 0;
    }

    /* Search parent process tree */
    pid_t parent = getppid();
    while (parent > 0) {
        snprintf(path_buf, path_len, "%s/%d_%s",
                 WSL_INTEROP_TEMP_FOLDER, (int)parent,
                 WSL_INTEROP_SOCKET_NAME);
        if (access(path_buf, F_OK) == 0) {
            /* Cache for future calls */
            setenv(WSL_INTEROP_ENV, path_buf, 1);
            return 0;
        }
        /* On FreeBSD, getppid doesn't change in a loop, so break to avoid
         * infinite loop. The reference uses UtilGetPpid() to walk the tree. */
        break;
    }

    return -1;
}

/* ========================================================================
 * Task Group F: I/O Relay — host-connectable stdio bridge for interop.
 *
 * When wsl-interop launches a Windows process via CreateProcessUtilityVm(8),
 * the Port field tells the host which TCP/vsock port to connect back to for
 * I/O streams. The host connects 3 times to the same port:
 *   connection 1 → stdin  (host → guest direction)
 *   connection 2 → stdout (guest → host direction)
 *   connection 3 → stderr (guest → host direction)
 *
 * On FreeBSD production, this would use AF_HYPERV sockets; in the Linux
 * test environment we use TCP on 127.0.0.1.
 *
 * Reference: lxinitshared.h LX_INIT_CREATE_NT_PROCESS_UTILITY_VM.Port field,
 *            src/linux/init/binfmt.cpp CreateNtProcessUtilityVm() I/O setup.
 * ======================================================================== */

/* Environment variable to override the I/O relay bind address (test mode).
 * Production ignores this and uses AF_HYPERV. */
#ifndef WSL_INTEROP_IO_BIND_IP
#define WSL_INTEROP_IO_BIND_IP  "WSL_INTEROP_IO_BIND_IP"
#endif

/* Default bind address for test environment. Production would not use TCP. */
#ifndef WSL_INTEROP_IO_DEFAULT_IP
#define WSL_INTEROP_IO_DEFAULT_IP  "127.0.0.1"
#endif

/* ---- Create the I/O relay listener socket ----
 *
 * Creates a TCP listener on 127.0.0.1 (or the address specified by
 * WSL_INTEROP_IO_BIND_IP env var) with an ephemeral port. The caller
 * fills the Port field of CreateProcessUtilityVm with the returned port.
 *
 * Parameters:
 *   out_fd   - receives the listener fd on success
 *   out_port - receives the bound TCP port (host byte order)
 *
 * Returns: 0 on success, -1 on failure. */
static inline int wsl_interop_create_io_listener(int *out_fd, uint16_t *out_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[interop-io] socket");
        return -1;
    }

    /* Allow rapid reuse of the port across test runs */
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    /* Bind to 127.0.0.1 (or override) on an ephemeral port */
    const char *bind_ip = getenv(WSL_INTEROP_IO_BIND_IP);
    if (!bind_ip || !bind_ip[0]) bind_ip = WSL_INTEROP_IO_DEFAULT_IP;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0; /* ephemeral */
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "[interop-io] invalid bind ip '%s'\n", bind_ip);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[interop-io] bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        perror("[interop-io] listen");
        close(fd);
        return -1;
    }

    /* Read back the assigned port */
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) < 0) {
        perror("[interop-io] getsockname");
        close(fd);
        return -1;
    }

    *out_fd = fd;
    *out_port = ntohs(addr.sin_port);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return 0;
}

/* ---- Accept exactly one I/O connection from the host ----
 *
 * Blocks (up to timeout_ms) for the host to connect back for one I/O stream.
 * Returns the connected fd on success, -1 on timeout or error. */
static inline int wsl_interop_accept_one_io(int listen_fd, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = listen_fd;
    pfd.revents = 0;
    pfd.events = POLLIN;

    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) {
        if (pr == 0)
            fprintf(stderr, "[interop-io] accept timeout (%d ms)\n", timeout_ms);
        else
            perror("[interop-io] poll");
        return -1;
    }

    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        perror("[interop-io] accept");
        return -1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* ---- Bidirectional relay between two fds until both sides close ----
 *
 * Used to pipe data between a local fd (STDIN_FILENO / STDOUT_FILENO /
 * STDERR_FILENO) and a network fd. Uses poll() with a 1-second idle timeout
 * so the caller can periodically check for termination conditions.
 *
 * Parameters:
 *   local_fd   - local fd (e.g. STDIN_FILENO for stdin→host direction)
 *   remote_fd  - network fd connected to the host
 *   direction  - 0 = local→remote (write side: stdin),
 *                1 = remote→local (read side: stdout/stderr)
 *   stop_flag  - pointer to a volatile int; if it becomes non-zero, the
 *                relay loop exits at the next poll iteration.
 *
 * The relay exits when:
 *   - poll returns 0 (idle timeout) AND stop_flag is set, OR
 *   - the read side returns EOF (peer closed), OR
 *   - a socket error occurs. */
static inline void wsl_interop_relay_pair(int local_fd, int remote_fd,
                                           int direction,
                                           volatile int *stop_flag)
{
    char buf[4096];
    /* For direction=0 (stdin: local→remote), we read from local_fd and
     * write to remote_fd. For direction=1 (stdout/stderr: remote→local),
     * we read from remote_fd and write to local_fd. */
    int read_fd  = (direction == 0) ? local_fd  : remote_fd;
    int write_fd = (direction == 0) ? remote_fd : local_fd;

    /* Make read_fd non-blocking so we can poll */
    int flags = fcntl(read_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(write_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(write_fd, F_SETFL, flags | O_NONBLOCK);

    for (;;) {
        if (*stop_flag) {
            /* Drain any remaining data before exiting */
            struct pollfd pfd;
            pfd.fd = read_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 0) <= 0) return;
            if (!(pfd.revents & POLLIN)) return;
        }

        struct pollfd pfd;
        pfd.fd = read_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, *stop_flag ? 0 : 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (pr == 0) {
            /* Idle timeout — only exit if stop_flag is set */
            if (*stop_flag) return;
            continue;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            /* Try one last read to drain, then exit */
            ssize_t n = read(read_fd, buf, sizeof(buf));
            if (n > 0) {
                size_t off = 0;
                while (off < (size_t)n) {
                    ssize_t w = write(write_fd, buf + off, (size_t)n - off);
                    if (w <= 0) break;
                    off += (size_t)w;
                }
            }
            return;
        }
        if (pfd.revents & POLLIN) {
            ssize_t n = read(read_fd, buf, sizeof(buf));
            if (n == 0) return; /* EOF */
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (errno == EINTR) continue;
                return;
            }
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t w = write(write_fd, buf + off, (size_t)n - off);
                if (w <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* Wait for write_fd to become writable */
                        struct pollfd wpfd;
                        wpfd.fd = write_fd;
                        wpfd.events = POLLOUT;
                        wpfd.revents = 0;
                        poll(&wpfd, 1, 1000);
                        continue;
                    }
                    if (errno == EINTR) continue;
                    return;
                }
                off += (size_t)w;
            }
        }
    }
}

/* ---- Run the full I/O relay: accept 3 host connections and pipe stdio ----
 *
 * After sending CreateProcessUtilityVm with a non-zero Port and receiving
 * Result==0, the caller invokes this to:
 *   1. Accept 3 connections from the host (stdin, stdout, stderr in order)
 *   2. Fork 2 children to relay stdout and stderr (guest → host)
 *   3. In the parent, relay stdin (host → guest) until the host closes it
 *   4. Reap the children
 *
 * Parameters:
 *   listen_fd   - the I/O listener fd (from wsl_interop_create_io_listener)
 *   timeout_ms  - per-connection accept timeout in milliseconds
 *
 * Returns: 0 on clean shutdown, -1 on setup failure. */
static inline int wsl_interop_run_io_relay(int listen_fd, int timeout_ms)
{
    /* Accept stdin connection (host → guest) */
    int stdin_net = wsl_interop_accept_one_io(listen_fd, timeout_ms);
    if (stdin_net < 0) {
        fprintf(stderr, "[interop-io] failed to accept stdin connection\n");
        return -1;
    }
    fprintf(stderr, "[interop-io] stdin connection accepted (fd=%d)\n", stdin_net);

    /* Accept stdout connection (guest → host) */
    int stdout_net = wsl_interop_accept_one_io(listen_fd, timeout_ms);
    if (stdout_net < 0) {
        fprintf(stderr, "[interop-io] failed to accept stdout connection\n");
        close(stdin_net);
        return -1;
    }
    fprintf(stderr, "[interop-io] stdout connection accepted (fd=%d)\n", stdout_net);

    /* Accept stderr connection (guest → host) */
    int stderr_net = wsl_interop_accept_one_io(listen_fd, timeout_ms);
    if (stderr_net < 0) {
        fprintf(stderr, "[interop-io] failed to accept stderr connection\n");
        close(stdin_net);
        close(stdout_net);
        return -1;
    }
    fprintf(stderr, "[interop-io] stderr connection accepted (fd=%d)\n", stderr_net);

    /* Done with the listener */
    close(listen_fd);

    volatile int stop_flag = 0;

    /* Fork a child to relay stdout (local STDOUT_FILENO → remote stdout_net).
     * direction=0 means local→remote: read from STDOUT_FILENO (Windows proc
     * output), write to stdout_net (sent to host). */
    pid_t stdout_pid = fork();
    if (stdout_pid == 0) {
        /* Child: relay stdout. Exit when STDOUT_FILENO reaches EOF
         * (Windows process closed its stdout). */
        wsl_interop_relay_pair(STDOUT_FILENO, stdout_net, 0, &stop_flag);
        _exit(0);
    }
    if (stdout_pid < 0) {
        perror("[interop-io] fork stdout");
        close(stdin_net);
        close(stdout_net);
        close(stderr_net);
        return -1;
    }

    /* Fork a child to relay stderr (local STDERR_FILENO → remote stderr_net).
     * direction=0 means local→remote: read from STDERR_FILENO, write to
     * stderr_net. */
    pid_t stderr_pid = fork();
    if (stderr_pid == 0) {
        /* Child: relay stderr. Exit when STDERR_FILENO reaches EOF. */
        wsl_interop_relay_pair(STDERR_FILENO, stderr_net, 0, &stop_flag);
        _exit(0);
    }
    if (stderr_pid < 0) {
        perror("[interop-io] fork stderr");
        stop_flag = 1;
        /* Still need to reap stdout child */
        int s;
        waitpid(stdout_pid, &s, 0);
        close(stdin_net);
        close(stdout_net);
        close(stderr_net);
        return -1;
    }

    /* Parent: relay stdin (remote stdin_net → local STDIN_FILENO).
     * direction=1 means remote→local: read from stdin_net (host side),
     * write to STDIN_FILENO (the Windows process's stdin).
     * This blocks until the host closes the stdin connection. */
    wsl_interop_relay_pair(STDIN_FILENO, stdin_net, 1, &stop_flag);

    /* Signal children to stop and reap them */
    stop_flag = 1;
    /* Close the network fds to unblock any pending reads in children */
    close(stdin_net);
    close(stdout_net);
    close(stderr_net);

    int s1, s2;
    waitpid(stdout_pid, &s1, 0);
    waitpid(stderr_pid, &s2, 0);

    fprintf(stderr, "[interop-io] relay complete (stdout_pid=%d, stderr_pid=%d)\n",
            stdout_pid, stderr_pid);
    return 0;
}

#endif /* WSL_INTEROP_H */
