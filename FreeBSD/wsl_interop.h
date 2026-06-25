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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
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

#endif /* WSL_INTEROP_H */
