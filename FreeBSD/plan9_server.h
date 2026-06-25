/*
 * SPDX-License-Identifier: MIT
 *
 * plan9_server.h - Plan9 9P2000.L file server for WSL-For-FreeBSD.
 *
 * Implements the guest-side Plan9 file server that exposes the guest
 * filesystem to the Windows host for \\wsl$\ access.
 *
 * Reference: src/linux/init/plan9.cpp (StartPlan9Server, RunPlan9Server,
 *            StopPlan9Server)
 *
 * Architecture:
 *   - Production (FreeBSD): Uses lib9p from FreeBSD contrib/lib9p with the
 *     fs backend (serves "/" via open(O_DIRECTORY) rootfd). Listens on
 *     AF_HYPERV (hvsocket) port 50001 (LX_INIT_UTILITY_VM_PLAN9_PORT).
 *   - Test (Linux/WSL2): Minimal 9P2000.L stub over TCP for protocol-level
 *     testing. Implements Tversion/Tattach/Tstat/Twalk/Tclunk/Tflush.
 *
 * lib9p selection rationale (verified via web research 2026-06-25):
 *   1. lib9p is part of FreeBSD base (/usr/src/contrib/lib9p), BSD-2-clause
 *   2. Supports full 9P2000.L (Tversion..Tunlinkat, 30+ message types)
 *   3. Transport-agnostic: struct l9p_transport with 3 callbacks, plus
 *      l9p_socket_accept() accepts pre-connected fd (works with hvsocket)
 *   4. fs backend: l9p_backend_fs_init(&backend, rootfd, ro) serves a
 *      directory tree via openat()/readdir()
 *   5. WSL 9P2000.W extensions (Taccess=128/Twreaddir=130/Twopen=132) are
 *      optional performance optimizations (confirmed in p9defs.h comment:
 *      "improved functionality and performance"). Windows p9rdr.sys falls
 *      back to standard 9P2000.L operations when the server responds with
 *      "9P2000.L" to a "9P2000.W" Tversion request.
 *
 * Startup flow (mirrors plan9.cpp StartPlan9Server):
 *   1. Open rootfd at "/" (O_DIRECTORY)
 *   2. Bind listening socket (hvsocket:50001 / TCP for test)
 *   3. Create pipe for parent-child signaling
 *   4. fork() child: init lib9p server + backend, accept loop
 *   5. Parent: read pipe (blocks until child is ready), return port
 *
 * Shutdown flow (mirrors plan9.cpp StopPlan9Server):
 *   - LxInitMessageStopPlan9Server(24) with Force flag
 *   - Force=true: SIGKILL child immediately
 *   - Force=false: check for active connections, graceful stop
 *   - Response: RESULT_MESSAGE<bool> with success/failure
 */
#ifndef PLAN9_SERVER_H
#define PLAN9_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <poll.h>

/* ---- WSL protocol constants (lxinitshared.h) ---- */
#define LX_INIT_UTILITY_VM_PLAN9_PORT 50001
#define LxInitMessageStopPlan9Server  24

/* ---- Type definitions (guarded: test builds get these from wsl_protocol.h;
 *      production builds get RESULT_MESSAGE_BOOL from gns_engine.h) ---- */

/* RESULT_MESSAGE_BOOL: already provided by wsl_protocol.h (test) or
 * gns_engine.h (production). Only define if neither was included. */
#if !defined(WSL_PROTOCOL_H) && !defined(RESULT_MESSAGE_BOOL_DEFINED)
typedef struct RESULT_MESSAGE_BOOL {
    struct MESSAGE_HEADER Header;
    bool Result;
} RESULT_MESSAGE_BOOL;
#endif /* !WSL_PROTOCOL_H && !RESULT_MESSAGE_BOOL_DEFINED */

/* LX_INIT_STOP_PLAN9_SERVER_MSG: not provided by wsl_protocol.h or gns_engine.h.
 * Always define it here unless a prior include already did. */
#ifndef LX_INIT_STOP_PLAN9_SERVER_MSG_DEFINED
#define LX_INIT_STOP_PLAN9_SERVER_MSG_DEFINED
typedef struct LX_INIT_STOP_PLAN9_SERVER_MSG {
    struct MESSAGE_HEADER Header;
    uint32_t Force;   /* bool: 1=force (SIGKILL), 0=graceful */
} LX_INIT_STOP_PLAN9_SERVER_MSG;
#endif /* LX_INIT_STOP_PLAN9_SERVER_MSG_DEFINED */

/* ---- Module state ---- */
static struct {
    pid_t child_pid;       /* Plan9 server child process PID, -1 if not running */
    unsigned int port;     /* Port reported to host (50001 for production) */
    int started;           /* 1 if server was started successfully */
    int control_pipe[2];   /* Pipe for stop signaling (parent→child) */
} g_plan9 = {
    .child_pid = -1,
    .port = 0,
    .started = 0,
    .control_pipe = { -1, -1 }
};

/* ===========================================================================
 * Production implementation: FreeBSD + lib9p + hvsocket
 * ===========================================================================
 * lib9p API (from contrib/lib9p/lib9p.h, backend/fs.h, transport/socket.h):
 *   int l9p_server_init(struct l9p_server **serverp, struct l9p_backend *backend);
 *   int l9p_backend_fs_init(struct l9p_backend **backendp, int rootfd, bool ro);
 *   int l9p_connection_init(struct l9p_server *server, struct l9p_connection **conn);
 *   void l9p_socket_accept(struct l9p_server *server, int conn_fd,
 *                          struct sockaddr *client_addr, socklen_t client_addr_len);
 *   void l9p_connection_close(struct l9p_connection *conn);
 *   enum l9p_version { L9P_2000, L9P_2000U, L9P_2000L };
 * =========================================================================== */
#ifdef __FreeBSD__

#include <sys/un.h>
/* lib9p headers (FreeBSD base system) */
#include <lib9p.h>
#include <backend/fs.h>

/* Bind an AF_HYPERV (hvsocket) listener on the given port.
 * Returns fd on success, -1 on failure. */
static int plan9_bind_hvsocket(unsigned int port)
{
    int fd = socket(AF_HYPERV, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[plan9] socket(AF_HYPERV)");
        return -1;
    }

    struct sockaddr_hvs addr;
    memset(&addr, 0, sizeof(addr));
    addr.sa_family = AF_HYPERV;
    addr.hvs_port = port;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[plan9] bind(AF_HYPERV)");
        close(fd);
        return -1;
    }

    if (listen(fd, 10) < 0) {
        perror("[plan9] listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* Child process entry: run the lib9p server loop.
 * Exits on pipe close (parent-initiated stop) or accept() failure. */
static void plan9_child_run(int listen_fd, int rootfd, int control_fd)
{
    /* Initialize lib9p server with fs backend */
    struct l9p_backend *backend = NULL;
    if (l9p_backend_fs_init(&backend, rootfd, false) != 0) {
        fprintf(stderr, "[plan9] l9p_backend_fs_init failed\n");
        _exit(1);
    }

    struct l9p_server *server = NULL;
    if (l9p_server_init(&server, backend) != 0) {
        fprintf(stderr, "[plan9] l9p_server_init failed\n");
        _exit(1);
    }
    server->ls_max_version = L9P_2000L;

    /* Signal parent that we're ready */
    close(control_fd);

    /* Accept loop: wait for hvsocket connections, dispatch to lib9p */
    struct pollfd pfds[2];
    pfds[0].fd = listen_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = -1; /* no additional control fd in child after close */
    pfds[1].events = 0;

    for (;;) {
        int rc = poll(pfds, 1, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfds[0].revents & POLLIN) {
            struct sockaddr client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int conn_fd = accept(listen_fd, &client_addr, &addr_len);
            if (conn_fd < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                break;
            }
            /* l9p_socket_accept handles connection lifecycle internally
             * (creates connection, spawns thread, etc.) */
            l9p_socket_accept(server, conn_fd, &client_addr, addr_len);
        }
    }

    _exit(0);
}

/* Start the Plan9 file server.
 * Returns the port number on success, 0 on failure.
 * Mirrors: plan9.cpp StartPlan9Server() */
static unsigned int plan9_start_server(void)
{
    if (g_plan9.started) {
        fprintf(stderr, "[plan9] server already started\n");
        return g_plan9.port;
    }

    /* 1. Open root directory fd for lib9p fs backend */
    int rootfd = open("/", O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) {
        perror("[plan9] open(/)");
        return 0;
    }

    /* 2. Bind hvsocket listener on port 50001 */
    int listen_fd = plan9_bind_hvsocket(LX_INIT_UTILITY_VM_PLAN9_PORT);
    if (listen_fd < 0) {
        close(rootfd);
        return 0;
    }

    /* 3. Create pipe for parent-child readiness signaling */
    if (pipe(g_plan9.control_pipe) < 0) {
        perror("[plan9] pipe");
        close(listen_fd);
        close(rootfd);
        return 0;
    }

    /* 4. Fork child process to run the server */
    pid_t pid = fork();
    if (pid < 0) {
        perror("[plan9] fork");
        close(listen_fd);
        close(rootfd);
        close(g_plan9.control_pipe[0]);
        close(g_plan9.control_pipe[1]);
        g_plan9.control_pipe[0] = g_plan9.control_pipe[1] = -1;
        return 0;
    }

    if (pid == 0) {
        /* Child: close parent's pipe end, run server */
        close(g_plan9.control_pipe[0]);
        int parent_pipe = g_plan9.control_pipe[1];
        /* Set listen_fd and rootfd to not be CLOEXEC in child */
        fcntl(listen_fd, F_SETFD, 0);
        fcntl(rootfd, F_SETFD, 0);
        plan9_child_run(listen_fd, rootfd, parent_pipe);
        /* Never returns */
        _exit(0);
    }

    /* Parent: close child's pipe end and listen fd (child owns it) */
    close(g_plan9.control_pipe[1]);
    g_plan9.control_pipe[1] = -1;
    close(listen_fd);
    close(rootfd);

    /* 5. Wait for child to signal readiness (closes its pipe end) */
    char buf;
    ssize_t n = read(g_plan9.control_pipe[0], &buf, 1);
    if (n < 0) {
        perror("[plan9] read readiness pipe");
        /* Child may still be starting; don't kill it */
    }

    g_plan9.child_pid = pid;
    g_plan9.port = LX_INIT_UTILITY_VM_PLAN9_PORT;
    g_plan9.started = 1;
    printf("[plan9] server started (pid=%d, port=%u)\n",
           (int)pid, g_plan9.port);
    return g_plan9.port;
}

/* Stop the Plan9 file server.
 * Returns true on success.
 * Mirrors: plan9.cpp StopPlan9Server() */
static bool plan9_stop_server(bool force)
{
    if (!g_plan9.started || g_plan9.child_pid < 0) {
        return true; /* Not running, nothing to stop */
    }

    if (force) {
        /* Force: SIGKILL the child immediately */
        kill(g_plan9.child_pid, SIGKILL);
    } else {
        /* Graceful: SIGTERM, wait up to 3 seconds, then SIGKILL */
        kill(g_plan9.child_pid, SIGTERM);
        int status;
        int waited = 0;
        while (waited < 30) {
            pid_t rc = waitpid(g_plan9.child_pid, &status, WNOHANG);
            if (rc == g_plan9.child_pid) break;
            if (rc < 0) break;
            usleep(100000); /* 100ms */
            waited++;
        }
        if (waited >= 30) {
            kill(g_plan9.child_pid, SIGKILL);
            waitpid(g_plan9.child_pid, &status, 0);
        }
    }

    /* Reap the child */
    int status;
    waitpid(g_plan9.child_pid, &status, 0);

    if (g_plan9.control_pipe[0] >= 0) {
        close(g_plan9.control_pipe[0]);
        g_plan9.control_pipe[0] = -1;
    }

    printf("[plan9] server stopped (force=%d)\n", force);
    g_plan9.child_pid = -1;
    g_plan9.started = 0;
    g_plan9.port = 0;
    return true;
}

/* Get the current Plan9 port (0 if not started). */
static unsigned int plan9_get_port(void)
{
    return g_plan9.port;
}

/* Check if Plan9 server is running. */
static bool plan9_is_running(void)
{
    return g_plan9.started && g_plan9.child_pid > 0;
}

/* ===========================================================================
 * Test implementation: Linux/WSL2 + minimal 9P stub + TCP
 * ===========================================================================
 * This is NOT a real file server. It implements just enough 9P2000.L to
 * verify protocol-level integration:
 *   - Tversion(100) → Rversion(101): negotiate "9P2000.L", msize
 *   - Tattach(104)  → Rattach(105): return root QID (dir, path=1)
 *   - Tstat(124)    → Rstat(125): minimal stat for root
 *   - Twalk(110)    → Rwalk(111): 0-element walk (root fid clone)
 *   - Tclunk(120)   → Rclunk(121): acknowledge
 *   - Tflush(108)   → Rflush(109): acknowledge
 *   - Others        → Rerror(7): "not supported"
 *
 * 9P wire format: size[4] type[1] tag[2] [body...]
 * String encoding: length[2] data[length]
 * QID: qtype[1] qversion[4] qpath[8] = 13 bytes
 * =========================================================================== */
#else /* !__FreeBSD__ */

/* 9P message types (subset for stub) */
#define P9_TVERSION 100
#define P9_RVERSION 101
#define P9_TATTACH  104
#define P9_RATTACH  105
#define P9_TFLUSH   108
#define P9_RFLUSH   109
#define P9_TWALK    110
#define P9_RWALK    111
#define P9_TCLUNK   120
#define P9_RCLUNK   121
#define P9_TSTAT    124
#define P9_RSTAT    125
#define P9_RERROR   7

#define P9_QID_DIR  0x80
#define P9_MAXMSIZE 65536

/* Read exactly n bytes from fd. Returns 0 on success, -1 on error/EOF. */
static int p9_readn(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)buf + done, n - done);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        done += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes to fd. Returns 0 on success, -1 on error. */
static int p9_writen(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        done += (size_t)w;
    }
    return 0;
}

/* Pack a little-endian uint16 */
static void p9_put16(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

/* Pack a little-endian uint32 */
static void p9_put32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

/* Pack a little-endian uint64 */
static void p9_put64(uint8_t *buf, uint64_t val)
{
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

/* Pack a 9P string (uint16 length + data, NUL-terminated) */
static size_t p9_put_string(uint8_t *buf, const char *s)
{
    size_t len = strlen(s);
    p9_put16(buf, (uint16_t)len);
    memcpy(buf + 2, s, len);
    return 2 + len;
}

/* Send a 9P response message. */
static void p9_send_response(int fd, uint8_t type, uint16_t tag,
                             const uint8_t *body, size_t body_len)
{
    size_t total = 4 + 1 + 2 + body_len; /* size[4] type[1] tag[2] body */

    /* FIX: combine header + body into a single write to prevent TCP
     * fragmentation. Previously two separate p9_writen calls could split
     * the message across TCP segments, causing the receiver's single
     * read() to get only the 7-byte header without the body. */
    uint8_t msgbuf[512];
    if (total > sizeof(msgbuf)) {
        /* Fallback for oversized messages: sequential writes */
        uint8_t hdr[7];
        p9_put32(hdr, (uint32_t)total);
        hdr[4] = type;
        p9_put16(hdr + 5, tag);
        if (p9_writen(fd, hdr, 7) < 0) return;
        if (body_len > 0 && p9_writen(fd, body, body_len) < 0) return;
        return;
    }

    p9_put32(msgbuf, (uint32_t)total);
    msgbuf[4] = type;
    p9_put16(msgbuf + 5, tag);
    if (body_len > 0)
        memcpy(msgbuf + 7, body, body_len);
    p9_writen(fd, msgbuf, total);
}

/* Send an Rerror response. */
static void p9_send_error(int fd, uint16_t tag, const char *msg)
{
    uint8_t body[256];
    size_t slen = p9_put_string(body, msg);
    p9_send_response(fd, P9_RERROR, tag, body, slen);
}

/* Handle one 9P request. Returns 0 to continue, -1 to close connection. */
static int p9_handle_request(int fd)
{
    /* Read message size (4 bytes) */
    uint8_t size_buf[4];
    if (p9_readn(fd, size_buf, 4) < 0) return -1;

    uint32_t msg_size = (uint32_t)size_buf[0]
                      | ((uint32_t)size_buf[1] << 8)
                      | ((uint32_t)size_buf[2] << 16)
                      | ((uint32_t)size_buf[3] << 24);
    if (msg_size < 7 || msg_size > P9_MAXMSIZE) return -1;

    /* Read rest of message (type[1] + tag[2] + body) */
    size_t remaining = msg_size - 4;
    uint8_t *rest = malloc(remaining);
    if (!rest) return -1;
    if (p9_readn(fd, rest, remaining) < 0) {
        free(rest);
        return -1;
    }

    uint8_t msg_type = rest[0];
    uint16_t tag = (uint16_t)rest[1] | ((uint16_t)rest[2] << 8);
    uint8_t *body = rest + 3;
    size_t body_len = remaining - 3;

    switch (msg_type) {
    case P9_TVERSION: {
        /* body: msize[4] version[s] */
        if (body_len < 6) { p9_send_error(fd, tag, "bad Tversion"); break; }
        uint32_t client_msize = (uint32_t)body[0]
                              | ((uint32_t)body[1] << 8)
                              | ((uint32_t)body[2] << 16)
                              | ((uint32_t)body[3] << 24);
        uint32_t msize = client_msize < P9_MAXMSIZE ? client_msize : P9_MAXMSIZE;

        /* Respond with 9P2000.L (downgrade from 9P2000.W if requested) */
        uint8_t resp[256];
        p9_put32(resp, msize);
        size_t slen = p9_put_string(resp + 4, "9P2000.L");
        p9_send_response(fd, P9_RVERSION, tag, resp, 4 + slen);
        printf("[plan9-stub] Tversion: msize=%u → Rversion 9P2000.L\n", msize);
        break;
    }
    case P9_TATTACH: {
        /* body: fid[4] afid[4] uname[s] aname[s] [n_uname[4]] */
        /* Respond with root QID: type=DIR(0x80), version=0, path=1 */
        uint8_t qid[13];
        qid[0] = P9_QID_DIR;  /* directory */
        p9_put32(qid + 1, 0);  /* version */
        p9_put64(qid + 5, 1);  /* path = 1 (root) */
        p9_send_response(fd, P9_RATTACH, tag, qid, 13);
        printf("[plan9-stub] Tattach → Rattach (root qid: dir, path=1)\n");
        break;
    }
    case P9_TSTAT: {
        /* body: fid[4] */
        /* Respond with minimal stat for root directory.
         * Stat format: size[2] type[2] dev[4] qid[13] mode[4]
         *              atime[4] mtime[4] length[8] name[s]
         *              uid[s] gid[s] muid[s] */
        uint8_t stat[256];
        uint8_t *p = stat + 2; /* skip size, fill later */

        p9_put16(p, 0);    p += 2;  /* type (0 = file) */
        p9_put32(p, 0);    p += 4;  /* dev */
        p[0] = P9_QID_DIR; p += 1;  /* qid.type */
        p9_put32(p, 0);    p += 4;  /* qid.version */
        p9_put64(p, 1);    p += 8;  /* qid.path */
        p9_put32(p, 0040755); p += 4; /* mode (dir+rwxr-xr-x) */
        p9_put32(p, 0);    p += 4;  /* atime */
        p9_put32(p, 0);    p += 4;  /* mtime */
        p9_put64(p, 0);    p += 8;  /* length */
        p += p9_put_string(p, "/");     /* name */
        p += p9_put_string(p, "root");  /* uid */
        p += p9_put_string(p, "wheel"); /* gid */
        p += p9_put_string(p, "root");  /* muid */

        size_t stat_len = (size_t)(p - stat);
        p9_put16(stat, (uint16_t)(stat_len - 2)); /* size field (excludes size itself) */

        /* Rstat body: stat_size[2] + stat[stat_len] */
        uint8_t resp[260];
        p9_put16(resp, (uint16_t)stat_len);
        memcpy(resp + 2, stat, stat_len);
        p9_send_response(fd, P9_RSTAT, tag, resp, 2 + stat_len);
        printf("[plan9-stub] Tstat → Rstat (root dir, mode=0755)\n");
        break;
    }
    case P9_TWALK: {
        /* body: fid[4] newfid[4] nwname[2] nwname*(wname[s]) */
        /* For stub: if nwname==0, clone fid (return 0 qids).
         * If nwname>0, return 0 walked (walk failed gracefully). */
        uint16_t nwname = 0;
        if (body_len >= 10) {
            nwname = (uint16_t)body[8] | ((uint16_t)body[9] << 8);
        }
        /* Rwalk body: nwqid[2] + nwqid*qid[13] */
        uint8_t resp[2];
        p9_put16(resp, 0); /* 0 qids walked */
        p9_send_response(fd, P9_RWALK, tag, resp, 2);
        printf("[plan9-stub] Twalk: nwname=%u → Rwalk (0 qids)\n", nwname);
        break;
    }
    case P9_TCLUNK: {
        /* body: fid[4]. Respond Rclunk (empty body). */
        p9_send_response(fd, P9_RCLUNK, tag, NULL, 0);
        printf("[plan9-stub] Tclunk → Rclunk\n");
        break;
    }
    case P9_TFLUSH: {
        /* body: oldtag[2]. Respond Rflush (empty body). */
        p9_send_response(fd, P9_RFLUSH, tag, NULL, 0);
        printf("[plan9-stub] Tflush → Rflush\n");
        break;
    }
    default:
        p9_send_error(fd, tag, "not supported (stub)");
        printf("[plan9-stub] unhandled type %u → Rerror\n", msg_type);
        break;
    }

    free(rest);
    return 0;
}

/* Child process entry: accept TCP connections and handle 9P requests.
 * Exits on pipe close (parent stop) or accept() failure. */
static void plan9_child_run(int listen_fd, int control_fd)
{
    /* Signal parent that we're ready */
    close(control_fd);

    for (;;) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int conn_fd = accept(listen_fd, (struct sockaddr *)&client, &clen);
        if (conn_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        printf("[plan9-stub] client connected\n");

        /* Handle requests until disconnect */
        while (p9_handle_request(conn_fd) == 0) {
            /* keep going */
        }

        close(conn_fd);
        printf("[plan9-stub] client disconnected\n");
    }

    _exit(0);
}

/* Start the Plan9 stub server (TCP for test environment).
 * Returns the port number on success, 0 on failure. */
static unsigned int plan9_start_server(void)
{
    if (g_plan9.started) {
        return g_plan9.port;
    }

    /* 1. Create TCP listener on port 50009 (localhost only).
     * Note: Production uses port 50001 (LX_INIT_UTILITY_VM_PLAN9_PORT) on
     * hvsocket. Test uses 50009 to avoid conflict with PORT_HVS_GNS (50001)
     * which the mock host binds for GNS engine connections. In production,
     * hvsocket addressing (VM ID + port) allows both services to use 50001. */
    #define P9_TEST_PORT 50009
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[plan9] socket");
        return 0;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(P9_TEST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[plan9] bind");
        close(listen_fd);
        return 0;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("[plan9] listen");
        close(listen_fd);
        return 0;
    }

    /* 2. Create pipe for readiness signaling */
    if (pipe(g_plan9.control_pipe) < 0) {
        perror("[plan9] pipe");
        close(listen_fd);
        return 0;
    }

    /* 3. Fork child */
    pid_t pid = fork();
    if (pid < 0) {
        perror("[plan9] fork");
        close(listen_fd);
        close(g_plan9.control_pipe[0]);
        close(g_plan9.control_pipe[1]);
        g_plan9.control_pipe[0] = g_plan9.control_pipe[1] = -1;
        return 0;
    }

    if (pid == 0) {
        /* Child */
        close(g_plan9.control_pipe[0]);
        fcntl(listen_fd, F_SETFD, 0); /* keep open across exec (no exec here) */
        plan9_child_run(listen_fd, g_plan9.control_pipe[1]);
        _exit(0);
    }

    /* Parent */
    close(g_plan9.control_pipe[1]);
    g_plan9.control_pipe[1] = -1;
    close(listen_fd);

    /* Wait for child readiness */
    char buf;
    ssize_t rd = read(g_plan9.control_pipe[0], &buf, 1);
    (void)rd;

    g_plan9.child_pid = pid;
    g_plan9.port = P9_TEST_PORT;
    g_plan9.started = 1;
    printf("[plan9-stub] server started (pid=%d, port=%u)\n",
           (int)pid, g_plan9.port);
    return g_plan9.port;
}

/* Stop the Plan9 stub server. */
static bool plan9_stop_server(bool force)
{
    if (!g_plan9.started || g_plan9.child_pid < 0) {
        return true;
    }

    if (force) {
        kill(g_plan9.child_pid, SIGKILL);
    } else {
        kill(g_plan9.child_pid, SIGTERM);
        int status;
        int waited = 0;
        while (waited < 30) {
            pid_t rc = waitpid(g_plan9.child_pid, &status, WNOHANG);
            if (rc == g_plan9.child_pid) break;
            if (rc < 0) break;
            usleep(100000);
            waited++;
        }
        if (waited >= 30) {
            kill(g_plan9.child_pid, SIGKILL);
        }
    }

    int status;
    waitpid(g_plan9.child_pid, &status, 0);

    if (g_plan9.control_pipe[0] >= 0) {
        close(g_plan9.control_pipe[0]);
        g_plan9.control_pipe[0] = -1;
    }

    printf("[plan9-stub] server stopped (force=%d)\n", force);
    g_plan9.child_pid = -1;
    g_plan9.started = 0;
    g_plan9.port = 0;
    return true;
}

/* Get the current Plan9 port (0 if not started). */
static unsigned int plan9_get_port(void)
{
    return g_plan9.port;
}

/* Check if Plan9 server is running. */
static bool plan9_is_running(void)
{
    return g_plan9.started && g_plan9.child_pid > 0;
}

#endif /* __FreeBSD__ */

#endif /* PLAN9_SERVER_H */
