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
 *     testing. Implements Tversion/Tattach/Tstat/Twalk/Tclunk/Tflush plus
 *     Tlopen/Tlcreate/Tread/Twrite/Tremove (Group H extension).
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

/* Conditional logger support */
#ifdef LOGGER_H
#define P9_LOG_ERROR(mod, ...)   LOG_ERROR(mod, __VA_ARGS__)
#define P9_LOG_WARN(mod, ...)    LOG_WARN(mod, __VA_ARGS__)
#define P9_LOG_INFO(mod, ...)    LOG_INFO(mod, __VA_ARGS__)
#define P9_LOG_DEBUG(mod, ...)   LOG_DEBUG(mod, __VA_ARGS__)
#else
#define P9_LOG_ERROR(mod, ...)   do { fprintf(stderr, "[%s] ", mod); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define P9_LOG_WARN(mod, ...)    do { fprintf(stderr, "[%s] ", mod); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define P9_LOG_INFO(mod, ...)    do { printf("[%s] ", mod); printf(__VA_ARGS__); printf("\n"); } while(0)
#define P9_LOG_DEBUG(mod, ...)   do { printf("[%s] ", mod); printf(__VA_ARGS__); printf("\n"); } while(0)
#endif

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
/* lib9p headers (FreeBSD base system).
 * <lib9p.h> provides l9p_server_init, l9p_connection_init, L9P_2000L.
 * <backend/fs.h> provides l9p_backend_fs_init (fs backend over rootfd).
 * <transport/socket.h> provides l9p_socket_accept (accept-loop helper that
 *   wraps l9p_connection_init + transport setup for each client). */
#include <lib9p.h>
#include <backend/fs.h>
#include <transport/socket.h>

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
        /* Graceful: SIGTERM, wait up to 5 seconds, then SIGKILL */
        kill(g_plan9.child_pid, SIGTERM);
        int status;
        int waited = 0;
        while (waited < 50) {
            pid_t rc = waitpid(g_plan9.child_pid, &status, WNOHANG);
            if (rc == g_plan9.child_pid) break;
            if (rc < 0) break;
            usleep(100000); /* 100ms */
            waited++;
        }
        if (waited >= 50) {
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
 *   - Tlopen(112)   → Rlopen(113): return QID + iounit (stub open)
 *   - Tlcreate(114) → Rlcreate(115): return QID + iounit (stub create)
 *   - Tread(116)    → Rread(117): return count=0 (empty file)
 *   - Twrite(118)   → Rwrite(119): echo back count (accept writes)
 *   - Tremove(122)  → Rremove(123): acknowledge
 *   - Others        → Rerror(7): "not supported"
 *
 * 9P wire format: size[4] type[1] tag[2] [body...]
 * String encoding: length[2] data[length]
 * QID: qtype[1] qversion[4] qpath[8] = 13 bytes
 * =========================================================================== */
#else /* !__FreeBSD__ */

#include <sys/stat.h>
#include <dirent.h>

/* 9P message types (subset for stub) */
#define P9_TVERSION 100
#define P9_RVERSION 101
#define P9_TATTACH  104
#define P9_RATTACH  105
#define P9_TFLUSH   108
#define P9_RFLUSH   109
#define P9_TWALK    110
#define P9_RWALK    111
#define P9_TLOPEN   112   /* 9P2000.L open */
#define P9_RLOPEN   113
#define P9_TLCREATE 114   /* 9P2000.L create */
#define P9_RLCREATE 115
#define P9_TREAD    116
#define P9_RREAD    117
#define P9_TWRITE   118
#define P9_RWRITE   119
#define P9_TCLUNK   120
#define P9_RCLUNK   121
#define P9_TREMOVE  122
#define P9_RREMOVE  123
#define P9_TSTAT    124
#define P9_RSTAT    125
#define P9_RERROR   7

#define P9_QID_DIR  0x80
#define P9_MAXMSIZE 65536

/* ---- Fid-to-fd mapping table (Group C: real file I/O) ----
 * Each Plan9 fid maps to a real file descriptor and a path relative
 * to the server root directory. This replaces the previous stub
 * behavior (empty responses) with actual file system operations. */
#define MAX_FID_MAP 64

struct fid_entry {
    uint32_t fid;
    int fd;           /* OS file descriptor, -1 = unused slot */
    uint64_t qpath;   /* unique QID path for this fid */
    uint8_t  qtype;   /* P9_QID_DIR (0x80) for directories, 0 for files */
    char path[512];   /* relative path from g_root_path, "" for root */
};

static struct fid_entry g_fid_map[MAX_FID_MAP];
static int g_fid_count = 0;
static int g_rootfd = -1;       /* open fd for the root directory */
static uint64_t g_next_qpath = 2; /* 1 = root, 2+ = dynamically assigned */
static char g_root_path[256];   /* temp directory path for the Plan9 root */

/* Find a fid entry. Returns NULL if not found. */
static struct fid_entry *fid_find(uint32_t fid)
{
    for (int i = 0; i < MAX_FID_MAP; i++) {
        if (g_fid_map[i].fd >= 0 && g_fid_map[i].fid == fid)
            return &g_fid_map[i];
    }
    return NULL;
}

/* Add a new fid entry. Returns NULL if table is full. */
static struct fid_entry *fid_add(uint32_t fid, int fd, uint64_t qpath,
                                  uint8_t qtype, const char *path)
{
    for (int i = 0; i < MAX_FID_MAP; i++) {
        if (g_fid_map[i].fd < 0) {
            g_fid_map[i].fid = fid;
            g_fid_map[i].fd = fd;
            g_fid_map[i].qpath = qpath;
            g_fid_map[i].qtype = qtype;
            if (path)
                snprintf(g_fid_map[i].path, sizeof(g_fid_map[i].path), "%s", path);
            else
                g_fid_map[i].path[0] = '\0';
            g_fid_count++;
            return &g_fid_map[i];
        }
    }
    return NULL;
}

/* Remove and close a fid entry. */
static void fid_remove(uint32_t fid)
{
    for (int i = 0; i < MAX_FID_MAP; i++) {
        if (g_fid_map[i].fd >= 0 && g_fid_map[i].fid == fid) {
            close(g_fid_map[i].fd);
            g_fid_map[i].fd = -1;
            g_fid_map[i].fid = 0;
            g_fid_count--;
            return;
        }
    }
}

/* Replace an existing fid entry's fd/path, keeping the same fid.
 * Used by Tlcreate/Tlopen when the same fid is reused for a new file.
 * Returns the entry pointer, or NULL if the fid was not found. */
static struct fid_entry *fid_replace(uint32_t fid, int fd, uint64_t qpath,
                                      uint8_t qtype, const char *path)
{
    for (int i = 0; i < MAX_FID_MAP; i++) {
        if (g_fid_map[i].fd >= 0 && g_fid_map[i].fid == fid) {
            close(g_fid_map[i].fd);
            g_fid_map[i].fd = fd;
            g_fid_map[i].qpath = qpath;
            g_fid_map[i].qtype = qtype;
            if (path)
                snprintf(g_fid_map[i].path, sizeof(g_fid_map[i].path), "%s", path);
            else
                g_fid_map[i].path[0] = '\0';
            return &g_fid_map[i];
        }
    }
    return NULL;
}

/* Assign a new unique qpath. */
static uint64_t fid_next_qpath(void)
{
    return g_next_qpath++;
}

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

    /* Helper: pack a QID into buf (13 bytes). */
    #define P9_PACK_QID(buf, qtype, qversion, qpath) do { \
        (buf)[0] = (uint8_t)(qtype); \
        p9_put32((buf) + 1, (qversion)); \
        p9_put64((buf) + 5, (qpath)); \
    } while(0)

    /* Helper: build a 9P2000.L stat from struct stat + fid_entry.
     * Writes into stat_buf (must be >= 256 bytes), returns total length. */
    #define P9_BUILD_STAT(stat_buf, entry, st) do { \
        uint8_t *_p = (stat_buf) + 2; /* skip size, fill later */ \
        uint16_t _type = S_ISDIR((st).st_mode) ? 1 : 0; \
        const char *_name = (entry)->path[0] ? (entry)->path : "/"; \
        p9_put16(_p, _type); _p += 2; \
        p9_put32(_p, (uint32_t)(st).st_dev); _p += 4; \
        P9_PACK_QID(_p, (entry)->qtype, 0, (entry)->qpath); _p += 13; \
        p9_put32(_p, (uint32_t)(st).st_mode); _p += 4; \
        p9_put32(_p, (uint32_t)(st).st_atime); _p += 4; \
        p9_put32(_p, (uint32_t)(st).st_mtime); _p += 4; \
        p9_put64(_p, (uint64_t)(st).st_size); _p += 8; \
        _p += p9_put_string(_p, _name); \
        _p += p9_put_string(_p, "root"); \
        _p += p9_put_string(_p, "wheel"); \
        _p += p9_put_string(_p, "root"); \
        size_t _slen = (size_t)(_p - (stat_buf)); \
        p9_put16((stat_buf), (uint16_t)(_slen - 2)); \
    } while(0)

    switch (msg_type) {
    case P9_TVERSION: {
        /* body: msize[4] version[s] */
        if (body_len < 6) { p9_send_error(fd, tag, "bad Tversion"); break; }
        uint32_t client_msize = (uint32_t)body[0]
                              | ((uint32_t)body[1] << 8)
                              | ((uint32_t)body[2] << 16)
                              | ((uint32_t)body[3] << 24);
        uint32_t msize = client_msize < P9_MAXMSIZE ? client_msize : P9_MAXMSIZE;

        uint8_t resp[256];
        p9_put32(resp, msize);
        size_t slen = p9_put_string(resp + 4, "9P2000.L");
        p9_send_response(fd, P9_RVERSION, tag, resp, 4 + slen);
        printf("[plan9-stub] Tversion: msize=%u → Rversion 9P2000.L\n", msize);
        break;
    }
    case P9_TATTACH: {
        /* body: fid[4] afid[4] uname[s] aname[s] [n_uname[4]]
         * C2: Open the real root directory and map the fid to it. */
        uint32_t fid = 0;
        if (body_len >= 4) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
        }
        int root_dup = dup(g_rootfd);
        if (root_dup < 0) {
            p9_send_error(fd, tag, "dup root failed");
            break;
        }
        if (!fid_add(fid, root_dup, 1, P9_QID_DIR, "")) {
            close(root_dup);
            p9_send_error(fd, tag, "fid table full");
            break;
        }
        uint8_t qid[13];
        P9_PACK_QID(qid, P9_QID_DIR, 0, 1);
        p9_send_response(fd, P9_RATTACH, tag, qid, 13);
        printf("[plan9-stub] Tattach: fid=%u → Rattach (root dir)\n", fid);
        break;
    }
    case P9_TSTAT: {
        /* body: fid[4]
         * C6: Build real stat from fstat() on the fid's fd. */
        uint32_t fid = 0;
        if (body_len >= 4) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (!entry) { p9_send_error(fd, tag, "unknown fid"); break; }
        struct stat st;
        if (fstat(entry->fd, &st) < 0) {
            p9_send_error(fd, tag, "fstat failed");
            break;
        }
        uint8_t stat_buf[512];
        P9_BUILD_STAT(stat_buf, entry, st);
        /* stat_buf already has the 2-byte size prefix required by 9P2000.L.
         * stat_len is the full stat size (including the 2-byte prefix). */
        size_t stat_len = (size_t)stat_buf[0] | ((size_t)stat_buf[1] << 8);
        stat_len += 2;
        p9_send_response(fd, P9_RSTAT, tag, stat_buf, stat_len);
        printf("[plan9-stub] Tstat: fid=%u path=%s → Rstat (mode=0%o)\n",
               fid, entry->path, (unsigned)st.st_mode & 07777);
        break;
    }
    case P9_TWALK: {
        /* body: fid[4] newfid[4] nwname[2] nwname*(wname[s])
         * C3: Real walk using openat(). If nwname==0, clone the fid
         * (dup fd). Otherwise walk each component from the parent fid. */
        uint32_t fid = 0, newfid = 0;
        uint16_t nwname = 0;
        if (body_len >= 10) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
            newfid = (uint32_t)body[4]
                   | ((uint32_t)body[5] << 8)
                   | ((uint32_t)body[6] << 16)
                   | ((uint32_t)body[7] << 24);
            nwname = (uint16_t)body[8] | ((uint16_t)body[9] << 8);
        }

        if (nwname == 0) {
            /* Clone: dup the parent fid's fd */
            struct fid_entry *parent = fid_find(fid);
            if (!parent) { p9_send_error(fd, tag, "unknown fid"); break; }
            int newfd = dup(parent->fd);
            if (newfd < 0) { p9_send_error(fd, tag, "dup failed"); break; }
            if (!fid_add(newfid, newfd, parent->qpath, parent->qtype, parent->path)) {
                close(newfd);
                p9_send_error(fd, tag, "fid table full");
                break;
            }
            uint8_t resp[2];
            p9_put16(resp, 0); /* 0 qids for clone */
            p9_send_response(fd, P9_RWALK, tag, resp, 2);
            printf("[plan9-stub] Twalk: clone fid=%u → newfid=%u\n", fid, newfid);
            break;
        }

        /* Walk each component using openat() */
        struct fid_entry *parent = fid_find(fid);
        if (!parent) { p9_send_error(fd, tag, "unknown fid"); break; }

        int cur_fd = parent->fd;
        char cur_path[512];
        snprintf(cur_path, sizeof(cur_path), "%s", parent->path);

        uint8_t qids[13 * 16]; /* up to 16 qids */
        uint16_t nwqid = 0;
        size_t pos = 10; /* body offset: fid[4] newfid[4] nwname[2] */

        for (uint16_t i = 0; i < nwname; i++) {
            if (pos + 2 > body_len) break;
            uint16_t name_len = (uint16_t)body[pos] | ((uint16_t)body[pos + 1] << 8);
            pos += 2;
            if (pos + name_len > body_len) break;
            char name[256];
            memcpy(name, body + pos, name_len);
            name[name_len] = '\0';
            pos += name_len;

            /* Try as directory first, then as file */
            int next_fd = openat(cur_fd, name, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            uint8_t next_qtype = P9_QID_DIR;
            if (next_fd < 0) {
                next_fd = openat(cur_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                next_qtype = 0;
            }
            if (next_fd < 0) {
                /* Component not found — walk failed, return 0 qids */
                nwqid = 0;
                break;
            }

            /* Build new path */
            char new_path[512];
            if (cur_path[0])
                snprintf(new_path, sizeof(new_path), "%s/%s", cur_path, name);
            else
                snprintf(new_path, sizeof(new_path), "%s", name);

            uint64_t next_qpath = fid_next_qpath();
            P9_PACK_QID(qids + nwqid * 13, next_qtype, 0, next_qpath);
            nwqid++;

            /* If this is the last component, store in fid_map */
            if (i == nwname - 1) {
                if (!fid_add(newfid, next_fd, next_qpath, next_qtype, new_path)) {
                    close(next_fd);
                    nwqid = 0;
                    break;
                }
            } else {
                /* Intermediate component: close old cur_fd (unless it's the parent) */
                if (cur_fd != parent->fd)
                    close(cur_fd);
                cur_fd = next_fd;
                snprintf(cur_path, sizeof(cur_path), "%s", new_path);
            }
        }

        if (nwqid == 0) {
            /* Walk failed entirely */
            uint8_t resp[2];
            p9_put16(resp, 0);
            p9_send_response(fd, P9_RWALK, tag, resp, 2);
            printf("[plan9-stub] Twalk: fid=%u nwname=%u → Rwalk (0 qids, failed)\n",
                   fid, nwname);
        } else {
            uint8_t resp[2 + 13 * 16];
            p9_put16(resp, nwqid);
            memcpy(resp + 2, qids, (size_t)nwqid * 13);
            p9_send_response(fd, P9_RWALK, tag, resp, 2 + (size_t)nwqid * 13);
            printf("[plan9-stub] Twalk: fid=%u nwname=%u → Rwalk (%u qids)\n",
                   fid, nwname, nwqid);
        }
        break;
    }
    case P9_TCLUNK: {
        /* body: fid[4]
         * C7: Close the fd and remove from fid table. */
        uint32_t fid = 0;
        if (body_len >= 4) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (entry)
            printf("[plan9-stub] Tclunk: fid=%u path=%s → Rclunk\n", fid, entry->path);
        else
            printf("[plan9-stub] Tclunk: fid=%u (unknown) → Rclunk\n", fid);
        fid_remove(fid);
        p9_send_response(fd, P9_RCLUNK, tag, NULL, 0);
        break;
    }
    case P9_TLOPEN: {
        /* 9P2000.L Tlopen body: fid[4] flags[4]
         * C4: Open the file referenced by fid with the given flags.
         * The fid was set up by Twalk; we re-open for I/O. */
        uint32_t fid = 0;
        uint32_t flags = 0;
        if (body_len >= 8) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
            flags = (uint32_t)body[4]
                  | ((uint32_t)body[5] << 8)
                  | ((uint32_t)body[6] << 16)
                  | ((uint32_t)body[7] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (!entry) { p9_send_error(fd, tag, "unknown fid"); break; }

        /* Re-open the file for I/O (the walk fd may be O_RDONLY or O_DIRECTORY) */
        if (entry->qtype & P9_QID_DIR) {
            /* Directory: just return the existing fd */
            uint8_t resp[17];
            P9_PACK_QID(resp, entry->qtype, 0, entry->qpath);
            p9_put32(resp + 13, 8192); /* iounit */
            p9_send_response(fd, P9_RLOPEN, tag, resp, 17);
            printf("[plan9-stub] Tlopen: fid=%u (dir) → Rlopen (iounit=8192)\n", fid);
        } else {
            /* File: re-open with requested flags */
            char fullpath[512];
            if (entry->path[0])
                snprintf(fullpath, sizeof(fullpath), "%s/%s", g_root_path, entry->path);
            else
                snprintf(fullpath, sizeof(fullpath), "%s", g_root_path);

            int newfd = open(fullpath, flags | O_CLOEXEC);
            if (newfd < 0) {
                p9_send_error(fd, tag, "open failed");
                printf("[plan9-stub] Tlopen: fid=%u path=%s flags=0x%x → error\n",
                       fid, entry->path, flags);
                break;
            }
            close(entry->fd);
            entry->fd = newfd;

            uint8_t resp[17];
            resp[0] = 0; /* qid.type = regular file */
            p9_put32(resp + 1, 0); /* qid.version */
            p9_put64(resp + 5, entry->qpath);
            p9_put32(resp + 13, 8192); /* iounit */
            p9_send_response(fd, P9_RLOPEN, tag, resp, 17);
            printf("[plan9-stub] Tlopen: fid=%u path=%s flags=0x%x → Rlopen (iounit=8192)\n",
                   fid, entry->path, flags);
        }
        break;
    }
    case P9_TLCREATE: {
        /* 9P2000.L Tlcreate body: fid[4] name[s] flags[4] mode[4] gid[4]
         * C7: Create a real file in the parent directory referenced by fid. */
        uint32_t fid = 0;
        uint16_t name_len = 0;
        char name[256];
        uint32_t flags = 0, mode = 0;
        if (body_len >= 10) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
            name_len = (uint16_t)body[4] | ((uint16_t)body[5] << 8);
            if (name_len > 0 && (size_t)(6 + name_len) <= body_len) {
                memcpy(name, body + 6, name_len);
                name[name_len] = '\0';
            }
            size_t off = (size_t)(6 + name_len);
            if (off + 12 <= body_len) {
                flags = (uint32_t)body[off]
                      | ((uint32_t)body[off + 1] << 8)
                      | ((uint32_t)body[off + 2] << 16)
                      | ((uint32_t)body[off + 3] << 24);
                mode = (uint32_t)body[off + 4]
                     | ((uint32_t)body[off + 5] << 8)
                     | ((uint32_t)body[off + 6] << 16)
                     | ((uint32_t)body[off + 7] << 24);
            }
        }
        struct fid_entry *parent = fid_find(fid);
        if (!parent) { p9_send_error(fd, tag, "unknown fid"); break; }

        int newfd = openat(parent->fd, name, flags | O_CREAT | O_CLOEXEC, mode & 0777);
        if (newfd < 0) {
            p9_send_error(fd, tag, "create failed");
            printf("[plan9-stub] Tlcreate: fid=%u name=%s → error: %s\n",
                   fid, name, strerror(errno));
            break;
        }

        /* Build child path */
        char child_path[512];
        if (parent->path[0])
            snprintf(child_path, sizeof(child_path), "%s/%s", parent->path, name);
        else
            snprintf(child_path, sizeof(child_path), "%s", name);

        uint64_t qpath = fid_next_qpath();
        /* Try fid_replace first: when fid is reused (e.g. from root dir
         * to a newly created file), replace the old entry. Fall back to
         * fid_add if the fid is not already in the table. */
        if (!fid_replace(fid, newfd, qpath, 0, child_path)) {
            if (!fid_add(fid, newfd, qpath, 0, child_path)) {
                close(newfd);
                p9_send_error(fd, tag, "fid table full");
                break;
            }
        }

        uint8_t resp[17];
        resp[0] = 0; /* regular file */
        p9_put32(resp + 1, 0);
        p9_put64(resp + 5, qpath);
        p9_put32(resp + 13, 8192);
        p9_send_response(fd, P9_RLCREATE, tag, resp, 17);
        printf("[plan9-stub] Tlcreate: fid=%u name=%s path=%s → Rlcreate (qpath=%llu)\n",
               fid, name, child_path, (unsigned long long)qpath);
        break;
    }
    case P9_TREAD: {
        /* Tread body: fid[4] offset[8] count[4]
         * C5: Real file read via pread() or directory read via getdents(). */
        uint32_t fid = 0;
        uint64_t offset = 0;
        uint32_t count = 0;
        if (body_len >= 16) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
            for (int i = 0; i < 8; i++)
                offset |= ((uint64_t)body[4 + i]) << (i * 8);
            count = (uint32_t)body[12]
                  | ((uint32_t)body[13] << 8)
                  | ((uint32_t)body[14] << 16)
                  | ((uint32_t)body[15] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (!entry) { p9_send_error(fd, tag, "unknown fid"); break; }

        if (entry->qtype & P9_QID_DIR) {
            /* Directory read: pack entries in 9P2000.L format.
             * Format: qid[13] offset[8] type[1] name[s] */
            DIR *dir = fdopendir(dup(entry->fd));
            if (!dir) { p9_send_error(fd, tag, "opendir failed"); break; }
            rewinddir(dir);

            /* Skip entries up to the requested offset */
            uint64_t entry_idx = 0;
            struct dirent *de;
            while (entry_idx < offset && (de = readdir(dir)) != NULL)
                entry_idx++;

            /* Pack entries into the response buffer */
            uint8_t *data = malloc(count);
            if (!data) { closedir(dir); p9_send_error(fd, tag, "oom"); break; }
            size_t data_len = 0;

            while ((de = readdir(dir)) != NULL && data_len < count) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                    continue;

                /* Determine QID type */
                uint8_t qtype = 0;
                if (de->d_type == DT_DIR)
                    qtype = P9_QID_DIR;
                else if (de->d_type == DT_LNK)
                    qtype = 0; /* symlinks are files in Plan9 */

                uint64_t d_qpath = fid_next_qpath();
                size_t name_bytes = strlen(de->d_name);
                /* Entry size: qid[13] + offset[8] + type[1] + string_len[2] + name[name_bytes] */
                size_t entry_size = 13 + 8 + 1 + 2 + name_bytes;
                if (data_len + entry_size > count) break;

                P9_PACK_QID(data + data_len, qtype, 0, d_qpath);
                data_len += 13;
                p9_put64(data + data_len, entry_idx + 1);
                data_len += 8;
                data[data_len] = (de->d_type == DT_DIR) ? 1 : 0;
                data_len += 1;
                data_len += p9_put_string(data + data_len, de->d_name);
                entry_idx++;
            }
            closedir(dir);

            /* Build Rread response: count[4] + data */
            uint8_t *resp = malloc(4 + data_len);
            if (!resp) { free(data); p9_send_error(fd, tag, "oom"); break; }
            p9_put32(resp, (uint32_t)data_len);
            if (data_len > 0)
                memcpy(resp + 4, data, data_len);
            p9_send_response(fd, P9_RREAD, tag, resp, 4 + data_len);
            free(data);
            free(resp);
            printf("[plan9-stub] Tread(dir): fid=%u off=%llu → Rread (%zu bytes, %llu entries)\n",
                   fid, (unsigned long long)offset, data_len, (unsigned long long)entry_idx - offset);
        } else {
            /* File read: use pread() */
            uint8_t *data = malloc(count);
            if (!data) { p9_send_error(fd, tag, "oom"); break; }
            ssize_t n = pread(entry->fd, data, count, (off_t)offset);
            if (n < 0) {
                free(data);
                p9_send_error(fd, tag, "read failed");
                break;
            }

            uint8_t *resp = malloc(4 + (size_t)n);
            if (!resp) { free(data); p9_send_error(fd, tag, "oom"); break; }
            p9_put32(resp, (uint32_t)n);
            if (n > 0)
                memcpy(resp + 4, data, (size_t)n);
            p9_send_response(fd, P9_RREAD, tag, resp, 4 + (size_t)n);
            free(data);
            free(resp);
            printf("[plan9-stub] Tread(file): fid=%u off=%llu count=%u → Rread (%zd bytes)\n",
                   fid, (unsigned long long)offset, count, n);
        }
        break;
    }
    case P9_TWRITE: {
        /* Twrite body: fid[4] offset[8] count[4] data[count]
         * C5: Real file write via pwrite(). */
        uint32_t fid = 0;
        uint64_t offset = 0;
        uint32_t count = 0;
        if (body_len >= 16) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
            for (int i = 0; i < 8; i++)
                offset |= ((uint64_t)body[4 + i]) << (i * 8);
            count = (uint32_t)body[12]
                  | ((uint32_t)body[13] << 8)
                  | ((uint32_t)body[14] << 16)
                  | ((uint32_t)body[15] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (!entry) { p9_send_error(fd, tag, "unknown fid"); break; }

        ssize_t n = 0;
        if (count > 0 && body_len >= 16 + count) {
            n = pwrite(entry->fd, body + 16, count, (off_t)offset);
        }

        uint8_t resp[4];
        if (n < 0) {
            p9_put32(resp, 0);
            printf("[plan9-stub] Twrite: fid=%u off=%llu count=%u → error: %s\n",
                   fid, (unsigned long long)offset, count, strerror(errno));
        } else {
            p9_put32(resp, (uint32_t)n);
            printf("[plan9-stub] Twrite: fid=%u off=%llu count=%u → Rwrite (%zd bytes)\n",
                   fid, (unsigned long long)offset, count, n);
        }
        p9_send_response(fd, P9_RWRITE, tag, resp, 4);
        break;
    }
    case P9_TREMOVE: {
        /* Tremove body: fid[4]
         * C7: Unlink the file from the filesystem. */
        uint32_t fid = 0;
        if (body_len >= 4) {
            fid = (uint32_t)body[0]
                | ((uint32_t)body[1] << 8)
                | ((uint32_t)body[2] << 16)
                | ((uint32_t)body[3] << 24);
        }
        struct fid_entry *entry = fid_find(fid);
        if (!entry) { p9_send_error(fd, tag, "unknown fid"); break; }

        char fullpath[512];
        if (entry->path[0])
            snprintf(fullpath, sizeof(fullpath), "%s/%s", g_root_path, entry->path);
        else
            snprintf(fullpath, sizeof(fullpath), "%s", g_root_path);

        int rc = (entry->qtype & P9_QID_DIR) ? rmdir(fullpath) : unlink(fullpath);
        if (rc < 0) {
            printf("[plan9-stub] Tremove: fid=%u path=%s → error: %s\n",
                   fid, entry->path, strerror(errno));
        } else {
            printf("[plan9-stub] Tremove: fid=%u path=%s → success\n", fid, entry->path);
        }
        fid_remove(fid);
        p9_send_response(fd, P9_RREMOVE, tag, NULL, 0);
        break;
    }
    case P9_TFLUSH: {
        /* body: oldtag[2]. Respond Rflush (empty body). */
        p9_send_response(fd, P9_RFLUSH, tag, NULL, 0);
        printf("[plan9-stub] Tflush → Rflush\n");
        break;
    }
    default:
        p9_send_error(fd, tag, "not supported");
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
    /* Initialize fid_map: mark all slots as unused */
    for (int i = 0; i < MAX_FID_MAP; i++) {
        g_fid_map[i].fd = -1;
        g_fid_map[i].fid = 0;
        g_fid_map[i].path[0] = '\0';
    }
    g_fid_count = 0;
    g_next_qpath = 2;

    /* Open root directory for Plan9 file system */
    g_rootfd = open(g_root_path, O_DIRECTORY | O_CLOEXEC);
    if (g_rootfd < 0) {
        fprintf(stderr, "[plan9-stub] open root '%s' failed: %s\n",
                g_root_path, strerror(errno));
        _exit(1);
    }
    printf("[plan9-stub] root directory: %s\n", g_root_path);

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

    /* 0. Create a temp directory to serve as the Plan9 filesystem root.
     * This provides a real, writable directory for file I/O tests. */
    {
        const char *test_root = getenv("WSL_TEST_ROOT");
        if (test_root && test_root[0]) {
            snprintf(g_root_path, sizeof(g_root_path), "%s/plan9_XXXXXX", test_root);
        } else {
            snprintf(g_root_path, sizeof(g_root_path), "/tmp/wsl_plan9_XXXXXX");
        }
        if (mkdtemp(g_root_path) == NULL) {
            perror("[plan9] mkdtemp");
            return 0;
        }
        printf("[plan9-stub] created temp root: %s\n", g_root_path);
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

    /* Clean up the temp directory recursively */
    if (g_root_path[0]) {
        /* Remove all files and subdirectories in the temp root */
        DIR *dir = opendir(g_root_path);
        if (dir) {
            struct dirent *de;
            char fullpath[512];
            while ((de = readdir(dir)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                    continue;
                snprintf(fullpath, sizeof(fullpath), "%s/%s", g_root_path, de->d_name);
                if (de->d_type == DT_DIR)
                    rmdir(fullpath);
                else
                    unlink(fullpath);
            }
            closedir(dir);
        }
        rmdir(g_root_path);
        printf("[plan9-stub] cleaned up temp root: %s\n", g_root_path);
        g_root_path[0] = '\0';
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
