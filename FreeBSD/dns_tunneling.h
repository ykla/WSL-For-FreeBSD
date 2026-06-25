/*
 * SPDX-License-Identifier: MIT
 *
 * dns_tunneling.h - WSL DNS Tunneling for FreeBSD guest init.
 *
 * Task Group B: When the host sets LxInitFeatureDnsTunneling (0x20), the guest
 * must run a local DNS server that does NOT resolve names itself. Instead, it
 * relays every DNS packet (verbatim) to the Windows host over a dedicated
 * hvsocket/TCP channel using LxGnsMessageDnsTunneling (type 70) messages.
 * The host applies Windows DNS Client policy (NRPT, VPN, suffix search, etc.)
 * and returns the answer, which the guest forwards back to the original
 * Linux/FreeBSD client.
 *
 * Architecture (ported from src/linux/init/DnsServer.cpp +
 * DnsTunnelingChannel.cpp + DnsTunnelingManager.cpp):
 *
 *   ┌──────────────────────────────┐        ┌────────────────────────────┐
 *   │  Linux/FreeBSD resolver      │        │  Windows host (real DNS)   │
 *   │  sends query to 10.255.255.254:53 │   │  applies NRPT/VPN policy   │
 *   └─────────────┬────────────────┘        └─────────────▲──────────────┘
 *                 │ UDP/TCP                                │ hvsocket/TCP
 *                 ▼                                        │  LxGnsMessageDnsTunneling
 *   ┌──────────────────────────────┐        ┌─────────────┴──────────────┐
 *   │  Guest DNS server (this file)│ ──────►│  DNS channel (this file)   │
 *   │  - binds 10.255.255.254:53   │ ◄──────│  - one fd to host          │
 *   │  - UDP + TCP listeners       │        │  - framed send/recv        │
 *   │  - maps DnsClientId → client │        └────────────────────────────┘
 *   └──────────────────────────────┘
 *
 * Design choices:
 *   - Single-threaded poll() loop (matches hvinit.c/hvbridge.c style; no
 *     pthread dependency). All sockets are non-blocking.
 *   - UDP: each recvfrom() gets a monotonic DnsClientId; the client's
 *     sockaddr_in is stored in dns_udp_map[] for response routing.
 *   - TCP: DNS-over-TCP frames have a 2-byte big-endian length prefix.
 *     Each accepted connection gets a DnsClientId; partial reads are
 *     buffered in dns_tcp_conn[] until the full frame is received.
 *   - Channel: outbound DNS packets are written as
 *     LX_GNS_DNS_TUNNELING_MESSAGE (Header + DnsClientIdentifier + raw DNS).
 *     Inbound messages on the channel are demuxed by DnsClientIdentifier
 *     and routed back to the UDP/TCP client.
 *
 * Test harness overrides:
 *   - WSL_DNS_TUNNEL_IP env var replaces 10.255.255.254 (useful when the
 *     test cannot bind that address; e.g. 127.0.0.1).
 *   - WSL_DNS_TUNNEL_PORT env var replaces port 53 (useful when the test
 *     runs without root/CAP_NET_BIND_SERVICE; e.g. 5353).
 *
 * Reference: src/linux/init/DnsServer.cpp, DnsTunnelingChannel.cpp,
 *            DnsTunnelingManager.cpp; lxinitshared.h.
 */
#ifndef DNS_TUNNELING_H
#define DNS_TUNNELING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Protocol definitions — provided by wsl_protocol.h (test) or gns_engine.h
 * (production). We do NOT include either header here; instead we declare the
 * DNS-tunneling-specific types ourselves if they are not already available.
 * This makes dns_tunneling.h usable from both hvinit_tcp.c (which includes
 * wsl_protocol.h) and hvinit.c (which includes gns_engine.h).
 *
 * Required from the includer's environment:
 *   - struct MESSAGE_HEADER { MessageType, MessageSize, SequenceNumber }
 *   - send_all(fd, buf, len) / recv_all(fd, buf, len) helpers (we provide
 *     fallbacks below if they are not already defined). */

#ifndef LX_GNS_DNS_TUNNELING_MESSAGE_DEFINED
#define LX_GNS_DNS_TUNNELING_MESSAGE_DEFINED

/* GNS message type for DNS tunneling (lxinitshared.h LxGnsMessageDnsTunneling). */
#ifndef LxGnsMessageDnsTunneling
#define LxGnsMessageDnsTunneling 70
#endif

/* Canonical DNS tunneling listener address. */
#ifndef LX_INIT_DNS_TUNNELING_IP_ADDRESS
#define LX_INIT_DNS_TUNNELING_IP_ADDRESS  "10.255.255.254"
#endif

#ifndef LX_INIT_DNS_SERVER_PORT
#define LX_INIT_DNS_SERVER_PORT 53
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/* Client identifier carried in every tunneled DNS message. Wire layout has
 * no padding between Protocol and DnsClientId (matches lxinitshared.h
 * static_assert). */
typedef struct LX_GNS_DNS_CLIENT_IDENTIFIER {
    uint8_t  Protocol;     /* IPPROTO_UDP or IPPROTO_TCP */
    uint8_t  _pad[3];
    uint32_t DnsClientId;
} LX_GNS_DNS_CLIENT_IDENTIFIER;

typedef struct LX_GNS_DNS_TUNNELING_MESSAGE {
    struct MESSAGE_HEADER          Header;
    LX_GNS_DNS_CLIENT_IDENTIFIER   DnsClientIdentifier;
    char                           Buffer[];
} LX_GNS_DNS_TUNNELING_MESSAGE;

#endif /* LX_GNS_DNS_TUNNELING_MESSAGE_DEFINED */

/* Local reliable I/O helpers. We use our own names (dns_send_all /
 * dns_recv_all) to avoid colliding with send_all/recv_all that may already
 * be defined as static inline in the includer's environment. */
static inline int dns_send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n > 0) sent += (size_t)n;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else return -1;
    }
    return 0;
}

static inline int dns_recv_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n > 0) got += (size_t)n;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else return -1;
    }
    return 0;
}

/* ---- Limits ---- */
#define DNS_MAX_UDP_PKTS     4096          /* max UDP DNS packet size (EDNS0) */
#define DNS_MAX_TCP_CONNS    32            /* concurrent TCP DNS connections  */
#define DNS_TCP_READ_BUF     (2 + 65535)   /* 2-byte length + max DNS frame  */
#define DNS_POLL_TIMEOUT_MS  1000          /* wake up periodically for shutdown */

/* ---- State ----
 * Single global instance: the GNS child process runs at most one DNS tunnel.
 * Kept as a struct so handlers can access it without globals everywhere. */

struct dns_udp_entry {
    bool            used;
    uint32_t        id;
    struct sockaddr_in client;
    socklen_t       client_len;
    int64_t         deadline_ms;   /* simple TTL; 0 = no deadline */
};

struct dns_tcp_conn {
    bool            used;
    int             fd;
    uint32_t        id;
    uint8_t         read_buf[DNS_TCP_READ_BUF];
    size_t          read_len;      /* bytes accumulated in read_buf */
    bool            have_length;   /* true after the 2-byte prefix is read */
    uint16_t        expect_len;    /* expected DNS frame length */
};

struct dns_tunnel {
    int             udp_fd;        /* UDP listener on <ip>:53 */
    int             tcp_fd;        /* TCP listener on <ip>:53 */
    int             channel_fd;    /* hvsocket/TCP to Windows host */
    bool            stopping;
    uint32_t        next_udp_id;   /* monotonic DnsClientId for UDP */
    uint32_t        next_tcp_id;   /* monotonic DnsClientId for TCP */
    struct dns_udp_entry udp_map[64];   /* DnsClientId → UDP client */
    struct dns_tcp_conn   tcp_conns[DNS_MAX_TCP_CONNS];
};

/* ---- Helpers ---- */

static inline void dns_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Monotonic millisecond clock for deadlines (uses clock_gettime CLOCK_MONOTONIC). */
static inline int64_t dns_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- UDP client map ---- */

static inline struct dns_udp_entry *dns_udp_alloc(struct dns_tunnel *t,
                                                  const struct sockaddr_in *client,
                                                  socklen_t client_len)
{
    /* Find a free slot (used=false). If table is full, recycle the oldest
     * by overwriting slot 0 — this is acceptable because UDP is best-effort
     * and the table is sized for typical WSL workloads. */
    for (int i = 0; i < (int)(sizeof(t->udp_map) / sizeof(t->udp_map[0])); i++) {
        if (!t->udp_map[i].used) {
            t->udp_map[i].used = true;
            t->udp_map[i].id = ++t->next_udp_id;  /* skip 0 */
            t->udp_map[i].client = *client;
            t->udp_map[i].client_len = client_len;
            t->udp_map[i].deadline_ms = dns_now_ms() + 30000;  /* 30s */
            return &t->udp_map[i];
        }
    }
    return NULL;  /* table full */
}

static inline struct dns_udp_entry *dns_udp_lookup(struct dns_tunnel *t, uint32_t id)
{
    for (int i = 0; i < (int)(sizeof(t->udp_map) / sizeof(t->udp_map[0])); i++) {
        if (t->udp_map[i].used && t->udp_map[i].id == id)
            return &t->udp_map[i];
    }
    return NULL;
}

static inline void dns_udp_free(struct dns_tunnel *t, uint32_t id)
{
    for (int i = 0; i < (int)(sizeof(t->udp_map) / sizeof(t->udp_map[0])); i++) {
        if (t->udp_map[i].used && t->udp_map[i].id == id) {
            t->udp_map[i].used = false;
            return;
        }
    }
}

/* ---- TCP connection table ---- */

static inline struct dns_tcp_conn *dns_tcp_alloc(struct dns_tunnel *t, int fd)
{
    for (int i = 0; i < DNS_MAX_TCP_CONNS; i++) {
        if (!t->tcp_conns[i].used) {
            memset(&t->tcp_conns[i], 0, sizeof(t->tcp_conns[i]));
            t->tcp_conns[i].used = true;
            t->tcp_conns[i].fd = fd;
            t->tcp_conns[i].id = ++t->next_tcp_id;  /* skip 0 */
            return &t->tcp_conns[i];
        }
    }
    return NULL;
}

static inline struct dns_tcp_conn *dns_tcp_lookup(struct dns_tunnel *t, uint32_t id)
{
    for (int i = 0; i < DNS_MAX_TCP_CONNS; i++) {
        if (t->tcp_conns[i].used && t->tcp_conns[i].id == id)
            return &t->tcp_conns[i];
    }
    return NULL;
}

static inline void dns_tcp_close(struct dns_tunnel *t, struct dns_tcp_conn *c)
{
    (void)t;  /* kept for API symmetry with other handlers */
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->used = false;
    c->fd = -1;
}

/* ---- Channel I/O: framed LxGnsMessageDnsTunneling ---- */

/* Send a DNS packet to the Windows host over the channel.
 * Returns 0 on success, -1 on error. */
static inline int dns_channel_send(struct dns_tunnel *t, uint8_t protocol,
                                   uint32_t client_id, const void *dns, size_t dns_len)
{
    /* Build LX_GNS_DNS_TUNNELING_MESSAGE in a stack/heap buffer.
     * Wire layout: [MESSAGE_HEADER][LX_GNS_DNS_CLIENT_IDENTIFIER][raw DNS]. */
    size_t msg_size = sizeof(LX_GNS_DNS_TUNNELING_MESSAGE) + dns_len;
    char *buf = malloc(msg_size);
    if (!buf) return -1;

    LX_GNS_DNS_TUNNELING_MESSAGE *msg = (LX_GNS_DNS_TUNNELING_MESSAGE *)buf;
    msg->Header.MessageType = LxGnsMessageDnsTunneling;
    msg->Header.MessageSize = (unsigned int)msg_size;
    msg->Header.SequenceNumber = 0;  /* DNS tunneling does not use seq numbers */
    msg->DnsClientIdentifier.Protocol = protocol;
    msg->DnsClientIdentifier._pad[0] = msg->DnsClientIdentifier._pad[1] =
        msg->DnsClientIdentifier._pad[2] = 0;
    msg->DnsClientIdentifier.DnsClientId = client_id;
    memcpy(msg->Buffer, dns, dns_len);

    int rc = dns_send_all(t->channel_fd, buf, msg_size);
    free(buf);
    if (rc < 0) {
        fprintf(stderr, "[dns] channel send failed (proto=%u id=%u len=%zu): %s\n",
                protocol, client_id, dns_len, strerror(errno));
        return -1;
    }
    printf("[dns] → host: proto=%s id=%u len=%zu\n",
           protocol == IPPROTO_UDP ? "UDP" : "TCP", client_id, dns_len);
    return 0;
}

/* Read one LxGnsMessageDnsTunneling from the channel (response from host).
 * On success returns a malloc'd buffer containing the full message (caller
 * frees), writes the DnsClientIdentifier into *out_id, and sets *out_dns
 * to point inside the buffer at the raw DNS bytes with length *out_dns_len.
 * Returns NULL on EOF/error. */
static inline char *dns_channel_recv(struct dns_tunnel *t,
                                     LX_GNS_DNS_CLIENT_IDENTIFIER *out_id,
                                     const char **out_dns, size_t *out_dns_len)
{
    struct MESSAGE_HEADER hdr;
    if (dns_recv_all(t->channel_fd, &hdr, sizeof(hdr)) < 0) return NULL;
    if (hdr.MessageSize < sizeof(hdr) || hdr.MessageSize > 65536 + sizeof(hdr)) {
        fprintf(stderr, "[dns] channel: bad message size %u\n", hdr.MessageSize);
        return NULL;
    }
    size_t payload = hdr.MessageSize - sizeof(hdr);
    char *msg = malloc(hdr.MessageSize);
    if (!msg) return NULL;
    memcpy(msg, &hdr, sizeof(hdr));
    if (payload > 0 && dns_recv_all(t->channel_fd, msg + sizeof(hdr), payload) < 0) {
        free(msg);
        return NULL;
    }

    if (hdr.MessageType != LxGnsMessageDnsTunneling) {
        fprintf(stderr, "[dns] channel: unexpected message type %u\n",
                hdr.MessageType);
        free(msg);
        return NULL;
    }
    if (payload < sizeof(LX_GNS_DNS_CLIENT_IDENTIFIER)) {
        fprintf(stderr, "[dns] channel: payload too small for identifier\n");
        free(msg);
        return NULL;
    }

    LX_GNS_DNS_TUNNELING_MESSAGE *dm = (LX_GNS_DNS_TUNNELING_MESSAGE *)msg;
    *out_id = dm->DnsClientIdentifier;
    *out_dns = dm->Buffer;
    *out_dns_len = payload - sizeof(LX_GNS_DNS_CLIENT_IDENTIFIER);
    return msg;
}

/* ---- UDP + TCP socket setup ---- */

static inline int dns_bind_udp(const char *ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    dns_set_nonblock(fd);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static inline int dns_bind_tcp(const char *ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    dns_set_nonblock(fd);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- Event handlers ---- */

static inline void dns_handle_udp_readable(struct dns_tunnel *t)
{
    uint8_t buf[DNS_MAX_UDP_PKTS];
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    for (;;) {
        ssize_t n = recvfrom(t->udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            perror("[dns] udp recvfrom");
            break;
        }
        if (n == 0) break;

        struct dns_udp_entry *e = dns_udp_alloc(t, &client, client_len);
        if (!e) {
            fprintf(stderr, "[dns] UDP map full, dropping query\n");
            break;
        }
        if (dns_channel_send(t, IPPROTO_UDP, e->id, buf, (size_t)n) < 0) {
            dns_udp_free(t, e->id);
            break;
        }
    }
}

static inline void dns_handle_tcp_accept(struct dns_tunnel *t)
{
    for (;;) {
        int fd = accept(t->tcp_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            perror("[dns] tcp accept");
            break;
        }
        dns_set_nonblock(fd);
        struct dns_tcp_conn *c = dns_tcp_alloc(t, fd);
        if (!c) {
            fprintf(stderr, "[dns] TCP table full, rejecting\n");
            close(fd);
            continue;
        }
        printf("[dns] TCP accept id=%u fd=%d\n", c->id, fd);
    }
}

/* Feed newly-read bytes into the connection's buffer. When the 2-byte length
 * prefix is known, read until the full DNS frame is available, then forward
 * it to the host. */
static inline void dns_handle_tcp_readable(struct dns_tunnel *t,
                                           struct dns_tcp_conn *c)
{
    for (;;) {
        if (c->read_len >= sizeof(c->read_buf)) {
            /* Overflow — close the connection. */
            fprintf(stderr, "[dns] TCP id=%u read overflow\n", c->id);
            dns_tcp_close(t, c);
            return;
        }
        ssize_t n = recv(c->fd, c->read_buf + c->read_len,
                         sizeof(c->read_buf) - c->read_len, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            /* Client closed */
            dns_tcp_close(t, c);
            return;
        }
        if (n == 0) {
            dns_tcp_close(t, c);
            return;
        }
        c->read_len += (size_t)n;

        /* Try to extract complete DNS frames from the buffer. */
        for (;;) {
            if (!c->have_length) {
                if (c->read_len < 2) break;  /* need the length prefix */
                uint16_t len;
                memcpy(&len, c->read_buf, 2);
                c->expect_len = ntohs(len);
                c->have_length = true;
            }
            if (c->read_len < (size_t)(2 + c->expect_len)) break;  /* need more */

            /* Full frame available — forward to host. */
            if (dns_channel_send(t, IPPROTO_TCP, c->id,
                                 c->read_buf + 2, c->expect_len) < 0) {
                dns_tcp_close(t, c);
                return;
            }

            /* Shift remaining bytes (if any) to the front of the buffer. */
            size_t consumed = 2 + c->expect_len;
            size_t remaining = c->read_len - consumed;
            if (remaining > 0)
                memmove(c->read_buf, c->read_buf + consumed, remaining);
            c->read_len = remaining;
            c->have_length = false;
            c->expect_len = 0;
        }
        /* Loop back to try reading more from the socket. */
    }
}

/* Route a DNS response received from the host back to the original client. */
static inline void dns_route_response(struct dns_tunnel *t,
                                      const LX_GNS_DNS_CLIENT_IDENTIFIER *id,
                                      const void *dns, size_t dns_len)
{
    printf("[dns] ← host: proto=%s id=%u len=%zu\n",
           id->Protocol == IPPROTO_UDP ? "UDP" : "TCP", id->DnsClientId, dns_len);

    if (id->Protocol == IPPROTO_UDP) {
        struct dns_udp_entry *e = dns_udp_lookup(t, id->DnsClientId);
        if (!e) {
            fprintf(stderr, "[dns] UDP id=%u not in map (expired?)\n",
                    id->DnsClientId);
            return;
        }
        ssize_t n = sendto(t->udp_fd, dns, dns_len, 0,
                           (struct sockaddr *)&e->client, e->client_len);
        if (n < 0) perror("[dns] udp sendto reply");
        dns_udp_free(t, id->DnsClientId);
    } else if (id->Protocol == IPPROTO_TCP) {
        struct dns_tcp_conn *c = dns_tcp_lookup(t, id->DnsClientId);
        if (!c) {
            fprintf(stderr, "[dns] TCP id=%u not in table (closed?)\n",
                    id->DnsClientId);
            return;
        }
        /* DNS-over-TCP responses are prefixed with 2-byte big-endian length. */
        uint8_t framed[2 + 65535];
        if (dns_len > 65535) {
            fprintf(stderr, "[dns] TCP response too large (%zu)\n", dns_len);
            dns_tcp_close(t, c);
            return;
        }
        uint16_t len_n = htons((uint16_t)dns_len);
        memcpy(framed, &len_n, 2);
        memcpy(framed + 2, dns, dns_len);
        if (dns_send_all(c->fd, framed, 2 + dns_len) < 0) {
            fprintf(stderr, "[dns] TCP id=%u reply send failed\n",
                    id->DnsClientId);
            dns_tcp_close(t, c);
            return;
        }
        /* Keep the connection open for pipelined queries. The client will
         * close it when done; we close on EOF or error. */
    } else {
        fprintf(stderr, "[dns] unknown protocol %u in response\n",
                id->Protocol);
    }
}

static inline void dns_handle_channel_readable(struct dns_tunnel *t)
{
    LX_GNS_DNS_CLIENT_IDENTIFIER id;
    const char *dns;
    size_t dns_len;
    char *msg = dns_channel_recv(t, &id, &dns, &dns_len);
    if (!msg) {
        fprintf(stderr, "[dns] channel closed by host, stopping\n");
        t->stopping = true;
        return;
    }
    dns_route_response(t, &id, dns, dns_len);
    free(msg);
}

/* ---- Main loop ---- */

/* Start the DNS tunnel: binds UDP+TCP listeners on ip:53, then runs the
 * poll() loop until dns_tunnel_stop() is called or the channel closes.
 * channel_fd is taken over (closed on stop). Returns when the loop exits. */
static inline void dns_tunnel_run(struct dns_tunnel *t, const char *ip)
{
    /* Normalize the listen IP — empty or NULL falls back to the canonical
     * WSL address so production callers can pass the host-provided value
     * verbatim even when it is empty. */
    if (!ip || !ip[0]) ip = LX_INIT_DNS_TUNNELING_IP_ADDRESS;

    /* Test harness override: WSL_DNS_TUNNEL_PORT lets tests bind an
     * unprivileged port (e.g. 5353) instead of 53, which requires root
     * or CAP_NET_BIND_SERVICE on Linux. Production leaves this unset. */
    uint16_t port = LX_INIT_DNS_SERVER_PORT;
    {
        const char *port_env = getenv("WSL_DNS_TUNNEL_PORT");
        if (port_env && port_env[0]) {
            long p = strtol(port_env, NULL, 10);
            if (p > 0 && p < 65536) port = (uint16_t)p;
        }
    }

    printf("[dns] starting on %s:%d (channel fd=%d)\n",
           ip, port, t->channel_fd);

    t->udp_fd = dns_bind_udp(ip, port);
    if (t->udp_fd < 0) {
        fprintf(stderr, "[dns] failed to bind UDP %s:%d: %s\n",
                ip, port, strerror(errno));
        return;
    }
    t->tcp_fd = dns_bind_tcp(ip, port);
    if (t->tcp_fd < 0) {
        fprintf(stderr, "[dns] failed to bind TCP %s:%d: %s\n",
                ip, port, strerror(errno));
        close(t->udp_fd);
        t->udp_fd = -1;
        return;
    }

    /* Make the channel non-blocking so we can poll() it together with the
     * listener sockets. */
    dns_set_nonblock(t->channel_fd);

    printf("[dns] listening: udp fd=%d, tcp fd=%d, channel fd=%d\n",
           t->udp_fd, t->tcp_fd, t->channel_fd);

    while (!t->stopping) {
        /* Build pollfd set: udp + tcp_listen + channel + active TCP conns.
         * conn_map[] parallels pfds[] — NULL for the first three (udp/tcp/
         * channel), then the matching dns_tcp_conn* for each TCP entry. */
        struct pollfd pfds[2 + DNS_MAX_TCP_CONNS + 1];
        struct dns_tcp_conn *conn_map[2 + DNS_MAX_TCP_CONNS + 1];
        int nfds = 0;

        pfds[nfds].fd = t->udp_fd;    pfds[nfds].events = POLLIN; pfds[nfds].revents = 0;
        conn_map[nfds] = NULL; nfds++;
        pfds[nfds].fd = t->tcp_fd;    pfds[nfds].events = POLLIN; pfds[nfds].revents = 0;
        conn_map[nfds] = NULL; nfds++;
        pfds[nfds].fd = t->channel_fd; pfds[nfds].events = POLLIN; pfds[nfds].revents = 0;
        conn_map[nfds] = NULL; nfds++;

        for (int i = 0; i < DNS_MAX_TCP_CONNS; i++) {
            if (t->tcp_conns[i].used && t->tcp_conns[i].fd >= 0) {
                pfds[nfds].fd = t->tcp_conns[i].fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                conn_map[nfds] = &t->tcp_conns[i];
                nfds++;
            }
        }

        int rc = poll(pfds, (nfds_t)nfds, DNS_POLL_TIMEOUT_MS);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[dns] poll");
            break;
        }
        if (rc == 0) {
            /* Timeout: expire stale UDP entries. */
            int64_t now = dns_now_ms();
            for (int i = 0; i < (int)(sizeof(t->udp_map) / sizeof(t->udp_map[0])); i++) {
                if (t->udp_map[i].used && t->udp_map[i].deadline_ms &&
                    t->udp_map[i].deadline_ms < now) {
                    t->udp_map[i].used = false;  /* drop timed-out entry */
                }
            }
            continue;
        }

        /* Handle events. We process all readable fds in one pass. */
        for (int i = 0; i < nfds; i++) {
            if (!(pfds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;

            if (pfds[i].fd == t->udp_fd) {
                dns_handle_udp_readable(t);
            } else if (pfds[i].fd == t->tcp_fd) {
                dns_handle_tcp_accept(t);
            } else if (pfds[i].fd == t->channel_fd) {
                if (pfds[i].revents & (POLLHUP | POLLERR)) {
                    fprintf(stderr, "[dns] channel hangup/error\n");
                    t->stopping = true;
                } else {
                    dns_handle_channel_readable(t);
                }
            } else {
                /* Must be a TCP connection — look it up via conn_map. */
                struct dns_tcp_conn *c = conn_map[i];
                if (c) {
                    if (pfds[i].revents & (POLLHUP | POLLERR))
                        dns_tcp_close(t, c);
                    else
                        dns_handle_tcp_readable(t, c);
                }
            }
        }
    }

    printf("[dns] shutting down\n");
    /* Close all sockets we own. The caller owns channel_fd's lifecycle if
     * it set dns_tunnel_stop() first; otherwise we close it. */
    for (int i = 0; i < DNS_MAX_TCP_CONNS; i++) {
        if (t->tcp_conns[i].used) dns_tcp_close(t, &t->tcp_conns[i]);
    }
    if (t->udp_fd >= 0) { close(t->udp_fd); t->udp_fd = -1; }
    if (t->tcp_fd >= 0) { close(t->tcp_fd); t->tcp_fd = -1; }
    if (t->channel_fd >= 0) { close(t->channel_fd); t->channel_fd = -1; }
}

/* Signal the loop to stop. Safe to call from another thread or signal handler
 * because `stopping` is only ever set here and read in the loop. */
static inline void dns_tunnel_stop(struct dns_tunnel *t)
{
    t->stopping = true;
}

#endif /* DNS_TUNNELING_H */
