/*
 * SPDX-License-Identifier: MIT
 *
 * port_tracker.h - Localhost port tracker for WSL-For-FreeBSD.
 *
 * Task Group C: Discovers guest-side listening TCP ports and notifies the
 * Windows host so that host->guest localhost forwarding works (the mechanism
 * behind `localhost:<port>` access from Windows to WSL services).
 *
 * Architecture (mirrors src/linux/init/localhost.cpp):
 *   1. Periodically enumerate listening TCP sockets.
 *        - FreeBSD: sysctl("net.inet.tcp.pcblist") + "net.inet.tcp6.pcblist"
 *          (replaces /proc/net/tcp; FreeBSD has no procfs TCP list)
 *        - Linux test harness: /proc/net/tcp + /proc/net/tcp6
 *   2. Diff against the previous snapshot.
 *   3. For newly-bound ports send LxGnsMessagePortListenerRelayStart (59).
 *      For ports no longer listening send LxGnsMessagePortListenerRelayStop (60).
 *      Body is LX_GNS_PORT_LISTENER_RELAY { Family, Port, Address[4] } with
 *      Port/Address in network byte order (matches WSL reference).
 *
 * Filtering (matches WSL localhost.cpp behaviour):
 *   - Only forward ports bound to INADDR_ANY (0.0.0.0 / ::) or the loopback
 *     address (127.0.0.1 / ::1). Host-side services bound to the guest's
 *     external IP are not relayed.
 *
 * Reference:
 *   - src/linux/init/localhost.cpp  (ParseTcpFile, SockToRelayMessage,
 *                                    ScanProcNetTCP, RunPortTracker)
 *   - src/shared/inc/lxinitshared.h (LX_GNS_PORT_LISTENER_RELAY, enum values)
 *   - FreeBSD in_pcb.h / tcp_var.h  (xinpgen, xinpcb, xtcpcb, xsocket)
 *
 * NOTE: Header-only module (static inline) matching the gns_engine.h pattern.
 */
#ifndef PORT_TRACKER_H
#define PORT_TRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#endif

/* ---- WSL message type values (must match gns_engine.h / wsl_protocol.h) ---- */
#ifndef LxGnsMessagePortListenerRelayStart
#define LxGnsMessagePortListenerRelayStart 59
#endif
#ifndef LxGnsMessagePortListenerRelayStop
#define LxGnsMessagePortListenerRelayStop  60
#endif

/* ---- LX_GNS_PORT_LISTENER_RELAY wire format (lxinitshared.h) ----
 * Layout: MESSAGE_HEADER(12) + Family(2) + Port(2) + Address[4](16) = 32 bytes.
 * Port and Address are in network byte order (matching SockToRelayMessage). */
struct MESSAGE_HEADER_PT {
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};

typedef struct LX_GNS_PORT_LISTENER_RELAY {
    struct MESSAGE_HEADER_PT Header;
    unsigned short Family;        /* AF_INET / AF_INET6 (host order) */
    unsigned short Port;          /* network byte order */
    unsigned int   Address[4];    /* IPv4 uses [0]; IPv6 uses all 4 */
} LX_GNS_PORT_LISTENER_RELAY;

/* ---- Port tracker state ----
 * Holds the last snapshot of listening ports so we can diff on each poll. */
struct port_entry {
    unsigned short family;        /* AF_INET / AF_INET6 (host order) */
    unsigned short port;          /* host order (for comparison) */
    uint32_t       addr[4];       /* network byte order (wire format) */
};

#define PORT_TRACKER_INITIAL_CAP 16

struct port_tracker {
    struct port_entry *entries;   /* sorted, unique */
    size_t count;
    size_t cap;
};

/* Initialize a tracker. Returns 0 on success. */
static inline int port_tracker_init(struct port_tracker *t)
{
    t->cap = PORT_TRACKER_INITIAL_CAP;
    t->count = 0;
    t->entries = (struct port_entry *)calloc(t->cap, sizeof(struct port_entry));
    return t->entries ? 0 : -1;
}

static inline void port_tracker_free(struct port_tracker *t)
{
    free(t->entries);
    t->entries = NULL;
    t->count = t->cap = 0;
}

/* ---- Snapshot collection ----
 * Collects the current set of listening TCP ports into a freshly-allocated
 * array. Caller frees with free(). Returns count, or -1 on error. */

static inline int port_entry_matches_relay(const struct port_entry *e)
{
    /* Only relay wildcard and loopback binds (matches WSL localhost.cpp). */
    if (e->family == AF_INET) {
        uint32_t a = ntohl(e->addr[0]);
        return (a == INADDR_ANY)  /* 0.0.0.0 */
            || (a == INADDR_LOOPBACK); /* 127.0.0.1 */
    }
    if (e->family == AF_INET6) {
        /* :: (all zero) or ::1 (loopback, last word == 1) */
        bool all_zero = (e->addr[0] | e->addr[1] | e->addr[2] | e->addr[3]) == 0;
        bool v4_compat_loopback = (e->addr[0] == 0 && e->addr[1] == 0 &&
                                   e->addr[2] == htonl(0xFFFF) &&
                                   e->addr[3] == htonl(INADDR_LOOPBACK));
        bool v6_loopback = (e->addr[0] == 0 && e->addr[1] == 0 &&
                            e->addr[2] == 0 && e->addr[3] == htonl(1));
        return all_zero || v6_loopback || v4_compat_loopback;
    }
    return 0;
}

/* Comparator for sorting port_entry (family, then port, then addr). */
static inline int port_entry_cmp(const void *a, const void *b)
{
    const struct port_entry *ea = (const struct port_entry *)a;
    const struct port_entry *eb = (const struct port_entry *)b;
    if (ea->family != eb->family) return (int)ea->family - (int)eb->family;
    if (ea->port != eb->port)    return (int)ea->port - (int)eb->port;
    return memcmp(ea->addr, eb->addr, sizeof(ea->addr));
}

/* Deduplicate + sort an array in place. Returns new count. */
static inline size_t port_entry_dedup_sort(struct port_entry *arr, size_t n)
{
    if (n == 0) return 0;
    qsort(arr, n, sizeof(struct port_entry), port_entry_cmp);
    size_t out = 1;
    for (size_t i = 1; i < n; i++) {
        if (port_entry_cmp(&arr[out - 1], &arr[i]) != 0) {
            arr[out++] = arr[i];
        }
    }
    return out;
}

#ifdef __FreeBSD__
/* FreeBSD: enumerate via sysctl pcblist. */
static inline int collect_listening_ports(struct port_entry **out_arr)
{
    *out_arr = NULL;
    size_t total = 0;
    struct port_entry *result = NULL;

    /* Iterate over IPv4 (pcblist) and IPv6 (pcblist6). */
    const char *mibs[2] = { "net.inet.tcp.pcblist", "net.inet.tcp6.pcblist" };
    int families[2] = { AF_INET, AF_INET6 };

    for (int mi = 0; mi < 2; mi++) {
        size_t len = 0;
        if (sysctlbyname(mibs[mi], NULL, &len, NULL, 0) < 0 || len == 0) {
            /* IPv6 pcblist may be unavailable if INET6 is disabled — skip. */
            continue;
        }
        char *buf = (char *)malloc(len);
        if (!buf) { free(result); return -1; }
        if (sysctlbyname(mibs[mi], buf, &len, NULL, 0) < 0) {
            free(buf);
            continue;
        }

        /* pcblist layout: xinpgen header, then (xinpgen + xtcpcb) per entry.
         * xtcpcb starts with an xinpgen (opacket), then xinpcb, then xsocket.
         * We walk using the documented xi_len field of each xinpgen. */
        if (len < sizeof(struct xinpgen)) { free(buf); continue; }

        struct xinpgen *xig = (struct xinpgen *)buf;
        char *p = buf + sizeof(struct xinpgen);
        char *end = buf + len;

        while (p + sizeof(struct xinpgen) <= end) {
            struct xinpgen *entry = (struct xinpgen *)p;
            if (entry->xig_len < sizeof(struct xinpgen) || entry->xig_len == 0) {
                break; /* safety: malformed or end marker */
            }
            if (p + entry->xig_len > end) break;

            /* The xinpcb follows the leading xinpgen opacket. */
            struct xinpcb *inp = (struct xinpcb *)(p + sizeof(struct xinpgen));
            /* xsocket follows xinpcb. */
            struct xsocket *so = (struct xsocket *)((char *)inp + sizeof(struct xinpcb));

            /* Only interested in listening (SO_ACCEPTCONN) sockets. */
            if (so->so_qlimit != 0 || (so->so_options & SO_ACCEPTCONN)) {
                struct port_entry e;
                memset(&e, 0, sizeof(e));
                e.family = (unsigned short)families[mi];

                if (families[mi] == AF_INET) {
                    e.port = ntohs(inp->inp_lport);
                    e.addr[0] = inp->inp_laddr.s_addr;
                } else {
#ifdef INET6
                    e.port = ntohs(inp->inp_lport);
                    /* inp_inc6.laddr is the IPv6 local address. */
                    memcpy(e.addr, &inp->in6p_laddr, 16);
#else
                    /* No INET6: skip. */
                    p += entry->xig_len;
                    continue;
#endif
                }

                if (port_entry_matches_relay(&e)) {
                    if (total % 16 == 0) {
                        struct port_entry *tmp = (struct port_entry *)realloc(result,
                            (total + 16) * sizeof(struct port_entry));
                        if (!tmp) { free(result); free(buf); return -1; }
                        result = tmp;
                    }
                    result[total++] = e;
                }
            }
            p += entry->xig_len;
        }
        free(buf);
    }

    total = port_entry_dedup_sort(result, total);
    *out_arr = result;
    return (int)total;
}

#else /* Linux test harness: parse /proc/net/tcp[,6]. */
static inline int parse_proc_net_tcp(const char *path, int family,
                                     struct port_entry **out_arr, size_t *cap,
                                     size_t *count)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0; /* file may not exist in sandbox */

    char line[256];
    /* skip header */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        /* /proc/net/tcp format:
         *   sl local_address rem_address st ...
         * local_address is hex "IP:PORT", st==0A means LISTEN. */
        unsigned int local_ip, local_port, state;
        char local_addr_hex[33];
        /* IPv4 line: "%d: %08X:%04X %08X:%04X %02X ..." */
        if (family == AF_INET) {
            if (sscanf(line, " %*d: %8x:%4x %*8x:%*4x %2x",
                       &local_ip, &local_port, &state) != 3) continue;
            if (state != 0x0A) continue; /* TCP_LISTEN */
            if (local_port == 0) continue;

            struct port_entry e;
            memset(&e, 0, sizeof(e));
            e.family = AF_INET;
            e.port = (unsigned short)local_port;
            e.addr[0] = local_ip; /* /proc/net/tcp prints s_addr (network byte order) */

            if (!port_entry_matches_relay(&e)) continue;

            if (*count == *cap) {
                *cap += 16;
                struct port_entry *tmp = (struct port_entry *)realloc(*out_arr,
                    *cap * sizeof(struct port_entry));
                if (!tmp) { fclose(f); return -1; }
                *out_arr = tmp;
            }
            (*out_arr)[(*count)++] = e;
            added++;
        } else {
            /* IPv6 line: "%*d: %32s:%4x %*32s:%*4x %2x" */
            if (sscanf(line, " %*d: %32[0-9A-Fa-f]:%4x %*32[0-9A-Fa-f]:%*4x %2x",
                       local_addr_hex, &local_port, &state) != 3) continue;
            if (state != 0x0A) continue;
            if (local_port == 0) continue;

            struct port_entry e;
            memset(&e, 0, sizeof(e));
            e.family = AF_INET6;
            e.port = (unsigned short)local_port;
            /* Parse 32 hex chars into 4 uint32_t (network byte order). */
            for (int i = 0; i < 4; i++) {
                char word[9];
                memcpy(word, local_addr_hex + i * 8, 8);
                word[8] = '\0';
                e.addr[i] = (uint32_t)strtoul(word, NULL, 16);
            }

            if (!port_entry_matches_relay(&e)) continue;

            if (*count == *cap) {
                *cap += 16;
                struct port_entry *tmp = (struct port_entry *)realloc(*out_arr,
                    *cap * sizeof(struct port_entry));
                if (!tmp) { fclose(f); return -1; }
                *out_arr = tmp;
            }
            (*out_arr)[(*count)++] = e;
            added++;
        }
    }
    fclose(f);
    return added;
}

static inline int collect_listening_ports(struct port_entry **out_arr)
{
    *out_arr = NULL;
    size_t cap = 0, count = 0;
    if (parse_proc_net_tcp("/proc/net/tcp", AF_INET, out_arr, &cap, &count) < 0) {
        free(*out_arr); return -1;
    }
    if (parse_proc_net_tcp("/proc/net/tcp6", AF_INET6, out_arr, &cap, &count) < 0) {
        free(*out_arr); return -1;
    }
    count = port_entry_dedup_sort(*out_arr, count);
    return (int)count;
}
#endif /* __FreeBSD__ */

/* ---- Relay message sender ---- */
static inline int port_tracker_send_relay(int gns_fd, unsigned int msg_type,
                                          const struct port_entry *e,
                                          unsigned int seq)
{
    LX_GNS_PORT_LISTENER_RELAY msg;
    memset(&msg, 0, sizeof(msg));
    msg.Header.MessageType = msg_type;
    msg.Header.MessageSize = (unsigned int)sizeof(msg);
    msg.Header.SequenceNumber = seq;
    msg.Family = e->family;
    msg.Port = htons(e->port);
    memcpy(msg.Address, e->addr, sizeof(msg.Address));

    /* Reliable send handling EAGAIN. */
    const char *p = (const char *)&msg;
    size_t sent = 0;
    while (sent < sizeof(msg)) {
        ssize_t n = send(gns_fd, p + sent, sizeof(msg) - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = gns_fd, .events = POLLOUT };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* ---- One polling cycle ----
 * Scans current listening ports, diffs against tracker state, and sends
 * PortListenerRelayStart/Stop messages for added/removed ports.
 * Returns 0 on success (even if no changes), -1 on fatal error. */
static inline int port_tracker_poll(struct port_tracker *t, int gns_fd)
{
    struct port_entry *current = NULL;
    int cur_count = collect_listening_ports(&current);
    if (cur_count < 0) {
        return -1;
    }

    /* Diff: walk both sorted arrays. */
    size_t i = 0, j = 0;
    unsigned int seq = 0; /* guest-initiated notifications use seq 0 */
    int added = 0, removed = 0;

    while (i < (size_t)cur_count || j < t->count) {
        int cmp;
        if (i >= (size_t)cur_count) {
            cmp = 1; /* old entry not in current -> removed */
        } else if (j >= t->count) {
            cmp = -1; /* current entry not in old -> added */
        } else {
            cmp = port_entry_cmp(&current[i], &t->entries[j]);
        }

        if (cmp < 0) {
            /* new listening port */
            if (port_tracker_send_relay(gns_fd,
                    LxGnsMessagePortListenerRelayStart,
                    &current[i], seq) == 0) {
                printf("[port_tracker] +relay family=%u port=%u\n",
                       current[i].family, current[i].port);
                added++;
            }
            i++;
        } else if (cmp > 0) {
            /* port stopped listening */
            if (port_tracker_send_relay(gns_fd,
                    LxGnsMessagePortListenerRelayStop,
                    &t->entries[j], seq) == 0) {
                printf("[port_tracker] -relay family=%u port=%u\n",
                       t->entries[j].family, t->entries[j].port);
                removed++;
            }
            j++;
        } else {
            i++; j++;
        }
    }

    /* Swap in the new snapshot. */
    free(t->entries);
    t->entries = current;
    t->count = (size_t)cur_count;
#ifdef LOGGER_H
    g_log_stats.port_events += (unsigned long)(added + removed);
#endif
    if (t->count > t->cap) t->cap = t->count;

    if (added || removed) {
        printf("[port_tracker] poll complete: +%d -%d (now tracking %zu)\n",
               added, removed, t->count);
    }
    return 0;
}

/* ---- Localhost relay handler for StartSocketRelay(15) ----
 *
 * NOTE: The existing gns_engine.h already implements
 * gns_handle_start_socket_relay() for the inbound direction. That handler
 * accepts host-initiated relay requests. The port tracker above covers the
 * outbound direction (guest notifies host of local binds).
 *
 * The two directions form the complete WSL localhost relay:
 *   guest bind -> PortListenerRelayStart(59) -> host opens Windows port ->
 *   Windows connection -> host sends StartSocketRelay(15) -> guest relays.
 */

#endif /* PORT_TRACKER_H */
