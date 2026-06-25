/*
 * SPDX-License-Identifier: MIT
 *
 * gns_engine.h - Guest Network Service (GNS) engine for WSL-For-FreeBSD.
 *
 * Implements Phase 9 (Task Group C) networking functionality:
 *   C1: GNS engine skeleton (message dispatch loop)
 *   C2: NetworkInformation(4) handling + /etc/resolv.conf generation
 *   C3: Interface configuration (IP/gateway/routes) via LxGnsMessageInterfaceConfiguration
 *   C4: Port forwarding via StartSocketRelay(15)
 *   C5: QueryNetworkingMode(25) + QueryVmId(26) responses
 *
 * Architecture:
 *   - The GNS engine runs as a separate hvsock/TCP connection to the host,
 *     parallel to the init channel. The host sends LxGnsMessage* messages
 *     on this channel for network configuration.
 *   - NetworkInformation(4) arrives on the init channel and carries the
 *     resolv.conf content (FileHeader + FileContents string offsets).
 *   - StartSocketRelay(15) arrives on the init channel and starts a relay
 *     thread that forwards connections from the host to the guest.
 *   - QueryNetworkingMode(25) and QueryVmId(26) arrive on the init channel
 *     and expect RESULT_MESSAGE responses.
 *
 * Reference: src/linux/init/GnsEngine.cpp, NetworkManager.cpp,
 *            GnsPortTracker.cpp, config.cpp (ConfigUpdateNetworkInformation)
 *
 * NOTE: This is a header-only module to match the terminal_notify.h pattern.
 *       All functions are static inline to avoid linker conflicts.
 */
#ifndef GNS_ENGINE_H
#define GNS_ENGINE_H

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
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- WSL message type values (from lxinitshared.h LX_MESSAGE_TYPE enum) ---- */
/* C-group message types */
#define LxInitMessageNetworkInformation    4
#define LxInitMessageStartSocketRelay      15
#define LxInitMessageQueryNetworkingMode   25
#define LxInitMessageQueryVmId             26

/* GNS message types (correct enum values from lxinitshared.h) */
#define LxGnsMessageInterfaceConfiguration              53
#define LxGnsMessageResult                              54
#define LxGnsMessageNotification                        55
#define LxGnsMessagePortMappingRequest                  56
#define LxGnsMessagePortMappingResponse                 57
#define LxGnsMessageSetPortListener                     58
#define LxGnsMessagePortListenerRelayStart              59
#define LxGnsMessagePortListenerRelayStop               60
#define LxGnsMessageVmNicCreatedNotification            61
#define LxGnsMessageCreateDeviceRequest                 62
#define LxGnsMessageModifyGuestDeviceSettingRequest     63
#define LxGnsMessageLoopbackRoutesRequest               64
#define LxGnsMessageDeviceSettingRequest                65
#define LxGnsMessageIfStateChangeRequest                66
#define LxGnsMessageIfStateChangeResponse               67
#define LxGnsMessageInitialIpConfigurationNotification  68
#define LxGnsMessageSetupIpv6                           69
#define LxGnsMessageDnsTunneling                        70
#define LxGnsMessageNoOp                                71
#define LxGnsMessageGlobalNetFilter                     72
#define LxGnsMessageInterfaceNetFilter                  73
#define LxGnsMessageConnectTestRequest                  74
#define LxGnsMessageListenerRelay                       75

/* Result message types */
#define LxMessageResultUint32   78
#define LxMessageResultInt32    77
#define LxMessageResultBool     76

/* ---- Core structures ----
 * NOTE: These are only defined if not already provided by wsl_protocol.h
 *       (the TCP test harness includes wsl_protocol.h first). The production
 *       hvinit.c does not include wsl_protocol.h, so it needs these here. */
#ifndef WSL_PROTOCOL_H

struct MESSAGE_HEADER {
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};

/* RESULT_MESSAGE<uint32_t> (type 78) */
typedef struct RESULT_MESSAGE_UINT32 {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
} RESULT_MESSAGE_UINT32;

/* RESULT_MESSAGE<int32_t> (type 79) */
typedef struct RESULT_MESSAGE_INT32 {
    struct MESSAGE_HEADER Header;
    int32_t Result;
} RESULT_MESSAGE_INT32;

/* RESULT_MESSAGE<bool> (type 80) */
typedef struct RESULT_MESSAGE_BOOL {
    struct MESSAGE_HEADER Header;
    bool Result;
} RESULT_MESSAGE_BOOL;

/* NetworkInformation (host -> guest, type 4)
 * Buffer contains two NUL-terminated strings indexed by FileHeaderIndex
 * and FileContentsIndex. FileContents is written to /etc/resolv.conf. */
typedef struct LX_INIT_NETWORK_INFORMATION {
    struct MESSAGE_HEADER Header;
    unsigned int FileHeaderIndex;
    unsigned int FileContentsIndex;
    char Buffer[];
} LX_INIT_NETWORK_INFORMATION;

/* StartSocketRelay (host -> guest, type 15)
 * Asks the guest to start relaying connections from the host on the given
 * HvSocketPort to the local (Family, Port) tuple. */
typedef struct LX_INIT_START_SOCKET_RELAY {
    struct MESSAGE_HEADER Header;
    unsigned short Family;
    unsigned short Port;
    int HvSocketPort;
    size_t BufferSize;
} LX_INIT_START_SOCKET_RELAY;

/* QueryVmId (host -> guest, type 26)
 * Buffer contains a query; response is RESULT_MESSAGE<uint32_t>. */
typedef struct LX_INIT_QUERY_VM_ID {
    struct MESSAGE_HEADER Header;
    char Buffer[];
} LX_INIT_QUERY_VM_ID;

/* GNS InterfaceConfiguration (host -> guest, type 334)
 * Content is a JSON/config string describing interface settings.
 * Response is LX_GNS_RESULT. */
typedef struct LX_GNS_INTERFACE_CONFIGURATION {
    struct MESSAGE_HEADER Header;
    char Content[];
} LX_GNS_INTERFACE_CONFIGURATION;

/* GNS Result (guest -> host, type 335) */
typedef struct LX_GNS_RESULT {
    struct MESSAGE_HEADER Header;
    int Result;
    char Buffer[];
} LX_GNS_RESULT;

#endif /* WSL_PROTOCOL_H */

/* ---- Helper: reliable send/recv (duplicated from wsl_protocol.h to keep
 *      this header self-contained for the production hvinit.c build). ---- */
static inline int gns_send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

static inline int gns_recv_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Receive a full WSL message: header first, then payload.
 * Returns malloc'd buffer (caller frees) or NULL. */
static inline void *gns_recv_message(int fd, struct MESSAGE_HEADER *out_hdr)
{
    struct MESSAGE_HEADER hdr;
    if (gns_recv_all(fd, &hdr, sizeof(hdr)) < 0) return NULL;
    if (hdr.MessageSize < sizeof(hdr)) return NULL;

    size_t payload = hdr.MessageSize - sizeof(hdr);
    char *msg = malloc(hdr.MessageSize);
    if (!msg) return NULL;
    memcpy(msg, &hdr, sizeof(hdr));
    if (payload > 0) {
        if (gns_recv_all(fd, msg + sizeof(hdr), payload) < 0) {
            free(msg);
            return NULL;
        }
    }
    if (out_hdr) *out_hdr = hdr;
    return msg;
}

/* ===================================================================
 * C2: NetworkInformation(4) — generate /etc/resolv.conf
 * ===================================================================
 *
 * The Buffer contains NUL-terminated strings. FileHeaderIndex and
 * FileContentsIndex are offsets into Buffer selecting two strings.
 * FileContents is written verbatim to /etc/resolv.conf.
 *
 * Reference: src/linux/init/config.cpp ConfigUpdateNetworkInformation
 */
static inline int gns_handle_network_information(void *msg_buf, size_t msg_size)
{
    if (msg_size < sizeof(LX_INIT_NETWORK_INFORMATION)) {
        fprintf(stderr, "[gns] NetworkInformation: message too small (%zu)\n", msg_size);
        return -1;
    }
    LX_INIT_NETWORK_INFORMATION *ni = (LX_INIT_NETWORK_INFORMATION *)msg_buf;

    size_t header_fixed = offsetof(LX_INIT_NETWORK_INFORMATION, Buffer);
    if (msg_size <= header_fixed) {
        fprintf(stderr, "[gns] NetworkInformation: no buffer data\n");
        return -1;
    }
    size_t buf_size = msg_size - header_fixed;

    /* Extract FileHeader string (for logging) */
    const char *file_header = NULL;
    if (ni->FileHeaderIndex < buf_size)
        file_header = ni->Buffer + ni->FileHeaderIndex;

    /* Extract FileContents string (the resolv.conf body) */
    const char *file_contents = NULL;
    if (ni->FileContentsIndex < buf_size)
        file_contents = ni->Buffer + ni->FileContentsIndex;

    printf("[gns] NetworkInformation: FileHeader='%s', FileContents='%s'\n",
           file_header ? file_header : "(null)",
           file_contents ? file_contents : "(null)");

    /* Write /etc/resolv.conf */
    const char *resolv_path = "/etc/resolv.conf";
    FILE *fp = fopen(resolv_path, "w");
    if (!fp) {
        perror("[gns] fopen /etc/resolv.conf");
        return -1;
    }
    if (file_contents) {
        /* Write the contents (NUL-terminated string) */
        fputs(file_contents, fp);
        /* Ensure trailing newline if missing */
        size_t len = strlen(file_contents);
        if (len > 0 && file_contents[len - 1] != '\n')
            fputc('\n', fp);
    }
    if (fclose(fp) != 0) {
        perror("[gns] fclose /etc/resolv.conf");
        return -1;
    }
    printf("[gns] wrote %s\n", resolv_path);
    return 0;
}

/* ===================================================================
 * C3: InterfaceConfiguration (LxGnsMessageInterfaceConfiguration, 334)
 * ===================================================================
 *
 * The Content field is a config string (often JSON in the reference WSL).
 * For the FreeBSD port we parse simple "key=value" lines and apply them
 * via ifconfig/route commands. The reference WSL uses nlmsg (netlink)
 * which is Linux-specific; FreeBSD uses ioctl/ifconfig.
 *
 * Supported keys (best-effort):
 *   interface=<name>      e.g. "hn0"
 *   address=<ip>/<mask>   e.g. "192.168.1.10/24"
 *   gateway=<ip>          e.g. "192.168.1.1"
 *   mtu=<n>               e.g. "1500"
 *   up                    (flag: bring interface up)
 *
 * Returns a LX_GNS_RESULT message to the sender.
 */
static inline void gns_send_result(int fd, unsigned int seq, int result_code,
                                   const char *note)
{
    size_t note_len = note ? strlen(note) + 1 : 0;
    size_t msg_size = sizeof(LX_GNS_RESULT) + note_len;
    LX_GNS_RESULT *resp = malloc(msg_size);
    if (!resp) return;
    memset(resp, 0, msg_size);
    resp->Header.MessageType = LxGnsMessageResult;
    resp->Header.MessageSize = (unsigned int)msg_size;
    resp->Header.SequenceNumber = seq;
    resp->Result = result_code;
    if (note && note_len > 0)
        memcpy(resp->Buffer, note, note_len);
    gns_send_all(fd, resp, msg_size);
    free(resp);
}

/* Run a shell command, returning exit status (0 = success). */
static inline int gns_run_cmd(const char *cmd)
{
    int rc = system(cmd);
    if (rc == -1) {
        perror("[gns] system()");
        return -1;
    }
    return WEXITSTATUS(rc);
}

static inline int gns_handle_interface_configuration(int gns_fd, void *msg_buf,
                                                     size_t msg_size,
                                                     unsigned int seq)
{
    if (msg_size < sizeof(LX_GNS_INTERFACE_CONFIGURATION)) {
        gns_send_result(gns_fd, seq, -1, "msg too small");
        return -1;
    }
    LX_GNS_INTERFACE_CONFIGURATION *ic = (LX_GNS_INTERFACE_CONFIGURATION *)msg_buf;

    size_t header_fixed = offsetof(LX_GNS_INTERFACE_CONFIGURATION, Content);
    if (msg_size <= header_fixed) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    size_t content_size = msg_size - header_fixed;
    /* Make a NUL-terminated copy for safe parsing */
    char *content = malloc(content_size + 1);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "oom");
        return -1;
    }
    memcpy(content, ic->Content, content_size);
    content[content_size] = '\0';

    printf("[gns] InterfaceConfiguration content: '%s'\n", content);

    /* Parse simple key=value lines */
    char interface[64] = {0};
    char address[128] = {0};
    char gateway[64] = {0};
    char mtu[16] = {0};
    int bring_up = 0;

    char *line = content;
    char *saveptr = NULL;
    char *tok;
    while ((tok = strtok_r(line, "\n\r", &saveptr)) != NULL) {
        line = NULL;
        /* Strip leading whitespace */
        while (*tok == ' ' || *tok == '\t') tok++;
        if (*tok == '\0' || *tok == '#') continue;

        if (strncmp(tok, "interface=", 10) == 0) {
            strncpy(interface, tok + 10, sizeof(interface) - 1);
        } else if (strncmp(tok, "address=", 8) == 0) {
            strncpy(address, tok + 8, sizeof(address) - 1);
        } else if (strncmp(tok, "gateway=", 8) == 0) {
            strncpy(gateway, tok + 8, sizeof(gateway) - 1);
        } else if (strncmp(tok, "mtu=", 4) == 0) {
            strncpy(mtu, tok + 4, sizeof(mtu) - 1);
        } else if (strcmp(tok, "up") == 0) {
            bring_up = 1;
        }
    }

    int result = 0;
    char cmd[256];

    /* Apply address */
    if (interface[0] && address[0]) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s %s 2>/dev/null", interface, address);
        printf("[gns] running: %s\n", cmd);
        int r = gns_run_cmd(cmd);
        if (r != 0) {
            fprintf(stderr, "[gns] ifconfig address failed (rc=%d)\n", r);
            result = -1;
        }
    }

    /* Apply MTU */
    if (interface[0] && mtu[0]) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %s 2>/dev/null", interface, mtu);
        printf("[gns] running: %s\n", cmd);
        gns_run_cmd(cmd);  /* non-fatal */
    }

    /* Bring up */
    if (interface[0] && bring_up) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", interface);
        printf("[gns] running: %s\n", cmd);
        gns_run_cmd(cmd);
    }

    /* Add default route */
    if (gateway[0]) {
        snprintf(cmd, sizeof(cmd), "route add default %s 2>/dev/null", gateway);
        printf("[gns] running: %s\n", cmd);
        int r = gns_run_cmd(cmd);
        if (r != 0) {
            /* Route may already exist — try delete then add */
            snprintf(cmd, sizeof(cmd), "route delete default %s 2>/dev/null", gateway);
            gns_run_cmd(cmd);
            snprintf(cmd, sizeof(cmd), "route add default %s 2>/dev/null", gateway);
            gns_run_cmd(cmd);
        }
    }

    free(content);
    gns_send_result(gns_fd, seq, result, result == 0 ? "ok" : "partial");
    return result;
}

/* ===================================================================
 * C4: StartSocketRelay(15) — port forwarding
 * ===================================================================
 *
 * Starts a relay process that accepts connections on (Family, Port) and
 * forwards them to the host's HvSocketPort. In the TCP test harness,
 * HvSocketPort maps to a localhost TCP port.
 *
 * Reference: src/linux/init/GnsPortTracker.cpp, localhost.cpp
 *
 * We fork a child that runs a simple accept loop. Each accepted connection
 * is relayed by forking again (or using a thread). For simplicity we use
 * fork() per connection.
 */
struct relay_state {
    int listen_fd;       /* listening socket for incoming connections */
    int host_port;       /* host-side port to relay to */
    pid_t pid;           /* relay process pid */
};

/* Relay a single connection: bidirectional copy between client_fd and host_fd. */
static inline void gns_relay_connection(int client_fd, int host_port)
{
    int host_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (host_fd < 0) {
        perror("[relay] socket");
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)host_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(host_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[relay] connect to host");
        close(host_fd);
        return;
    }

    /* Bidirectional relay */
    char buf[4096];
    for (;;) {
        struct pollfd pfds[2];
        pfds[0].fd = client_fd;  pfds[0].events = POLLIN;  pfds[0].revents = 0;
        pfds[1].fd = host_fd;    pfds[1].events = POLLIN;  pfds[1].revents = 0;
        int rc = poll(pfds, 2, -1);
        if (rc <= 0) {
            if (rc < 0 && errno == EINTR) continue;
            break;
        }
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (gns_send_all(host_fd, buf, (size_t)n) < 0) break;
        }
        if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(host_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (gns_send_all(client_fd, buf, (size_t)n) < 0) break;
        }
    }
    close(host_fd);
}

static inline int gns_handle_start_socket_relay(int init_fd, void *msg_buf,
                                                size_t msg_size,
                                                struct relay_state *out_state)
{
    if (msg_size < sizeof(LX_INIT_START_SOCKET_RELAY)) {
        fprintf(stderr, "[gns] StartSocketRelay: message too small (%zu)\n", msg_size);
        return -1;
    }
    LX_INIT_START_SOCKET_RELAY *ssr = (LX_INIT_START_SOCKET_RELAY *)msg_buf;

    printf("[gns] StartSocketRelay: Family=%u, Port=%u, HvSocketPort=%d, BufferSize=%zu\n",
           ssr->Family, ssr->Port, ssr->HvSocketPort, ssr->BufferSize);

    /* Create listening socket on the guest side */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[gns] relay socket");
        return -1;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ssr->Port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[gns] relay bind");
        close(listen_fd);
        return -1;
    }
    if (listen(listen_fd, 16) < 0) {
        perror("[gns] relay listen");
        close(listen_fd);
        return -1;
    }

    /* Fork a relay daemon */
    pid_t pid = fork();
    if (pid < 0) {
        perror("[gns] relay fork");
        close(listen_fd);
        return -1;
    }
    if (pid == 0) {
        /* Child: accept loop */
        close(init_fd);  /* child doesn't need the init channel */
        for (;;) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                break;
            }
            pid_t cpid = fork();
            if (cpid == 0) {
                close(listen_fd);
                gns_relay_connection(client_fd, ssr->HvSocketPort);
                _exit(0);
            }
            close(client_fd);  /* parent doesn't need client */
        }
        _exit(0);
    }

    /* Parent: record state, close listen fd (child owns it) */
    close(listen_fd);
    if (out_state) {
        out_state->listen_fd = -1;  /* owned by child */
        out_state->host_port = ssr->HvSocketPort;
        out_state->pid = pid;
    }
    printf("[gns] relay started (pid=%d) on port %u -> host port %d\n",
           pid, ssr->Port, ssr->HvSocketPort);
    return 0;
}

/* ===================================================================
 * C5: QueryNetworkingMode(25) + QueryVmId(26)
 * ===================================================================
 *
 * QueryNetworkingMode: returns the networking mode as RESULT_MESSAGE<uint32_t>.
 *   0 = NAT (default for FreeBSD port)
 *   1 = Mirrored
 *   2 = Bridged
 *   3 = None
 *
 * QueryVmId: returns the VM GUID. The reference WSL returns a string in
 * the buffer; for the FreeBSD port we return a fixed GUID string.
 *
 * Reference: src/linux/init/config.cpp lines 434, 439
 */

/* Networking mode constants (from LX_INIT_NETWORKING_MODE enum) */
#define LX_INIT_NETWORKING_MODE_NAT        0
#define LX_INIT_NETWORKING_MODE_BRIDGED    1
#define LX_INIT_NETWORKING_MODE_MIRRORED   2

static inline int gns_handle_query_networking_mode(int init_fd, void *msg_buf,
                                                   size_t msg_size)
{
    (void)msg_buf; (void)msg_size;
    /* FreeBSD port defaults to NAT mode */
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    /* Echo the sequence number from the query */
    if (msg_size >= sizeof(struct MESSAGE_HEADER)) {
        struct MESSAGE_HEADER *qh = (struct MESSAGE_HEADER *)msg_buf;
        resp.Header.SequenceNumber = qh->SequenceNumber;
    }
    resp.Result = LX_INIT_NETWORKING_MODE_NAT;
    printf("[gns] QueryNetworkingMode -> NAT (0)\n");
    return gns_send_all(init_fd, &resp, sizeof(resp));
}

static inline int gns_handle_query_vm_id(int init_fd, void *msg_buf,
                                         size_t msg_size)
{
    /* Return a RESULT_MESSAGE<uint32_t> with a fixed VM ID for the FreeBSD port.
     * The reference WSL returns the actual VM GUID; we return a placeholder. */
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    if (msg_size >= sizeof(struct MESSAGE_HEADER)) {
        struct MESSAGE_HEADER *qh = (struct MESSAGE_HEADER *)msg_buf;
        resp.Header.SequenceNumber = qh->SequenceNumber;
    }
    /* Fixed VM ID for FreeBSD port (would be a real GUID in production) */
    resp.Result = 0xB5D00001;
    printf("[gns] QueryVmId -> 0xB5D00001\n");
    return gns_send_all(init_fd, &resp, sizeof(resp));
}

/* ===================================================================
 * C1: GNS Engine — message dispatch loop
 * ===================================================================
 *
 * Runs on a dedicated GNS channel (separate hvsock/TCP connection).
 * Dispatches LxGnsMessage* types to handlers.
 *
 * Returns when the channel is closed or on fatal error.
 */
static inline void gns_engine_loop(int gns_fd)
{
    printf("[gns] engine started (fd=%d)\n", gns_fd);

    /* Set non-blocking so we can handle partial reads */
    fcntl(gns_fd, F_SETFL, fcntl(gns_fd, F_GETFL) | O_NONBLOCK);

    for (;;) {
        struct pollfd pfd;
        pfd.fd = gns_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[gns] poll");
            break;
        }
        if (rc == 0) continue;

        if (pfd.revents & (POLLERR | POLLNVAL)) {
            fprintf(stderr, "[gns] poll error on gns_fd\n");
            break;
        }
        if (!(pfd.revents & POLLIN)) continue;

        struct MESSAGE_HEADER hdr;
        if (gns_recv_all(gns_fd, &hdr, sizeof(hdr)) < 0) {
            printf("[gns] host disconnected from gns channel\n");
            break;
        }

        if (hdr.MessageSize < sizeof(hdr)) {
            fprintf(stderr, "[gns] invalid message size %u\n", hdr.MessageSize);
            continue;
        }

        size_t payload_len = hdr.MessageSize - sizeof(hdr);
        char *full_msg = malloc(hdr.MessageSize);
        if (!full_msg) {
            perror("[gns] malloc");
            break;
        }
        memcpy(full_msg, &hdr, sizeof(hdr));
        if (payload_len > 0) {
            if (gns_recv_all(gns_fd, full_msg + sizeof(hdr), payload_len) < 0) {
                fprintf(stderr, "[gns] failed to read payload\n");
                free(full_msg);
                break;
            }
        }

        printf("[gns] received message type=%u (size=%u, seq=%u)\n",
               hdr.MessageType, hdr.MessageSize, hdr.SequenceNumber);

        switch (hdr.MessageType) {
        case LxGnsMessageInterfaceConfiguration:
            gns_handle_interface_configuration(gns_fd, full_msg,
                                               hdr.MessageSize,
                                               hdr.SequenceNumber);
            break;

        case LxGnsMessageNoOp:
            /* No-op: respond with success result */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "noop");
            break;

        case LxGnsMessageConnectTestRequest:
            /* Connectivity test: respond with success */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "connect ok");
            break;

        case LxGnsMessageInitialIpConfigurationNotification:
            /* Initial IP notification — acknowledge */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "ip configured");
            break;

        case LxGnsMessageSetupIpv6:
            /* IPv6 setup — acknowledge (IPv6 not yet supported) */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "ipv6 ack");
            break;

        case LxGnsMessageVmNicCreatedNotification:
            /* NIC created notification — acknowledge */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "nic created");
            break;

        default:
            printf("[gns] unhandled GNS message type %u — acknowledging\n",
                   hdr.MessageType);
            /* Acknowledge unknown messages to prevent host hangs */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "unhandled");
            break;
        }

        free(full_msg);
    }

    printf("[gns] engine exiting\n");
}

#endif /* GNS_ENGINE_H */
