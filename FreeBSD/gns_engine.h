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

/* Task Group C (localhost relay): port discovery + PortListenerRelay notify.
 * Included here so gns_engine_loop can poll the tracker each cycle. */
#include "port_tracker.h"

/* Conditional logger support: if logger.h has been included by the caller,
 * use LOG_* macros; otherwise fall back to raw printf/fprintf. */
#ifdef LOGGER_H
#define GNS_LOG_ERROR(mod, ...)   LOG_ERROR(mod, __VA_ARGS__)
#define GNS_LOG_WARN(mod, ...)    LOG_WARN(mod, __VA_ARGS__)
#define GNS_LOG_INFO(mod, ...)    LOG_INFO(mod, __VA_ARGS__)
#define GNS_LOG_DEBUG(mod, ...)   LOG_DEBUG(mod, __VA_ARGS__)
#else
#define GNS_LOG_ERROR(mod, ...)   do { fprintf(stderr, "[%s] ", mod); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define GNS_LOG_WARN(mod, ...)    do { fprintf(stderr, "[%s] ", mod); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define GNS_LOG_INFO(mod, ...)    do { printf("[%s] ", mod); printf(__VA_ARGS__); printf("\n"); } while(0)
#define GNS_LOG_DEBUG(mod, ...)   do { printf("[%s] ", mod); printf(__VA_ARGS__); printf("\n"); } while(0)
#endif

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
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ===================================================================
 * VM GUID helpers
 * ===================================================================
 *
 * Returns the host UUID for use in QueryVmId responses.
 *   - FreeBSD: /etc/hostid (written by hostid(1) from kern.hostuuid sysctl)
 *   - Linux (test env): /etc/machine-id, then /proc/sys/kernel/random/boot_id
 *   - Final fallback: fixed nil UUID placeholder
 *
 * Task Group G: QueryVmId returns actual VM GUID instead of placeholder.
 */
static inline int gns_get_vm_guid_string(char *buf, size_t buf_size)
{
    if (buf_size < 37) return -1;  /* 36 chars UUID + NUL */

    static const char *const try_paths[] = {
        "/etc/hostid",                              /* FreeBSD */
        "/etc/machine-id",                          /* Linux */
        "/proc/sys/kernel/random/boot_id",          /* Linux fallback */
        NULL,
    };

    for (int i = 0; try_paths[i] != NULL; i++) {
        FILE *f = fopen(try_paths[i], "r");
        if (!f) continue;
        size_t n = fread(buf, 1, buf_size - 1, f);
        fclose(f);
        if (n == 0) continue;
        buf[n] = '\0';
        /* Strip trailing whitespace */
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                         buf[n-1] == ' '  || buf[n-1] == '\t')) {
            buf[--n] = '\0';
        }
        if (n > 0) return 0;
    }

    /* All sources failed — return fixed placeholder UUID */
    snprintf(buf, buf_size, "00000000-0000-0000-0000-000000000000");
    return 0;
}

/* Derive a uint32_t VM ID from the GUID string (first 8 hex digits).
 * Used by the init-channel QueryVmId handler which returns RESULT_MESSAGE_UINT32. */
static inline uint32_t gns_get_vm_id_u32(void)
{
    char guid[64];
    if (gns_get_vm_guid_string(guid, sizeof(guid)) < 0) {
        return 0xB5D00001;  /* legacy fallback */
    }
    /* Collect first run of hex digits (up to 8) */
    char hex9[9];
    size_t i, j = 0;
    for (i = 0; guid[i] && j < 8; i++) {
        char c = guid[i];
        if (c == '-') break;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            hex9[j++] = c;
        } else {
            break;
        }
    }
    hex9[j] = '\0';
    if (j == 0) return 0xB5D00001;
    return (uint32_t)strtoul(hex9, NULL, 16);
}

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

/* Group B: init-channel message types (from lxinitshared.h enum) */
#define LxInitMessageKernelVersion             18
#define LxInitMessageAddVirtioFsDevice         19
#define LxInitMessageAddVirtioFsDeviceResponse 20
#define LxInitMessageRemountVirtioFsDevice     21
#define LxInitMessageStartDistroInit           22

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
/* typedef alias so production code can use `MESSAGE_HEADER` without `struct` */
typedef struct MESSAGE_HEADER MESSAGE_HEADER;

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
/* Guard macro: later headers (e.g. plan9_server.h) can check this to avoid
 * redefining RESULT_MESSAGE_BOOL when gns_engine.h has already provided it. */
#define RESULT_MESSAGE_BOOL_DEFINED

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

/* B1: MountDrvFs / RemountDrvfs (host -> guest, type 13)
 * Triggers DrvFs remount in the specified mount namespace (elevated/non-elevated).
 * Response is RESULT_MESSAGE_INT32 (type 77).
 * Reference: lxinitshared.h LX_INIT_MOUNT_DRVFS */
#define LxInitMessageRemountDrvfs 13
typedef struct LX_INIT_MOUNT_DRVFS {
    struct MESSAGE_HEADER Header;
    bool Admin;                   /* true = use elevated (admin) 9p server */
    unsigned int VolumesToMount;  /* bitmap of drive indices to mount */
    unsigned int UnreadableVolumes; /* bitmap of volumes that can't be read */
    int DefaultOwnerUid;          /* UID to use for file ownership */
} LX_INIT_MOUNT_DRVFS;

#endif /* WSL_PROTOCOL_H */

/* ===================================================================
 * Group B: VirtioFs device message structs
 * ===================================================================
 * Defined OUTSIDE the WSL_PROTOCOL_H guard so they are visible to both
 * production code (hvinit.c, which includes only gns_engine.h) and the
 * test harness (hvinit_tcp.c / wsl_mock_host.c, which include
 * wsl_protocol.h first, causing the guard block above to be skipped).
 * MESSAGE_HEADER and bool are already defined at this point by either
 * the guard block above (production) or wsl_protocol.h (test).
 *
 * Reference: src/shared/inc/lxinitshared.h lines 1066-1103 */
#ifndef LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE_DEFINED
#define LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE_DEFINED

/* AddVirtioFsDevice (19) — host -> guest request.
 * Buffer contains two NUL-terminated strings indexed by PathOffset and
 * OptionsOffset: the mount path and mount options. */
typedef struct {
    struct MESSAGE_HEADER Header;
    bool Admin;
    unsigned int PathOffset;    /* offset into Buffer for mount path */
    unsigned int OptionsOffset; /* offset into Buffer for mount options */
    char Buffer[];              /* contains path + options strings */
} LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE;

/* AddVirtioFsDeviceResponse (20) — guest -> host response.
 * Also used as the response for RemountVirtioFsDevice(21).
 * Buffer contains a NUL-terminated tag string indexed by TagOffset. */
typedef struct {
    struct MESSAGE_HEADER Header;
    int Result;
    unsigned int TagOffset;     /* offset into Buffer for tag string */
    char Buffer[];              /* contains tag string */
} LX_INIT_ADD_VIRTIOFS_SHARE_RESPONSE_MESSAGE;

/* RemountVirtioFsDevice (21) — host -> guest request.
 * Response is LX_INIT_ADD_VIRTIOFS_SHARE_RESPONSE_MESSAGE (type 20).
 * Buffer contains a NUL-terminated tag string indexed by TagOffset. */
typedef struct {
    struct MESSAGE_HEADER Header;
    bool Admin;
    unsigned int TagOffset;     /* offset into Buffer for tag string */
    char Buffer[];              /* contains tag string */
} LX_INIT_REMOUNT_VIRTIOFS_SHARE_MESSAGE;

#endif /* LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE_DEFINED */

/* E3: Global flag controlling /etc/resolv.conf generation.
 * Set from wsl.conf [network] generateResolvConf (default true).
 * When false, gns_handle_network_information() skips writing resolv.conf. */
static int g_generate_resolvconf = 1;

#ifndef GNS_RESOLVCONF_PATH_DEFAULT
#define GNS_RESOLVCONF_PATH_DEFAULT "/etc/resolv.conf"
#endif

/* Configurable resolv.conf target (default /etc/resolv.conf).
 * Tests set this via gns_set_resolvconf_path() when WSL_TEST_ROOT is set. */
static char g_resolvconf_path[256] = GNS_RESOLVCONF_PATH_DEFAULT;

static inline void gns_set_resolvconf_path(const char *path)
{
    if (path && path[0]) {
        strncpy(g_resolvconf_path, path, sizeof(g_resolvconf_path) - 1);
        g_resolvconf_path[sizeof(g_resolvconf_path) - 1] = '\0';
    } else {
        strncpy(g_resolvconf_path, GNS_RESOLVCONF_PATH_DEFAULT,
                sizeof(g_resolvconf_path) - 1);
        g_resolvconf_path[sizeof(g_resolvconf_path) - 1] = '\0';
    }
}

static inline const char *gns_get_resolvconf_path(void)
{
    return g_resolvconf_path;
}

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
        GNS_LOG_ERROR("gns", "NetworkInformation: message too small (%zu)", msg_size);
        return -1;
    }
    LX_INIT_NETWORK_INFORMATION *ni = (LX_INIT_NETWORK_INFORMATION *)msg_buf;

    size_t header_fixed = offsetof(LX_INIT_NETWORK_INFORMATION, Buffer);
    if (msg_size <= header_fixed) {
        GNS_LOG_ERROR("gns", "NetworkInformation: no buffer data");
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

    /* E3: Check generateResolvConf flag (from wsl.conf [network]).
     * When false, skip writing /etc/resolv.conf — the guest keeps
     * its existing resolv.conf (user-managed or pre-configured). */
    if (!g_generate_resolvconf) {
        printf("[gns] generateResolvConf=false, skipping %s write\n",
               g_resolvconf_path);
        return 0;
    }

    /* Write resolv.conf atomically: write to temp file, then rename.
     * This prevents a TOCTOU race where the test harness opens the file
     * between fopen("w") (which creates an empty file) and fputs (which
     * writes the content). With rename(), the file only appears with its
     * complete content. */
    const char *resolv_path = g_resolvconf_path;
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", resolv_path);
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        GNS_LOG_ERROR("gns", "fopen %s: %s", tmp_path, strerror(errno));
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
        fprintf(stderr, "[gns] fclose %s: %s\n", tmp_path, strerror(errno));
        return -1;
    }
    if (rename(tmp_path, resolv_path) < 0) {
        fprintf(stderr, "[gns] rename %s -> %s: %s\n",
                tmp_path, resolv_path, strerror(errno));
        unlink(tmp_path);
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

/* Run a shell command, returning exit status (0 = success).
 * On Linux (test harness), FreeBSD-specific ifconfig keywords (e.g. 'alias')
 * can cause ifconfig to attempt a DNS lookup that hangs indefinitely when
 * the nameserver is unreachable. Wrap with `timeout` to prevent test hangs.
 * Production (FreeBSD) runs commands directly. */
static inline int gns_run_cmd(const char *cmd)
{
#ifdef __FreeBSD__
    int rc = system(cmd);
#else
    char wrapped[512];
    int n = snprintf(wrapped, sizeof(wrapped), "timeout 3 %s", cmd);
    /* Task Group B: if command is too long, truncation is safer than
     * buffer overflow. The truncated command will likely fail. */
    if (n < 0 || (size_t)n >= sizeof(wrapped)) {
        fprintf(stderr, "[gns] gns_run_cmd: command truncated\n");
        return -1;
    }
    int rc = system(wrapped);
#endif
    if (rc == -1) {
        GNS_LOG_ERROR("gns", "system() failed: %s", strerror(errno));
        return -1;
    }
    return WEXITSTATUS(rc);
}

/* Forward declarations for JSON helpers (defined later in this header).
 * Needed because gns_handle_interface_configuration (Group D) uses them
 * before their full definitions appear. */
static inline int gns_json_get_string(const char *json, const char *key,
                                      char *out, size_t out_size);
static inline long gns_json_get_int(const char *json, const char *key, long def);
static inline int gns_json_get_bool(const char *json, const char *key, int def);
static inline int gns_json_get_subobject(const char *json, const char *key,
                                         char *out, size_t out_size);

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

    /* D: Parse interface configuration.
     * Supports two formats:
     * 1. HNSEndpoint JSON (starts with '{') — the format real WSL hosts send.
     *    Fields: MacAddress, IPAddress, PrefixLength, GatewayAddress,
     *    DNSServerList, PortFriendlyName, ID (GUID).
     * 2. Simple key=value lines (fallback for test harness).
     * Reference: HCN API HNSEndpoint JSON, src/linux/init/GnsEngine.cpp
     *            ApplyEndpointConfiguration(). */
    char interface[64] = {0};
    char address[128] = {0};
    char gateway[64] = {0};
    char mtu[16] = {0};
    int bring_up = 0;
    char dns_servers[256] = {0};
    int prefix_len = 0;

    /* Detect JSON format (HNSEndpoint) */
    const char *p = content;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '{') {
        /* D: HNSEndpoint JSON parsing */
        printf("[gns] InterfaceConfiguration: parsing as HNSEndpoint JSON\n");

        /* PortFriendlyName → interface name (preferred) */
        gns_json_get_string(content, "PortFriendlyName", interface, sizeof(interface));

        /* If no PortFriendlyName, try "Name" or "targetDeviceName" */
        if (!interface[0]) {
            gns_json_get_string(content, "Name", interface, sizeof(interface));
        }
        if (!interface[0]) {
            gns_json_get_string(content, "targetDeviceName", interface, sizeof(interface));
        }

        /* IPAddress (single string) or IPAddresses (array — take first) */
        gns_json_get_string(content, "IPAddress", address, sizeof(address));
        if (!address[0]) {
            /* Try IPAddresses array — extract first element */
            char iparr[256] = {0};
            if (gns_json_get_subobject(content, "IPAddresses",
                                        iparr, sizeof(iparr)) == 0 && iparr[0]) {
                /* iparr contains ["172.x.x.x", ...] — extract first quoted string */
                const char *q1 = strchr(iparr, '"');
                if (q1) {
                    const char *q2 = strchr(q1 + 1, '"');
                    if (q2) {
                        size_t alen = (size_t)(q2 - q1 - 1);
                        if (alen >= sizeof(address)) alen = sizeof(address) - 1;
                        memcpy(address, q1 + 1, alen);
                        address[alen] = '\0';
                    }
                }
            }
        }

        /* PrefixLength */
        prefix_len = (int)gns_json_get_int(content, "PrefixLength", 0);
        if (prefix_len > 0 && address[0]) {
            /* Append /prefix to address for ifconfig */
            size_t alen = strlen(address);
            if (alen + 8 < sizeof(address)) {
                snprintf(address + alen, sizeof(address) - alen, "/%d", prefix_len);
            }
        }

        /* GatewayAddress (single) or Gateways (array — take first) */
        gns_json_get_string(content, "GatewayAddress", gateway, sizeof(gateway));
        if (!gateway[0]) {
            char gwarr[256] = {0};
            if (gns_json_get_subobject(content, "Gateways",
                                        gwarr, sizeof(gwarr)) == 0 && gwarr[0]) {
                const char *q1 = strchr(gwarr, '"');
                if (q1) {
                    const char *q2 = strchr(q1 + 1, '"');
                    if (q2) {
                        size_t glen = (size_t)(q2 - q1 - 1);
                        if (glen >= sizeof(gateway)) glen = sizeof(gateway) - 1;
                        memcpy(gateway, q1 + 1, glen);
                        gateway[glen] = '\0';
                    }
                }
            }
        }

        /* DNSServerList (comma-separated) */
        gns_json_get_string(content, "DNSServerList", dns_servers, sizeof(dns_servers));

        /* MacAddress — apply if present */
        char mac_addr[32] = {0};
        gns_json_get_string(content, "MacAddress", mac_addr, sizeof(mac_addr));

        bring_up = 1;  /* HNSEndpoint always brings interface up */

        printf("[gns] HNSEndpoint: iface=%s addr=%s gw=%s prefix=%d dns=%s mac=%s\n",
               interface, address, gateway, prefix_len, dns_servers, mac_addr);

        /* Apply MAC address if present */
        if (interface[0] && mac_addr[0]) {
            char cmd[192];
            /* Convert "00-15-5D-xx-xx-xx" to "00:15:5d:xx:xx:xx" for ifconfig */
            char ifconfig_mac[32] = {0};
            size_t mi = 0;
            for (size_t i = 0; mac_addr[i] && mi < sizeof(ifconfig_mac) - 1; i++) {
                if (mac_addr[i] == '-') {
                    ifconfig_mac[mi++] = ':';
                } else {
                    ifconfig_mac[mi++] = tolower((unsigned char)mac_addr[i]);
                }
            }
            snprintf(cmd, sizeof(cmd), "ifconfig %s ether %s 2>/dev/null",
                     interface, ifconfig_mac);
            printf("[gns] running: %s\n", cmd);
            gns_run_cmd(cmd);
        }

        /* Apply DNS servers to resolv.conf if present */
        if (dns_servers[0]) {
            printf("[gns] HNSEndpoint: DNS servers: %s\n", dns_servers);
            /* The DNS update is handled by gns_handle_network_information
             * which writes resolv.conf. Here we just log it. */
        }
    } else {
        /* Fallback: simple key=value lines (test harness format) */
        printf("[gns] InterfaceConfiguration: parsing as key=value lines\n");

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
 * D-group: LxGnsMessageNotification(55) — HNS state changes
 * ===================================================================
 *
 * The host sends Notification(55) on the GNS channel to apply ongoing
 * network state changes. The payload is a JSON string of the form:
 *   {
 *     "ResourceType": "Route|IPAddress|DNS|Interface|MacAddress",
 *     "RequestType":  "Add|Remove|Update|Refresh|Reset",
 *     "Settings":     { ... type-specific ... },
 *     "targetDeviceName": "<iface>"    // optional
 *   }
 *
 * This is the primary state-change channel for NAT mode (the FreeBSD
 * default). Reference: src/linux/init/GnsEngine.cpp ProcessNotification,
 * ProcessRouteChange, ProcessIpAddressChange, ProcessDNSChange,
 * ProcessLinkChange, ProcessMacAddressChange. JSON schema:
 * src/shared/inc/hns_schema.h (Route, IPAddress, DNS, NetworkInterface,
 * MacAddress, ModifyGuestEndpointSettingRequest, GuestEndpointResourceType,
 * ModifyRequestType).
 *
 * Note: the reference opens the adapter by GUID; FreeBSD uses interface
 * names. We use targetDeviceName if present, else g_default_interface
 * (default "lo0" for safe testing; production sets this to the NIC).
 *
 * All apply paths are best-effort (shell out to ifconfig/route) and always
 * acknowledge with LX_GNS_RESULT so the host does not hang.
 */

/* Default interface used when Notification omits targetDeviceName.
 * Tests use "lo0" (always present, safe). Production should set this
 * to the actual NIC (e.g. "hn0" for Hyper-V netvsc, "vtnet0" for virtio). */
static char g_default_interface[32] = "lo0";

static inline void gns_set_default_interface(const char *name)
{
    if (name && name[0]) {
        strncpy(g_default_interface, name, sizeof(g_default_interface) - 1);
        g_default_interface[sizeof(g_default_interface) - 1] = '\0';
    }
}

/* ---- Minimal JSON value extractor ----
 * Targets the fixed HNS schema; not a general-purpose parser. Finds
 * `"key"` followed by `:` and returns a pointer to the value start.
 * String values are returned without surrounding quotes via the _string
 * helper; numbers/bools via _int/_bool. Sub-objects are copied into a
 * caller buffer via _subobject. All return 0 on success, -1 if absent. */

static inline const char *gns_json_find_value(const char *json, const char *key)
{
    char pat[64];
    int n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n <= 0 || n >= (int)sizeof(pat)) return NULL;
    const char *p = json;
    for (;;) {
        p = strstr(p, pat);
        if (!p) return NULL;
        p += n;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ':') { p++; while (*p == ' ' || *p == '\t') p++; return p; }
    }
}

static inline int gns_json_get_string(const char *json, const char *key,
                                      char *out, size_t outsz)
{
    const char *v = gns_json_find_value(json, key);
    if (!v || *v != '"') return -1;
    v++;
    size_t i = 0;
    while (*v && *v != '"' && i + 1 < outsz) {
        if (*v == '\\' && v[1]) v++;  /* skip escaped char */
        out[i++] = *v++;
    }
    out[i] = '\0';
    return 0;
}

static inline long gns_json_get_int(const char *json, const char *key, long def)
{
    const char *v = gns_json_find_value(json, key);
    if (!v) return def;
    return strtol(v, NULL, 10);
}

static inline int gns_json_get_bool(const char *json, const char *key, int def)
{
    const char *v = gns_json_find_value(json, key);
    if (!v) return def;
    if (strncmp(v, "true", 4) == 0) return 1;
    if (strncmp(v, "false", 5) == 0) return 0;
    return def;
}

/* Copy the {...} sub-object for `key` into `out` (NUL-terminated).
 * Returns 0 on success, -1 if absent/not an object. */
static inline int gns_json_get_subobject(const char *json, const char *key,
                                         char *out, size_t outsz)
{
    const char *v = gns_json_find_value(json, key);
    if (!v || *v != '{') return -1;
    int depth = 0;
    size_t i = 0;
    while (*v && i + 1 < outsz) {
        char c = *v++;
        if (c == '{') depth++;
        else if (c == '}') { depth--; if (depth == 0) { out[i++] = c; break; } }
        else if (c == '"') {  /* copy string literal verbatim, honoring escapes */
            out[i++] = c;
            while (*v && i + 1 < outsz) {
                char ch = *v++;
                out[i++] = ch;
                if (ch == '\\' && *v) {
                    out[i++] = *v++;  /* copy escaped char so \" won't terminate */
                } else if (ch == '"') {
                    break;  /* closing quote */
                }
            }
            continue;
        }
        out[i++] = c;
    }
    out[i] = '\0';
    return i > 0 ? 0 : -1;
}

/* ---- Apply helpers (best-effort, via ifconfig/route) ---- */

/* ResourceType=Route. Settings: NextHop, DestinationPrefix, SitePrefixLength,
 * Metric, Family (2=AF_INET, 23=AF_INET6 on Windows; we only act on IPv4). */
static inline void gns_apply_route_change(const char *settings,
                                          const char *request_type)
{
    char next_hop[64] = {0};
    char dest_prefix[80] = {0};
    gns_json_get_string(settings, "NextHop", next_hop, sizeof(next_hop));
    gns_json_get_string(settings, "DestinationPrefix", dest_prefix, sizeof(dest_prefix));

    printf("[gns] Route %s: NextHop=%s DestPrefix=%s\n",
           request_type, next_hop, dest_prefix);

    if (strcmp(request_type, "Reset") == 0) {
        /* Reset routing table — flush default routes (best-effort) */
        gns_run_cmd("route delete default 2>/dev/null");
        return;
    }

    if (!next_hop[0]) return;

    char cmd[256];
    if (strcmp(request_type, "Remove") == 0) {
        /* Default route removal */
        if (dest_prefix[0] == '\0' || strncmp(dest_prefix, "0.0.0.0", 7) == 0) {
            snprintf(cmd, sizeof(cmd), "route delete default %s 2>/dev/null", next_hop);
        } else {
            snprintf(cmd, sizeof(cmd), "route delete %s %s 2>/dev/null", dest_prefix, next_hop);
        }
        gns_run_cmd(cmd);
    } else {
        /* Add / Update → add (update is best-effort: delete then add) */
        if (strcmp(request_type, "Update") == 0) {
            snprintf(cmd, sizeof(cmd), "route delete default %s 2>/dev/null", next_hop);
            gns_run_cmd(cmd);
        }
        if (dest_prefix[0] == '\0' || strncmp(dest_prefix, "0.0.0.0", 7) == 0) {
            snprintf(cmd, sizeof(cmd), "route add default %s 2>/dev/null", next_hop);
        } else {
            snprintf(cmd, sizeof(cmd), "route add %s %s 2>/dev/null", dest_prefix, next_hop);
        }
        gns_run_cmd(cmd);
    }
}

/* ResourceType=IPAddress. Settings: Address, Family, OnLinkPrefixLength. */
static inline void gns_apply_ip_change(const char *iface,
                                       const char *settings,
                                       const char *request_type)
{
    char address[64] = {0};
    gns_json_get_string(settings, "Address", address, sizeof(address));
    long prefix = gns_json_get_int(settings, "OnLinkPrefixLength", 0);

    printf("[gns] IPAddress %s: %s/%ld on %s\n",
           request_type, address, prefix, iface);

    if (!address[0] || !iface[0]) return;

    char cmd[256];
    if (strcmp(request_type, "Remove") == 0) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s delete %s 2>/dev/null", iface, address);
    } else {
        /* Add / Update. FreeBSD: ifconfig iface address[/mask] alias */
        if (prefix > 0 && prefix <= 32) {
            snprintf(cmd, sizeof(cmd), "ifconfig %s %s/%ld alias 2>/dev/null",
                     iface, address, prefix);
        } else {
            snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask 255.255.255.255 alias 2>/dev/null",
                     iface, address);
        }
        if (strcmp(request_type, "Update") == 0) {
            gns_run_cmd(cmd);  /* add first */
            snprintf(cmd, sizeof(cmd), "ifconfig %s %s/%ld alias 2>/dev/null",
                     iface, address, prefix > 0 ? prefix : 32);
        }
    }
    gns_run_cmd(cmd);
}

/* ResourceType=DNS. Settings: Domain, Search, ServerList, Options.
 * Writes /etc/resolv.conf (path configurable via g_resolvconf_path). */
static inline void gns_apply_dns_change(const char *settings,
                                        const char *request_type)
{
    if (strcmp(request_type, "Remove") == 0) {
        printf("[gns] DNS Remove: ignored (next add/update overwrites)\n");
        return;
    }

    char domain[128] = {0};
    char search[256] = {0};
    char server_list[512] = {0};
    char options[256] = {0};
    gns_json_get_string(settings, "Domain", domain, sizeof(domain));
    gns_json_get_string(settings, "Search", search, sizeof(search));
    gns_json_get_string(settings, "ServerList", server_list, sizeof(server_list));
    gns_json_get_string(settings, "Options", options, sizeof(options));

    printf("[gns] DNS %s: servers=%s domain=%s search=%s\n",
           request_type, server_list, domain, search);

    if (!g_generate_resolvconf) {
        printf("[gns] generateResolvConf=false, skipping %s write\n",
               g_resolvconf_path);
        return;
    }

    FILE *fp = fopen(g_resolvconf_path, "w");
    if (!fp) {
        fprintf(stderr, "[gns] DNS fopen %s: %s\n", g_resolvconf_path, strerror(errno));
        return;
    }
    if (options[0]) fputs(options, fp);
    /* ServerList is comma-separated */
    char servers[512];
    strncpy(servers, server_list, sizeof(servers) - 1);
    servers[sizeof(servers) - 1] = '\0';
    char *save = NULL;
    for (char *s = strtok_r(servers, ",", &save); s; s = strtok_r(NULL, ",", &save)) {
        while (*s == ' ') s++;
        fprintf(fp, "nameserver %s\n", s);
    }
    if (domain[0]) fprintf(fp, "domain %s\n", domain);
    if (search[0]) {
        /* Search is comma-separated; resolv.conf wants space-separated */
        char search_out[256] = {0};
        char *sv = NULL;
        for (char *s = strtok_r(search, ",", &sv); s; s = strtok_r(NULL, ",", &sv)) {
            while (*s == ' ') s++;
            if (search_out[0]) strncat(search_out, " ", sizeof(search_out) - strlen(search_out) - 1);
            strncat(search_out, s, sizeof(search_out) - strlen(search_out) - 1);
        }
        if (search_out[0]) fprintf(fp, "search %s\n", search_out);
    }
    fclose(fp);
    printf("[gns] wrote %s\n", g_resolvconf_path);
}

/* ResourceType=Interface. Settings: Connected (bool), NlMtu, Metric. */
static inline void gns_apply_link_change(const char *iface,
                                         const char *settings,
                                         const char *request_type)
{
    int connected = gns_json_get_bool(settings, "Connected", 1);
    long mtu = gns_json_get_int(settings, "NlMtu", 0);

    printf("[gns] Interface %s: %s mtu=%ld on %s\n",
           request_type, connected ? "up" : "down", mtu, iface);

    if (!iface[0]) return;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ifconfig %s %s 2>/dev/null",
             iface, connected ? "up" : "down");
    gns_run_cmd(cmd);
    if (connected && mtu > 0) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %ld 2>/dev/null", iface, mtu);
        gns_run_cmd(cmd);
    }
}

/* ResourceType=MacAddress. Settings: PhysicalAddress (e.g. "00-15-5d-..."). */
static inline void gns_apply_mac_change(const char *iface,
                                        const char *settings)
{
    char mac[64] = {0};
    gns_json_get_string(settings, "PhysicalAddress", mac, sizeof(mac));
    printf("[gns] MacAddress: %s on %s (best-effort)\n", mac, iface);
    if (!mac[0] || !iface[0]) return;
    /* FreeBSD ifconfig uses ':' separator; HNS uses '-'. Convert. */
    char bsd_mac[64];
    size_t j = 0;
    for (size_t i = 0; mac[i] && j + 1 < sizeof(bsd_mac); i++) {
        bsd_mac[j++] = (mac[i] == '-') ? ':' : mac[i];
    }
    bsd_mac[j] = '\0';
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ifconfig %s link %s 2>/dev/null", iface, bsd_mac);
    gns_run_cmd(cmd);
}

/* Main Notification(55) dispatcher. msg_buf is the full message (header+body);
 * the body is a NUL-terminated JSON string starting after the fixed header. */
static inline int gns_handle_notification(int gns_fd, void *msg_buf,
                                          size_t msg_size, unsigned int seq)
{
    if (msg_size < sizeof(struct MESSAGE_HEADER)) {
        gns_send_result(gns_fd, seq, -1, "msg too small");
        return -1;
    }
    /* The payload follows the 12-byte MESSAGE_HEADER. Treat it as a JSON
     * string. (Wire layout matches LX_GNS_INTERFACE_CONFIGURATION.) */
    size_t header_fixed = sizeof(struct MESSAGE_HEADER);
    if (msg_size <= header_fixed) {
        gns_send_result(gns_fd, seq, -1, "no payload");
        return -1;
    }
    size_t body_len = msg_size - header_fixed;
    char *body = malloc(body_len + 1);
    if (!body) {
        gns_send_result(gns_fd, seq, -1, "oom");
        return -1;
    }
    memcpy(body, (char *)msg_buf + header_fixed, body_len);
    body[body_len] = '\0';

    printf("[gns] Notification(55) payload: %s\n", body);

    char resource_type[32] = {0};
    char request_type[16] = {0};
    char target_device[32] = {0};
    gns_json_get_string(body, "ResourceType", resource_type, sizeof(resource_type));
    gns_json_get_string(body, "RequestType", request_type, sizeof(request_type));
    gns_json_get_string(body, "targetDeviceName", target_device, sizeof(target_device));

    const char *iface = target_device[0] ? target_device : g_default_interface;

    int result = 0;
    if (strcmp(resource_type, "Route") == 0) {
        char settings[1024];
        if (gns_json_get_subobject(body, "Settings", settings, sizeof(settings)) == 0)
            gns_apply_route_change(settings, request_type);
        else
            result = -1;
    } else if (strcmp(resource_type, "IPAddress") == 0) {
        char settings[1024];
        if (gns_json_get_subobject(body, "Settings", settings, sizeof(settings)) == 0)
            gns_apply_ip_change(iface, settings, request_type);
        else
            result = -1;
    } else if (strcmp(resource_type, "DNS") == 0) {
        char settings[1024];
        if (gns_json_get_subobject(body, "Settings", settings, sizeof(settings)) == 0)
            gns_apply_dns_change(settings, request_type);
        else
            result = -1;
    } else if (strcmp(resource_type, "Interface") == 0) {
        char settings[512];
        if (gns_json_get_subobject(body, "Settings", settings, sizeof(settings)) == 0)
            gns_apply_link_change(iface, settings, request_type);
        else
            result = -1;
    } else if (strcmp(resource_type, "MacAddress") == 0) {
        char settings[256];
        if (gns_json_get_subobject(body, "Settings", settings, sizeof(settings)) == 0)
            gns_apply_mac_change(iface, settings);
        else
            result = -1;
    } else {
        printf("[gns] Notification: unknown ResourceType '%s' — acknowledging\n",
               resource_type);
        result = 0;  /* ack unknown to avoid host hang */
    }

    free(body);
    gns_send_result(gns_fd, seq, result,
                    result == 0 ? "notification applied" : "partial");
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
    (void)msg_size;
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    /* Echo the sequence number from the query */
    if (msg_size >= sizeof(struct MESSAGE_HEADER)) {
        struct MESSAGE_HEADER *qh = (struct MESSAGE_HEADER *)msg_buf;
        resp.Header.SequenceNumber = qh->SequenceNumber;
    }

    /* Group F: Read networking mode from WSL2_NETWORKING_MODE env var
     * instead of hardcoding NAT. The host (main.cpp) sets this env var
     * to an LX_MINI_INIT_NETWORKING_MODE enum value before launching the
     * guest init: None=0, Nat=1, Bridged=2, Mirrored=3, VirtioProxy=4.
     * We map these to our internal LX_INIT_NETWORKING_MODE_* constants
     * (NAT=0, BRIDGED=1, MIRRORED=2) which are returned to the host.
     * Default (unset/None/Nat) is NAT. Reference: init.cpp:2242-2247. */
    uint32_t mode = LX_INIT_NETWORKING_MODE_NAT;
    const char *env = getenv("WSL2_NETWORKING_MODE");
    if (env && env[0]) {
        int v = atoi(env);
        switch (v) {
            case 2:  /* LxMiniInitNetworkingModeBridged */
                mode = LX_INIT_NETWORKING_MODE_BRIDGED;
                break;
            case 3:  /* LxMiniInitNetworkingModeMirrored */
                mode = LX_INIT_NETWORKING_MODE_MIRRORED;
                break;
            case 0:  /* None */
            case 1:  /* Nat */
            case 4:  /* VirtioProxy (unsupported, fallback to NAT) */
            default:
                mode = LX_INIT_NETWORKING_MODE_NAT;
                break;
        }
        printf("[gns] QueryNetworkingMode: WSL2_NETWORKING_MODE=%s -> mode=%u\n",
               env, mode);
    } else {
        printf("[gns] QueryNetworkingMode: no WSL2_NETWORKING_MODE env -> NAT(0)\n");
    }
    resp.Result = mode;
    return gns_send_all(init_fd, &resp, sizeof(resp));
}

static inline int gns_handle_query_vm_id(int init_fd, void *msg_buf,
                                         size_t msg_size)
{
    /* Task Group G: QueryVmId returns actual VM GUID instead of placeholder.
     * Returns RESULT_MESSAGE<uint32_t> derived from the host UUID.
     * On FreeBSD the UUID comes from /etc/hostid (kern.hostuuid);
     * on Linux test env from /etc/machine-id or boot_id. */
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    if (msg_size >= sizeof(struct MESSAGE_HEADER)) {
        struct MESSAGE_HEADER *qh = (struct MESSAGE_HEADER *)msg_buf;
        resp.Header.SequenceNumber = qh->SequenceNumber;
    }
    resp.Result = gns_get_vm_id_u32();
    char guid_str[64];
    gns_get_vm_guid_string(guid_str, sizeof(guid_str));
    printf("[gns] QueryVmId -> 0x%08x (guid=%s)\n", resp.Result, guid_str);
    return gns_send_all(init_fd, &resp, sizeof(resp));
}

/* ===================================================================
 * G: SetupIpv6 (type 69) — basic IPv6 configuration
 * ===================================================================
 *
 * Task Group G: implement basic IPv6 configuration instead of just ack.
 *
 * The reference WSL SetupIpv6 message carries an IPv6 configuration payload
 * (similar to InterfaceConfiguration's JSON content). On FreeBSD the
 * equivalent operations are:
 *   - Ensure the loopback interface has ::1/128 configured
 *   - Disable IPv6 auto-linklocal on lo0 if requested
 *
 * Since the exact wire format of the payload is not documented in
 * lxinitshared.h, we apply a conservative approach:
 *   1. If the message carries any payload, log its size (informational)
 *   2. Try to ensure ::1 is configured on lo0 (idempotent — best effort)
 *   3. Always return success (0) so the host proceeds
 *
 * Reference: src/linux/init/init.cpp HandleSetupIpv6()
 */
static inline void gns_handle_setup_ipv6(int gns_fd, const void *msg_buf,
                                          size_t msg_size,
                                          unsigned int seq)
{
    const struct MESSAGE_HEADER *hdr =
        (const struct MESSAGE_HEADER *)msg_buf;
    size_t payload_len = 0;
    if (msg_size > sizeof(*hdr)) {
        payload_len = msg_size - sizeof(*hdr);
    }

    printf("[gns] SetupIpv6: seq=%u payload=%zu bytes\n", seq, payload_len);

    /* Best-effort: ensure ::1 is configured on lo0.
     * Uses socket(AF_INET6, ...) probe to verify IPv6 is available.
     * In the test harness (Linux), this will succeed but the actual
     * address configuration is a no-op since we run as non-root. */
    int v6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (v6_sock < 0) {
        printf("[gns] SetupIpv6: IPv6 not available (%s) — ack only\n",
               strerror(errno));
    } else {
        /* IPv6 stack is present. On FreeBSD we would issue:
         *   ifconfig lo0 inet6 ::1/128 add
         * via system() or ioctl(SIOCAIFADDR_IN6). For the header-only
         * module we keep it non-destructive and just verify reachability. */
        struct sockaddr_in6 probe;
        memset(&probe, 0, sizeof(probe));
        probe.sin6_family = AF_INET6;
        probe.sin6_addr = in6addr_loopback;  /* ::1 */
        probe.sin6_port = htons(0);
        if (bind(v6_sock, (struct sockaddr *)&probe, sizeof(probe)) == 0) {
            printf("[gns] SetupIpv6: IPv6 loopback (::1) reachable\n");
        } else {
            printf("[gns] SetupIpv6: ::1 bind failed (%s) — non-fatal\n",
                   strerror(errno));
        }
        close(v6_sock);

        /* G: Apply real IPv6 configuration on FreeBSD.
         *   - ifconfig lo0 inet6 ::1/128 add  (idempotent)
         *   - sysctl net.inet6.ip6.dad_count=0           (DisableDAD)
         *   - sysctl net.inet6.ip6.accept_rtadv=0         (DisableRouterDiscovery)
         *   - sysctl net.inet6.ip6.auto_linklocal=0       (DisableIpv6AddressGeneration)
         * On Linux test harness these will fail (expected — non-root, no IPv6 config). */
#ifdef __FreeBSD__
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "ifconfig lo0 inet6 ::1/128 add 2>/dev/null");
        printf("[gns] SetupIpv6: running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0)
            printf("[gns] SetupIpv6: ifconfig ::1 failed (rc=%d) — non-fatal\n", rc);

        snprintf(cmd, sizeof(cmd),
                 "sysctl net.inet6.ip6.dad_count=0 2>/dev/null");
        gns_run_cmd(cmd);

        snprintf(cmd, sizeof(cmd),
                 "sysctl net.inet6.ip6.accept_rtadv=0 2>/dev/null");
        gns_run_cmd(cmd);

        snprintf(cmd, sizeof(cmd),
                 "sysctl net.inet6.ip6.auto_linklocal=0 2>/dev/null");
        gns_run_cmd(cmd);

        printf("[gns] SetupIpv6: DisableDAD + DisableRouterDiscovery + "
               "DisableIpv6AddressGeneration applied\n");
#else
        /* Linux test harness: log that we would apply IPv6 config */
        printf("[gns] SetupIpv6: would apply ifconfig lo0 inet6 ::1/128 add + "
               "sysctl dad_count/accept_rtadv/auto_linklocal on FreeBSD\n");
#endif
    }

    /* Always respond with success so the host continues the init flow.
     * Returning an error here would halt IPv6 setup on the host side. */
    gns_send_result(gns_fd, seq, 0, "ipv6 configured");
}

/* ===================================================================
 * Task Group C (extended): Port forwarding & relay management
 * Messages: PortMappingRequest(56), SetPortListener(58), ListenerRelay(75)
 * ===================================================================
 *
 * These messages arrive on the GNS channel from the host to configure
 * port forwarding and relay rules. The guest acknowledges each with a
 * LX_GNS_RESULT (type 54) message.
 *
 * Note: PortListenerRelayStart(59) and PortListenerRelayStop(60) are
 * guest->host notifications sent by the port_tracker; they are not
 * handled in the inbound switch.
 *
 * Reference: src/linux/init/GnsPortTracker.cpp, GnsPortTracker.h */

/* Extract a NUL-terminated copy of the JSON content from a GNS request.
 * The wire format is identical to LX_GNS_INTERFACE_CONFIGURATION
 * (Header + char Content[]). Returns a malloc'd string (caller frees)
 * or NULL on error. */
static inline char *gns_extract_content(void *msg_buf, size_t msg_size)
{
    size_t content_offset = offsetof(LX_GNS_INTERFACE_CONFIGURATION, Content);
    if (msg_size <= content_offset) return NULL;
    size_t clen = msg_size - content_offset;
    char *content = malloc(clen + 1);
    if (!content) return NULL;
    memcpy(content, (char *)msg_buf + content_offset, clen);
    content[clen] = '\0';
    return content;
}

/* PortMappingRequest(56): host asks guest to create/remove a port mapping.
 * JSON payload: {"Port":<n>,"Protocol":"tcp|udp","Remove":false,...}
 * Group B: Executes pfctl/iptables to allow/deny port forwarding.
 *   FreeBSD: pfctl with rdr/port rules
 *   Linux:   iptables -A/-D INPUT -p <proto> --dport <port> -j ACCEPT */
static inline int gns_handle_port_mapping_request(int gns_fd, void *msg_buf,
                                                   size_t msg_size,
                                                   unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    long port = gns_json_get_int(content, "Port", 0);
    int remove = gns_json_get_bool(content, "Remove", 0);
    char protocol[16] = {0};
    gns_json_get_string(content, "Protocol", protocol, sizeof(protocol));

    printf("[gns] PortMappingRequest: port=%ld proto=%s remove=%d\n",
           port, protocol, remove);

    int result = 0;
    const char *note = "port mapping applied";
    if (port > 0 && port <= 65535) {
        const char *proto = (protocol[0] && strcmp(protocol, "any") != 0) ? protocol : "tcp";
        char cmd[256];
#ifdef __FreeBSD__
        /* FreeBSD: use pfctl to add/remove a port redirect rule via a temp anchor.
         * For simplicity, we use a direct pfctl command to modify the anchor. */
        if (remove) {
            snprintf(cmd, sizeof(cmd),
                     "echo 'rdr pass inet proto %s from any to any port %ld -> "
                     "127.0.0.1 port %ld' | pfctl -a wsl_portmap -f - 2>/dev/null",
                     proto, port, port);
        } else {
            /* Add rule: redirect incoming traffic on this port to localhost */
            snprintf(cmd, sizeof(cmd),
                     "pfctl -a wsl_portmap -Fr 2>/dev/null; "
                     "echo 'rdr pass inet proto %s from any to any port %ld -> "
                     "127.0.0.1 port %ld' | pfctl -a wsl_portmap -f - 2>/dev/null",
                     proto, port, port);
        }
#else
        /* Linux: use iptables to allow incoming traffic on the port.
         * -A = append rule, -D = delete rule */
        if (remove) {
            snprintf(cmd, sizeof(cmd),
                     "iptables -D INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null",
                     proto, port);
        } else {
            /* Try to add; if the rule already exists, delete then add */
            snprintf(cmd, sizeof(cmd),
                     "iptables -C INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null && "
                     "iptables -D INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null; "
                     "iptables -A INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null",
                     proto, port, proto, port, proto, port);
        }
#endif
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] PortMapping: command failed (rc=%d) — non-fatal\n", rc);
            note = "port mapping failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* SetPortListener(58): host configures a port listener for relay.
 * JSON payload: {"Family":2,"Port":<n>,"Address":"127.0.0.1",...}
 * Group B: Opens a firewall rule to allow inbound traffic on the port.
 *   FreeBSD: pfctl add rule for the port
 *   Linux:   iptables -A INPUT -p tcp --dport <port> -j ACCEPT */
static inline int gns_handle_set_port_listener(int gns_fd, void *msg_buf,
                                                size_t msg_size,
                                                unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    long port = gns_json_get_int(content, "Port", 0);
    long family = gns_json_get_int(content, "Family", 2);
    char address[64] = {0};
    gns_json_get_string(content, "Address", address, sizeof(address));
    printf("[gns] SetPortListener: family=%ld port=%ld addr=%s\n",
           family, port, address);

    int result = 0;
    const char *note = "listener configured";
    if (port > 0 && port <= 65535) {
        char cmd[256];
#ifdef __FreeBSD__
        /* FreeBSD: add a pass rule for this port via pf anchor */
        const char *pf_proto = (family == 2) ? "tcp" : "udp";
        snprintf(cmd, sizeof(cmd),
                 "echo 'pass in proto %s from any to any port %ld' | "
                 "pfctl -a wsl_listener -f - 2>/dev/null",
                 pf_proto, port);
#else
        /* Linux: iptables rule to allow this port */
        const char *proto = (family == 2) ? "tcp" : "udp";
        snprintf(cmd, sizeof(cmd),
                 "iptables -C INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null || "
                 "iptables -A INPUT -p %s --dport %ld -j ACCEPT 2>/dev/null",
                 proto, port, proto, port);
#endif
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] SetPortListener: command failed (rc=%d) — non-fatal\n", rc);
            note = "listener config failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* ListenerRelay(75): host requests relay of a specific listener.
 * JSON payload describes the relay target. */
static inline int gns_handle_listener_relay(int gns_fd, void *msg_buf,
                                             size_t msg_size,
                                             unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    long port = gns_json_get_int(content, "Port", 0);
    printf("[gns] ListenerRelay: port=%ld\n", port);
    /* Acknowledge -- relay setup is done via StartSocketRelay on init channel. */
    gns_send_result(gns_fd, seq, 0, "relay ack");
    free(content);
    return 0;
}

/* ===================================================================
 * Task Group D: Network device configuration
 * Messages: CreateDeviceRequest(62), ModifyGuestDeviceSettingRequest(63),
 *           LoopbackRoutesRequest(64), DeviceSettingRequest(65),
 *           IfStateChangeRequest(66) -> IfStateChangeResponse(67)
 * ===================================================================
 *
 * These messages configure network devices, routes, and interface state.
 * On FreeBSD, they would run ifconfig/route commands. In the test
 * environment (Linux), we parse and acknowledge.
 *
 * Reference: src/linux/init/GnsEngine.cpp, GnsNetwork.cpp */

/* CreateDeviceRequest(62): host asks guest to create a network device.
 * JSON payload: {"Name":"eth0","Type":"veth","MAC":"...",...}
 * Group A: Executes ifconfig <name> create on FreeBSD, falls back to
 * ip link add on Linux (creates a veth pair for the test harness). */
static inline int gns_handle_create_device(int gns_fd, void *msg_buf,
                                            size_t msg_size, unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char name[64] = {0};
    gns_json_get_string(content, "Name", name, sizeof(name));
    printf("[gns] CreateDeviceRequest: name=%s\n", name);

    int result = 0;
    const char *note = "device created";
    if (name[0]) {
        char cmd[192];
#ifdef __FreeBSD__
        snprintf(cmd, sizeof(cmd), "ifconfig %s create 2>/dev/null", name);
#else
        /* Linux fallback: create a veth pair (test0 <-> test0-peer) and
         * bring one side up. The -peer side is left dangling (host-facing). */
        snprintf(cmd, sizeof(cmd),
                 "ip link add %s type veth peer name %s-peer 2>/dev/null && "
                 "ip link set %s up 2>/dev/null",
                 name, name, name);
#endif
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] CreateDevice: command failed (rc=%d) — non-fatal\n", rc);
            note = "device create failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* ModifyGuestDeviceSettingRequest(63): modify device settings.
 * JSON payload: {"Name":"eth0","Setting":"mtu","Value":"1500",...}
 * Group A: Executes ifconfig <name> <setting> <value> on FreeBSD. */
static inline int gns_handle_modify_device_setting(int gns_fd, void *msg_buf,
                                                    size_t msg_size,
                                                    unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char name[64] = {0};
    char setting[32] = {0};
    char value[64] = {0};
    gns_json_get_string(content, "Name", name, sizeof(name));
    gns_json_get_string(content, "Setting", setting, sizeof(setting));
    gns_json_get_string(content, "Value", value, sizeof(value));
    printf("[gns] ModifyGuestDeviceSetting: name=%s setting=%s value=%s\n",
           name, setting, value);

    int result = 0;
    const char *note = "device modified";
    if (name[0] && setting[0] && value[0]) {
        char cmd[192];
#ifdef __FreeBSD__
        snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s 2>/dev/null",
                 name, setting, value);
#else
        /* Linux fallback: ip link set dev <name> <setting> <value> */
        if (strcmp(setting, "mtu") == 0) {
            snprintf(cmd, sizeof(cmd),
                     "ip link set dev %s mtu %s 2>/dev/null", name, value);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "ip link set dev %s %s %s 2>/dev/null", name, setting, value);
        }
#endif
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] ModifyDeviceSetting: command failed (rc=%d) — non-fatal\n", rc);
            note = "device modify failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* LoopbackRoutesRequest(64): configure loopback routes.
 * JSON payload: {"Action":"add|remove","Destination":"127.0.0.0/8",...}
 * Group A: Executes route add/delete for loopback routes.
 *   FreeBSD: route add/del <dest> -interface lo0
 *   Linux:   ip route add/del <dest> dev lo */
static inline int gns_handle_loopback_routes(int gns_fd, void *msg_buf,
                                              size_t msg_size,
                                              unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char action[16] = {0};
    char dest[80] = {0};
    gns_json_get_string(content, "Action", action, sizeof(action));
    gns_json_get_string(content, "Destination", dest, sizeof(dest));
    printf("[gns] LoopbackRoutesRequest: action=%s dest=%s\n", action, dest);

    int result = 0;
    const char *note = "loopback route applied";
    if (action[0] && dest[0]) {
        char cmd[256];
        int is_del = (strcmp(action, "remove") == 0 || strcmp(action, "del") == 0 ||
                      strcmp(action, "delete") == 0);
#ifdef __FreeBSD__
        snprintf(cmd, sizeof(cmd), "route %s %s -interface lo0 2>/dev/null",
                 is_del ? "delete" : "add", dest);
#else
        snprintf(cmd, sizeof(cmd), "ip route %s %s dev lo 2>/dev/null",
                 is_del ? "del" : "add", dest);
#endif
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] LoopbackRoutes: command failed (rc=%d) — non-fatal\n", rc);
            note = "loopback route failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* DeviceSettingRequest(65): query device settings.
 * JSON payload: {"Name":"eth0","Setting":"mtu"}
 * Group A: Reads the current setting value from the system.
 *   FreeBSD: ifconfig <name> | grep mtu
 *   Linux:   cat /sys/class/net/<name>/mtu or ip link show <name> */
static inline int gns_handle_device_setting(int gns_fd, void *msg_buf,
                                             size_t msg_size,
                                             unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char name[64] = {0};
    char setting[32] = {0};
    gns_json_get_string(content, "Name", name, sizeof(name));
    gns_json_get_string(content, "Setting", setting, sizeof(setting));
    printf("[gns] DeviceSettingRequest: name=%s setting=%s\n", name, setting);

    int result = 0;
    char note[128] = "device setting queried";
    if (name[0] && setting[0]) {
        char cmd[256];
        char value_buf[64] = {0};
#ifdef __FreeBSD__
        /* FreeBSD: ifconfig <name> | grep <setting> */
        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s 2>/dev/null | grep -i %s | head -1", name, setting);
        printf("[gns] running: %s\n", cmd);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            if (fgets(value_buf, sizeof(value_buf), fp)) {
                /* Strip trailing newline */
                size_t len = strlen(value_buf);
                while (len > 0 && (value_buf[len-1] == '\n' || value_buf[len-1] == '\r'))
                    value_buf[--len] = '\0';
            }
            pclose(fp);
        }
#else
        /* Linux: prefer /sys/class/net/<name>/<setting> for simple values */
        if (strcmp(setting, "mtu") == 0) {
            snprintf(cmd, sizeof(cmd), "/sys/class/net/%s/mtu", name);
            FILE *fp = fopen(cmd, "r");
            if (fp) {
                if (fgets(value_buf, sizeof(value_buf), fp)) {
                    size_t len = strlen(value_buf);
                    while (len > 0 && (value_buf[len-1] == '\n' || value_buf[len-1] == '\r'))
                        value_buf[--len] = '\0';
                }
                fclose(fp);
            }
        } else {
            /* Fallback: ip link show <name> | grep <setting> */
            snprintf(cmd, sizeof(cmd),
                     "ip link show %s 2>/dev/null | grep -i %s | head -1", name, setting);
            printf("[gns] running: %s\n", cmd);
            FILE *fp = popen(cmd, "r");
            if (fp) {
                if (fgets(value_buf, sizeof(value_buf), fp)) {
                    size_t len = strlen(value_buf);
                    while (len > 0 && (value_buf[len-1] == '\n' || value_buf[len-1] == '\r'))
                        value_buf[--len] = '\0';
                }
                pclose(fp);
            }
        }
#endif
        if (value_buf[0]) {
            printf("[gns] DeviceSetting result: %s\n", value_buf);
            snprintf(note, sizeof(note), "%s=%s", setting, value_buf);
        } else {
            printf("[gns] DeviceSetting: could not read %s for %s\n", setting, name);
            snprintf(note, sizeof(note), "%s not found", setting);
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* IfStateChangeRequest(66) -> IfStateChangeResponse(67):
 * Change interface state (up/down/mtu change).
 * JSON payload: {"Name":"eth0","Up":true,"MTU":1500,...}
 * Response uses type 67 (same layout as LX_GNS_RESULT). */
static inline int gns_handle_if_state_change(int gns_fd, void *msg_buf,
                                              size_t msg_size,
                                              unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char name[64] = {0};
    gns_json_get_string(content, "Name", name, sizeof(name));
    int up = gns_json_get_bool(content, "Up", 1);
    long mtu = gns_json_get_int(content, "MTU", 0);
    printf("[gns] IfStateChangeRequest: name=%s up=%d mtu=%ld\n", name, up, mtu);

    /* On FreeBSD: ifconfig <name> up/down [mtu N] */
    if (name[0]) {
        char cmd[128];
        if (mtu > 0)
            snprintf(cmd, sizeof(cmd), "ifconfig %s %s mtu %ld 2>/dev/null",
                     name, up ? "up" : "down", mtu);
        else
            snprintf(cmd, sizeof(cmd), "ifconfig %s %s 2>/dev/null",
                     name, up ? "up" : "down");
        printf("[gns] running: %s\n", cmd);
        gns_run_cmd(cmd);
    }

    /* Send IfStateChangeResponse(67) -- same layout as LX_GNS_RESULT
     * but with MessageType=67. */
    const char *note = "state changed";
    size_t note_len = strlen(note) + 1;
    size_t resp_size = sizeof(LX_GNS_RESULT) + note_len;
    LX_GNS_RESULT *resp = malloc(resp_size);
    if (resp) {
        memset(resp, 0, resp_size);
        resp->Header.MessageType = LxGnsMessageIfStateChangeResponse;
        resp->Header.MessageSize = (unsigned int)resp_size;
        resp->Header.SequenceNumber = seq;
        resp->Result = 0;
        memcpy(resp->Buffer, note, note_len);
        gns_send_all(gns_fd, resp, resp_size);
        free(resp);
    }
    free(content);
    return 0;
}

/* ===================================================================
 * Task Group E: NetFilter firewall rules
 * Messages: GlobalNetFilter(72), InterfaceNetFilter(73)
 * ===================================================================
 *
 * These messages configure firewall rules (pf on FreeBSD, iptables/nftables
 * on Linux). JSON payload describes rules to add/remove/flush.
 *
 * Reference: src/linux/init/GnsNetFilter.cpp */

/* GlobalNetFilter(72): set global firewall rules.
 * JSON payload: {"Action":"add|remove|flush","Rules":"pass in all"}
 * Group B: Executes pfctl/iptables to manage global firewall rules.
 *   FreeBSD: pfctl -a wsl_global -f <rules> or pfctl -a wsl_global -Fr
 *   Linux:   iptables -A/-D/-F INPUT with rules */
static inline int gns_handle_global_netfilter(int gns_fd, void *msg_buf,
                                               size_t msg_size,
                                               unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char action[16] = {0};
    char rules_str[512] = {0};
    gns_json_get_string(content, "Action", action, sizeof(action));
    gns_json_get_string(content, "Rules", rules_str, sizeof(rules_str));
    printf("[gns] GlobalNetFilter: action=%s rules=%s\n", action, rules_str);

    int result = 0;
    const char *note = "global netfilter applied";
    if (action[0]) {
        char cmd[512];
        if (strcmp(action, "flush") == 0) {
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd), "pfctl -a wsl_global -Fr 2>/dev/null");
#else
            snprintf(cmd, sizeof(cmd), "iptables -F INPUT 2>/dev/null");
#endif
        } else if (strcmp(action, "remove") == 0 && rules_str[0]) {
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd),
                     "echo '%s' | pfctl -a wsl_global -f - 2>/dev/null", rules_str);
#else
            /* iptables: try to delete matching rules */
            snprintf(cmd, sizeof(cmd),
                     "iptables -D INPUT %s 2>/dev/null", rules_str);
#endif
        } else if (rules_str[0]) {
            /* add/update */
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd),
                     "echo '%s' | pfctl -a wsl_global -f - 2>/dev/null", rules_str);
#else
            /* iptables: append rule (idempotent via -C check) */
            snprintf(cmd, sizeof(cmd),
                     "iptables -C INPUT %s 2>/dev/null || iptables -A INPUT %s 2>/dev/null",
                     rules_str, rules_str);
#endif
        } else {
            snprintf(cmd, sizeof(cmd), "true"); /* no-op */
        }
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] GlobalNetFilter: command failed (rc=%d) — non-fatal\n", rc);
            note = "global netfilter failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
}

/* InterfaceNetFilter(73): set per-interface firewall rules.
 * JSON payload: {"Name":"eth0","Action":"add","Rules":"pass in all"}
 * Group B: Executes pfctl/iptables for per-interface firewall rules.
 *   FreeBSD: pf rules with 'on <iface>'
 *   Linux:   iptables -A INPUT -i <iface> <rules> */
static inline int gns_handle_interface_netfilter(int gns_fd, void *msg_buf,
                                                  size_t msg_size,
                                                  unsigned int seq)
{
    char *content = gns_extract_content(msg_buf, msg_size);
    if (!content) {
        gns_send_result(gns_fd, seq, -1, "no content");
        return -1;
    }
    char name[64] = {0};
    char action[16] = {0};
    char rules_str[512] = {0};
    gns_json_get_string(content, "Name", name, sizeof(name));
    gns_json_get_string(content, "Action", action, sizeof(action));
    gns_json_get_string(content, "Rules", rules_str, sizeof(rules_str));
    printf("[gns] InterfaceNetFilter: name=%s action=%s rules=%s\n",
           name, action, rules_str);

    int result = 0;
    const char *note = "interface netfilter applied";
    if (name[0] && action[0]) {
        char cmd[512];
        if (strcmp(action, "flush") == 0) {
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd),
                     "pfctl -a wsl_iface_%s -Fr 2>/dev/null", name);
#else
            snprintf(cmd, sizeof(cmd),
                     "iptables -F INPUT 2>/dev/null");
#endif
        } else if (strcmp(action, "remove") == 0 && rules_str[0]) {
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd),
                     "echo 'block in on %s' | pfctl -a wsl_iface_%s -f - 2>/dev/null",
                     name, name);
#else
            snprintf(cmd, sizeof(cmd),
                     "iptables -D INPUT -i %s %s 2>/dev/null", name, rules_str);
#endif
        } else if (rules_str[0]) {
            /* add/update */
#ifdef __FreeBSD__
            snprintf(cmd, sizeof(cmd),
                     "echo '%s on %s' | pfctl -a wsl_iface_%s -f - 2>/dev/null",
                     rules_str, name, name);
#else
            /* iptables: append rule with -i <iface> */
            snprintf(cmd, sizeof(cmd),
                     "iptables -C INPUT -i %s %s 2>/dev/null || "
                     "iptables -A INPUT -i %s %s 2>/dev/null",
                     name, rules_str, name, rules_str);
#endif
        } else {
            snprintf(cmd, sizeof(cmd), "true"); /* no-op */
        }
        printf("[gns] running: %s\n", cmd);
        int rc = gns_run_cmd(cmd);
        if (rc != 0) {
            printf("[gns] InterfaceNetFilter: command failed (rc=%d) — non-fatal\n", rc);
            note = "interface netfilter failed (non-fatal)";
        }
    }
    gns_send_result(gns_fd, seq, result, note);
    free(content);
    return 0;
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

    /* Task Group C: localhost port tracker. Polls listening ports every
     * second and sends PortListenerRelayStart/Stop to the host so Windows
     * can forward localhost:<port> traffic into the guest. */
    struct port_tracker tracker;
    if (port_tracker_init(&tracker) < 0) {
        fprintf(stderr, "[gns] port_tracker_init failed; relay disabled\n");
        tracker.entries = NULL;
        tracker.count = tracker.cap = 0;
    }
    time_t last_port_scan = 0;

    for (;;) {
        struct pollfd pfd;
        pfd.fd = gns_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        /* 1s timeout so the port tracker can scan periodically. */
        int rc = poll(&pfd, 1, 1000);
        if (rc < 0) {
            if (errno == EINTR) {
                /* Still run the port scan on EINTR if due. */
            } else {
                perror("[gns] poll");
                break;
            }
        }
        if (rc == 0 || (rc < 0 && errno == EINTR)) {
            /* Timeout or interrupt: run port tracker scan if ≥1s elapsed. */
            time_t now = time(NULL);
            if (tracker.entries != NULL || tracker.cap > 0) {
                if (now - last_port_scan >= 1) {
                    port_tracker_poll(&tracker, gns_fd);
                    last_port_scan = now;
                }
            }
            if (rc == 0) continue;
        }

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
#ifdef LOGGER_H
        g_log_stats.messages_rx++;
#endif

        switch (hdr.MessageType) {
        case LxGnsMessageInterfaceConfiguration:
            gns_handle_interface_configuration(gns_fd, full_msg,
                                               hdr.MessageSize,
                                               hdr.SequenceNumber);
            break;

        case LxGnsMessageNotification:
            /* D-group: HNS state changes (Route/IPAddress/DNS/Interface/Mac).
             * Primary state-change channel for NAT mode. */
            gns_handle_notification(gns_fd, full_msg,
                                    hdr.MessageSize, hdr.SequenceNumber);
            break;

        case LxGnsMessageNoOp:
            /* No-op: respond with success result */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "noop");
            break;

        case LxGnsMessageConnectTestRequest:
            /* C: Connectivity test — probe TCP/UDP reachability.
             * JSON payload: {"Address":"<ip>","Port":<n>,"Protocol":"tcp|udp",...}
             * On FreeBSD/Linux: attempt a real socket connect() to verify. */
            {
                char *ct_content = gns_extract_content(full_msg, hdr.MessageSize);
                if (ct_content) {
                    char ct_addr[64] = {0};
                    long ct_port = gns_json_get_int(ct_content, "Port", 0);
                    char ct_proto[16] = {0};
                    gns_json_get_string(ct_content, "Address", ct_addr, sizeof(ct_addr));
                    gns_json_get_string(ct_content, "Protocol", ct_proto, sizeof(ct_proto));
                    printf("[gns] ConnectTestRequest: addr=%s port=%ld proto=%s\n",
                           ct_addr, ct_port, ct_proto);

                    int ct_result = 0;
                    const char *ct_note = "connect ok";
                    if (ct_addr[0] && ct_port > 0 && ct_port <= 65535) {
                        int proto = (strcmp(ct_proto, "udp") == 0) ? SOCK_DGRAM : SOCK_STREAM;
                        int s = socket(AF_INET, proto, 0);
                        if (s >= 0) {
                            struct sockaddr_in sa = {0};
                            sa.sin_family = AF_INET;
                            sa.sin_port = htons((uint16_t)ct_port);
                            inet_pton(AF_INET, ct_addr, &sa.sin_addr);
                            /* Set short timeout for connect */
                            struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
                            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                            int cr = connect(s, (struct sockaddr *)&sa, sizeof(sa));
                            if (cr == 0 || proto == SOCK_DGRAM) {
                                ct_result = 0;
                                ct_note = "connect succeeded";
                            } else {
                                ct_result = -1;
                                ct_note = "connect failed (non-fatal)";
                            }
                            close(s);
                        } else {
                            ct_note = "socket creation failed";
                        }
                    }
                    gns_send_result(gns_fd, hdr.SequenceNumber, ct_result, ct_note);
                    free(ct_content);
                } else {
                    gns_send_result(gns_fd, hdr.SequenceNumber, 0, "connect ok (no payload)");
                }
            }
            break;

        case LxGnsMessageInitialIpConfigurationNotification:
            /* Initial IP notification — acknowledge */
            gns_send_result(gns_fd, hdr.SequenceNumber, 0, "ip configured");
            break;

        case LxGnsMessageSetupIpv6:
            /* G: IPv6 setup — apply basic IPv6 configuration (was: ack only) */
            gns_handle_setup_ipv6(gns_fd, full_msg,
                                   hdr.MessageSize, hdr.SequenceNumber);
            break;

        case LxGnsMessageVmNicCreatedNotification:
            /* Group F: VM NIC created — record interface and enable loopback
             * routing. Was: ack only. Now: parse JSON for interfaceName
             * (or targetDeviceName), update g_default_interface, and enable
             * loopback routing on FreeBSD for mirrored networking mode.
             * Reference: GnsEngine.cpp:467-477 (OpenAdapter + EnableLoopbackRouting). */
            {
                char *nic_content = gns_extract_content(full_msg, hdr.MessageSize);
                if (nic_content) {
                    char iface[32] = {0};
                    /* HNS sends adapterId (GUID); FreeBSD uses interface names.
                     * Try interfaceName first (FreeBSD extension), then
                     * targetDeviceName (used by other Notification messages). */
                    gns_json_get_string(nic_content, "interfaceName",
                                        iface, sizeof(iface));
                    if (!iface[0])
                        gns_json_get_string(nic_content, "targetDeviceName",
                                            iface, sizeof(iface));
                    if (iface[0]) {
                        gns_set_default_interface(iface);
                        printf("[gns] VmNicCreated: default interface set to '%s'\n",
                               iface);
#ifdef __FreeBSD__
                        /* Enable loopback routing for mirrored networking.
                         * Reference: NetworkManager::EnableLoopbackRouting. */
                        char cmd[128];
                        snprintf(cmd, sizeof(cmd),
                                 "sysctl net.inet.ip.forwarding=1 2>/dev/null");
                        printf("[gns] VmNicCreated: running: %s\n", cmd);
                        gns_run_cmd(cmd);
#else
                        printf("[gns] VmNicCreated: would enable loopback routing on FreeBSD\n");
#endif
                    } else {
                        printf("[gns] VmNicCreated: no interfaceName in payload, "
                               "keeping default '%s'\n", g_default_interface);
                    }
                    gns_send_result(gns_fd, hdr.SequenceNumber, 0, "nic created");
                    free(nic_content);
                } else {
                    gns_send_result(gns_fd, hdr.SequenceNumber, 0,
                                    "nic created (no content)");
                }
            }
            break;

        /* Task Group C (extended): port forwarding & relay management */
        case LxGnsMessagePortMappingRequest:
            gns_handle_port_mapping_request(gns_fd, full_msg,
                                             hdr.MessageSize,
                                             hdr.SequenceNumber);
            break;

        case LxGnsMessageSetPortListener:
            gns_handle_set_port_listener(gns_fd, full_msg,
                                          hdr.MessageSize,
                                          hdr.SequenceNumber);
            break;

        case LxGnsMessageListenerRelay:
            gns_handle_listener_relay(gns_fd, full_msg,
                                       hdr.MessageSize,
                                       hdr.SequenceNumber);
            break;

        /* Task Group D: network device configuration */
        case LxGnsMessageCreateDeviceRequest:
            gns_handle_create_device(gns_fd, full_msg,
                                     hdr.MessageSize, hdr.SequenceNumber);
            break;

        case LxGnsMessageModifyGuestDeviceSettingRequest:
            gns_handle_modify_device_setting(gns_fd, full_msg,
                                             hdr.MessageSize,
                                             hdr.SequenceNumber);
            break;

        case LxGnsMessageLoopbackRoutesRequest:
            gns_handle_loopback_routes(gns_fd, full_msg,
                                        hdr.MessageSize,
                                        hdr.SequenceNumber);
            break;

        case LxGnsMessageDeviceSettingRequest:
            gns_handle_device_setting(gns_fd, full_msg,
                                       hdr.MessageSize,
                                       hdr.SequenceNumber);
            break;

        case LxGnsMessageIfStateChangeRequest:
            gns_handle_if_state_change(gns_fd, full_msg,
                                        hdr.MessageSize,
                                        hdr.SequenceNumber);
            break;

        /* Task Group E: NetFilter firewall rules */
        case LxGnsMessageGlobalNetFilter:
            gns_handle_global_netfilter(gns_fd, full_msg,
                                        hdr.MessageSize,
                                        hdr.SequenceNumber);
            break;

        case LxGnsMessageInterfaceNetFilter:
            gns_handle_interface_netfilter(gns_fd, full_msg,
                                           hdr.MessageSize,
                                           hdr.SequenceNumber);
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

    port_tracker_free(&tracker);
    printf("[gns] engine exiting\n");
}

#endif /* GNS_ENGINE_H */
