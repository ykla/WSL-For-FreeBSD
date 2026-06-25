/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_protocol.h - Shared WSL protocol definitions for local testing.
 *
 * Extracted from hvinit.c / hvbridge.c and aligned with the official
 * lxinitshared.h LX_MESSAGE_TYPE enum values. Used by the mock host
 * and the TCP-adapted guest binaries to ensure both sides agree on
 * wire formats.
 */
#ifndef WSL_PROTOCOL_H
#define WSL_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <poll.h>

/* ---- Port constants ---- */
#define PORT_HVS              50000  /* hvinit -> host (capability/notify/init) */
#define PORT_HVS_GNS          50001  /* hvinit -> host (GNS engine channel) */
#define PORT_HVS_BSD          60000  /* hvbridge listen port (session/interop) */

/* ---- WSL message type values (from lxinitshared.h LX_MESSAGE_TYPE enum) ---- */
#define LxInitMessageCreateProcess               1
#define LxInitMessageCreateSession               2
#define LxInitMessageCreateSessionResponse       3
#define LxInitMessageNetworkInformation           4
#define LxInitMessageInitialize                  5
#define LxInitMessageInitializeResponse          6
#define LxInitMessageTimezoneInformation          7  /* A3: host->guest timezone update */
#define LxInitMessageCreateProcessUtilityVm      8
#define LxInitMessageExitStatus                  9
#define LxInitMessageWindowSizeChanged           10
#define LxInitMessageCreateProcessResponse       11
#define LxInitMessageQueryDrvfsElevated          12
#define LxInitMessageRemountDrvfs                13  /* B1: host->guest, remount DrvFs in namespace */
#define LxInitMessageTerminateInstance           14
#define LxInitMessageStartSocketRelay            15
#define LxInitMessageQueryEnvironmentVariable    16
#define LxInitMessageQueryFeatureFlags           17
#define LxInitMessageCreateLoginSession          23
#define LxInitMessageStopPlan9Server             24  /* Group A: host->guest, stop Plan9 server */
#define LxInitMessageQueryNetworkingMode         25
#define LxInitMessageQueryVmId                   26
#define LxInitMessageOobeResult                  28  /* F1: guest->host, OOBE completion */
#define LxMiniInitMessageCreateInstanceResult    33
#define LxMiniInitMessageGuestCapabilities       43
#define LxMessageResultBool                      76
#define LxMessageResultInt32                     77
#define LxMessageResultUint32                    78
#define LxMessageResultUint8                     79

/* GNS message types (correct enum values from lxinitshared.h) */
#define LxGnsMessageInterfaceConfiguration              53
#define LxGnsMessageResult                              54
#define LxGnsMessageDnsTunneling                        70
#define LxGnsMessageNoOp                                71
#define LxGnsMessageConnectTestRequest                  74

/* B (DNS Tunneling): IP address the guest DNS server binds to.
 * Reference: lxinitshared.h LX_INIT_DNS_TUNNELING_IP_ADDRESS.
 * In production this is 10.255.255.254; tests override via WSL_DNS_TUNNEL_IP. */
#define LX_INIT_DNS_TUNNELING_IP_ADDRESS  "10.255.255.254"
#define LX_INIT_DNS_SERVER_PORT           53
#define LX_INIT_DNS_MAX_UDP_SIZE          4096
#define LX_INIT_DNS_TCP_LEN_PREFIX        2   /* bytes storing DNS-over-TCP request length */

/* Group A: Plan9 file server port (lxinitshared.h LX_INIT_UTILITY_VM_PLAN9_PORT) */
#define LX_INIT_UTILITY_VM_PLAN9_PORT     50001

/* ---- Core structures ---- */

struct MESSAGE_HEADER {
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};

/* GuestCapabilities (guest -> host, type 43) */
typedef struct LX_INIT_GUEST_CAPABILITIES {
    struct MESSAGE_HEADER Header;   /* 12 bytes — Phase 0 fix: was uint32_t */
    bool SeccompAvailable;
    char Buffer[];                  /* kernel version string (NUL-terminated) */
} LX_INIT_GUEST_CAPABILITIES;

/* RESULT_MESSAGE<uint32_t> (type 78) */
typedef struct RESULT_MESSAGE_UINT32 {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
} RESULT_MESSAGE_UINT32;

/* CreateSession (host -> guest, type 2) */
typedef struct LX_INIT_CREATE_SESSION {
    struct MESSAGE_HEADER Header;
    int64_t PidNamespace;
    char Buffer[];
} LX_INIT_CREATE_SESSION;

/* CreateSessionResponse (guest -> host, type 3) */
typedef struct LX_INIT_CREATE_SESSION_RESPONSE {
    struct MESSAGE_HEADER Header;
    unsigned int Port;
} LX_INIT_CREATE_SESSION_RESPONSE;

/* Initialize (host -> guest, type 5) — full configuration information.
 * Replaces the simplified LX_INIT_INITIALIZE stub with the real structure
 * matching src/shared/inc/lxinitshared.h LX_INIT_CONFIGURATION_INFORMATION.
 * Buffer[] contains 6 NUL-terminated strings referenced by the offset fields:
 *   hostname, domainname, windows_hosts, distribution_name, plan9_socket, timezone */
typedef struct LX_INIT_CONFIGURATION_INFORMATION {
    struct MESSAGE_HEADER Header;
    uint32_t HostnameOffset;
    uint32_t DomainnameOffset;
    uint32_t WindowsHostsOffset;
    uint32_t DistributionNameOffset;
    uint32_t Plan9SocketOffset;
    uint32_t TimezoneOffset;
    uint32_t DrvFsVolumesBitmap;
    uint32_t DrvFsDefaultOwner;
    uint32_t FeatureFlags;
    uint32_t DrvfsMount;       /* LX_INIT_DRVFS_MOUNT enum value */
    char Buffer[];
} LX_INIT_CONFIGURATION_INFORMATION;

/* Kept for backward compatibility — alias to the real structure */
typedef LX_INIT_CONFIGURATION_INFORMATION LX_INIT_INITIALIZE;

/* ConfigurationInformationResponse / InitializeResponse (guest -> host, type 6) */
typedef struct LX_INIT_CONFIGURATION_INFORMATION_RESPONSE {
    struct MESSAGE_HEADER Header;
    uint32_t Plan9Port;
    uint32_t DefaultUid;
    uint32_t InteropPort;
    bool SystemdEnabled;
    uint64_t PidNamespace;
    uint32_t FlavorIndex;
    uint32_t VersionIndex;
    char Buffer[];
} LX_INIT_CONFIGURATION_INFORMATION_RESPONSE;

/* CreateInstanceResult (guest -> host, type 33) */
typedef struct LX_MINI_INIT_CREATE_INSTANCE_RESULT {
    struct MESSAGE_HEADER Header;
    int Result;
    unsigned int FailureStep;
    uint64_t Pid;
    uint32_t ConnectPort;
    unsigned int WarningsOffset;
    char Buffer[];
} LX_MINI_INIT_CREATE_INSTANCE_RESULT;

/* CreateProcessCommon (embedded in CreateProcessUtilityVm) */
/* DrvFs mount mode (from lxinitshared.h LX_INIT_DRVFS_MOUNT) */
typedef enum {
    LxInitDrvfsMountNone        = 0,
    LxInitDrvfsMountNonElevated = 1,
    LxInitDrvfsMountElevated    = 2
} LX_INIT_DRVFS_MOUNT;

/* Feature flags (from lxinitshared.h LX_INIT_FEATURE_FLAGS) */
#define LxInitFeatureNone               0x00
#define LxInitFeatureVirtIo9p           0x01
#define LxInitFeatureVirtIoFs           0x02
#define LxInitFeatureDisable9pServer    0x04
#define LxInitFeatureRootfsCompressed   0x08
#define LxInitFeatureSystemDistro       0x10
#define LxInitFeatureDnsTunneling       0x20

/* Sentinel for "no port" in InitializeResponse */
#define LX_INIT_UTILITY_VM_INVALID_PORT 0xFFFFFFFFu

/* CreateProcess common structure (matches official lxinitshared.h) */
#ifndef LX_INIT_CREATE_PROCESS_COMMON_DEFINED
#define LX_INIT_CREATE_PROCESS_COMMON_DEFINED
typedef struct LX_INIT_CREATE_PROCESS_COMMON {
    uint32_t FilenameOffset;
    uint32_t CurrentWorkingDirectoryOffset;
    uint32_t CommandLineOffset;
    uint16_t CommandLineCount;
    uint32_t EnvironmentOffset;
    uint16_t EnvironmentCount;
    uint32_t NtEnvironmentOffset;
    uint16_t NtEnvironmentCount;
    uint32_t NtPathOffset;
    uint32_t ShellOptions;
    uint32_t UsernameOffset;
    uint32_t DefaultUid;
    int32_t  Flags;
    char Buffer[];
} LX_INIT_CREATE_PROCESS_COMMON;
#endif

/* CreateProcess flags (from lxinitshared.h LX_INIT_CREATE_PROCESS_FLAGS) */
#define LxInitCreateProcessFlagsStdInConsole    0x1
#define LxInitCreateProcessFlagsStdOutConsole   0x2
#define LxInitCreateProcessFlagsStdErrConsole   0x4
#define LxInitCreateProcessFlagsElevated        0x8
#define LxInitCreateProcessFlagsInteropEnabled  0x10

/* CreateProcessUtilityVm (host -> guest, type 8) */
typedef struct LX_INIT_CREATE_PROCESS_UTILITY_VM {
    struct MESSAGE_HEADER Header;
    unsigned short Rows;
    unsigned short Columns;
    LX_INIT_CREATE_PROCESS_COMMON Common;
} LX_INIT_CREATE_PROCESS_UTILITY_VM;

/* ExitStatus (guest -> host, type 9) */
typedef struct LX_INIT_PROCESS_EXIT_STATUS {
    struct MESSAGE_HEADER Header;
    int ExitCode;
} LX_INIT_PROCESS_EXIT_STATUS;

/* WindowSizeChanged (host -> guest, type 10) */
typedef struct LX_INIT_WINDOW_SIZE_CHANGED {
    struct MESSAGE_HEADER Header;
    unsigned short Rows;
    unsigned short Columns;
} LX_INIT_WINDOW_SIZE_CHANGED;

/* B1: MountDrvFs / RemountDrvfs (host -> guest, type 13)
 * Triggers DrvFs remount in the specified mount namespace (elevated/non-elevated).
 * Response is RESULT_MESSAGE_INT32 (type 77).
 * Reference: lxinitshared.h LX_INIT_MOUNT_DRVFS */
typedef struct LX_INIT_MOUNT_DRVFS {
    struct MESSAGE_HEADER Header;
    bool Admin;                   /* true = use elevated (admin) 9p server */
    unsigned int VolumesToMount;  /* bitmap of drive indices to mount */
    unsigned int UnreadableVolumes; /* bitmap of volumes that can't be read */
    int DefaultOwnerUid;          /* UID to use for file ownership */
} LX_INIT_MOUNT_DRVFS;

/* F1: OobeResult (guest -> host, type 28)
 * Sent on a dedicated OOBE channel when the distribution's first-run
 * setup (OOBE) completes. The host blocks waiting for this message
 * when RunOOBE=true and the create-process request has an empty
 * filename/commandline with the AllowOOBE flag (0x20) set.
 *
 * Fields:
 *   Result     - 0 on success, non-zero on failure
 *   DefaultUid - configured default UID, or -1 if not present
 *
 * Reference: src/shared/inc/lxinitshared.h LX_INIT_OOBE_RESULT */
typedef struct LX_INIT_OOBE_RESULT {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
    int64_t DefaultUid;
} LX_INIT_OOBE_RESULT;

/* F1: CreateProcess AllowOOBE flag (from lxinitshared.h LX_INIT_CREATE_PROCESS_FLAGS) */
#define LxInitCreateProcessFlagAllowOOBE         0x20

/* Phase 9 (Task Group C): Networking structures */

/* NetworkInformation (host -> guest, type 4)
 * Buffer contains NUL-terminated strings indexed by FileHeaderIndex and
 * FileContentsIndex. FileContents is written to /etc/resolv.conf. */
typedef struct LX_INIT_NETWORK_INFORMATION {
    struct MESSAGE_HEADER Header;
    unsigned int FileHeaderIndex;
    unsigned int FileContentsIndex;
    char Buffer[];
} LX_INIT_NETWORK_INFORMATION;

/* TimezoneInformation (host -> guest, type 7) — A3
 * Buffer contains a NUL-terminated IANA timezone string at TimezoneOffset.
 * Reference: lxinitshared.h LX_INIT_TIMEZONE_INFORMATION */
typedef struct LX_INIT_TIMEZONE_INFORMATION {
    struct MESSAGE_HEADER Header;
    unsigned int TimezoneOffset;  /* offset into Buffer[] */
    char Buffer[];
} LX_INIT_TIMEZONE_INFORMATION;

/* StartSocketRelay (host -> guest, type 15) */
typedef struct LX_INIT_START_SOCKET_RELAY {
    struct MESSAGE_HEADER Header;
    unsigned short Family;
    unsigned short Port;
    int HvSocketPort;
    size_t BufferSize;
} LX_INIT_START_SOCKET_RELAY;

/* GNS InterfaceConfiguration (host -> guest, type 334) */
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

/* ---- Task Group D: Interop server structures ---- */

/* RESULT_MESSAGE<bool> (type 76) — bool stored as uint32_t for 4-byte alignment */
typedef struct RESULT_MESSAGE_BOOL {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
} RESULT_MESSAGE_BOOL;

/* Group A: StopPlan9Server (type 24) — host requests Plan9 server shutdown.
 * Response is RESULT_MESSAGE_BOOL (type 76). Force=true → SIGKILL immediately.
 * Reference: lxinitshared.h LX_INIT_STOP_PLAN9_SERVER */
#ifndef LX_INIT_STOP_PLAN9_SERVER_MSG_DEFINED
#define LX_INIT_STOP_PLAN9_SERVER_MSG_DEFINED
typedef struct LX_INIT_STOP_PLAN9_SERVER_MSG {
    struct MESSAGE_HEADER Header;
    uint32_t Force;   /* bool: 1=force (SIGKILL), 0=graceful */
} LX_INIT_STOP_PLAN9_SERVER_MSG;
#endif

/* RESULT_MESSAGE<int32_t> (type 77) */
typedef struct RESULT_MESSAGE_INT32 {
    struct MESSAGE_HEADER Header;
    int32_t Result;
} RESULT_MESSAGE_INT32;

/* RESULT_MESSAGE<uint8_t> (type 79) — uint8_t stored as uint32_t for alignment */
typedef struct RESULT_MESSAGE_UINT8 {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
} RESULT_MESSAGE_UINT8;

/* QueryEnvironmentVariable (type 16) — Buffer holds var name (request) or value (response) */
typedef struct LX_INIT_QUERY_ENVIRONMENT_VARIABLE {
    struct MESSAGE_HEADER Header;
    char Buffer[];
} LX_INIT_QUERY_ENVIRONMENT_VARIABLE;

/* QueryVmId (type 26) — Buffer holds VmId string (may be empty) */
typedef struct LX_INIT_QUERY_VM_ID {
    struct MESSAGE_HEADER Header;
    char Buffer[];
} LX_INIT_QUERY_VM_ID;

/* CreateLoginSession (type 23) — Buffer holds username (NUL-terminated) */
typedef struct LX_INIT_CREATE_LOGIN_SESSION {
    struct MESSAGE_HEADER Header;
    unsigned int Uid;
    unsigned int Gid;
    char Buffer[];
} LX_INIT_CREATE_LOGIN_SESSION;

/* CreateProcessResponse (type 11) — response to CreateProcess(1) */
typedef struct LX_INIT_CREATE_PROCESS_RESPONSE {
    struct MESSAGE_HEADER Header;
    int Result;           /* errno-style: 0 = success */
    int64_t SignalPipeId; /* LxBus handle id; 0 if none */
    unsigned int Flags;   /* LX_INIT_CREATE_PROCESS_RESULT_FLAG_* */
} LX_INIT_CREATE_PROCESS_RESPONSE;

#define LX_INIT_CREATE_PROCESS_RESULT_FLAG_GUI_APPLICATION 0x1

/* ---- Task Group B: DNS Tunneling structures ----
 * Reference: lxinitshared.h LX_GNS_DNS_CLIENT_IDENTIFIER, LX_GNS_DNS_TUNNELING_MESSAGE.
 * Wire format: MESSAGE_HEADER + DnsClientIdentifier + raw DNS bytes (no padding).
 * The host runs the actual resolver; the guest just relays DNS packets over
 * a dedicated hvsock/TCP channel using this message type (LxGnsMessageDnsTunneling=70). */

typedef struct LX_GNS_DNS_CLIENT_IDENTIFIER {
    uint8_t  Protocol;     /* IPPROTO_UDP (17) or IPPROTO_TCP (6) */
    uint8_t  _pad[3];      /* align DnsClientId to 4-byte boundary */
    uint32_t DnsClientId;  /* unique id per UDP request or TCP connection */
} LX_GNS_DNS_CLIENT_IDENTIFIER;
#define LX_GNS_DNS_TUNNELING_MESSAGE_DEFINED

/* static_assert equivalent: Buffer must start right after the identifier.
 * sizeof(Header)=12, sizeof(DnsClientIdentifier)=8, so Buffer offset = 20. */
typedef struct LX_GNS_DNS_TUNNELING_MESSAGE {
    struct MESSAGE_HEADER          Header;
    LX_GNS_DNS_CLIENT_IDENTIFIER   DnsClientIdentifier;
    char                           Buffer[];  /* raw DNS request/response */
} LX_GNS_DNS_TUNNELING_MESSAGE;

/* Sanity check: ensure no padding before Buffer. */
/* (offsetof cannot be used in #if, so we rely on the struct layout above
 *  matching the reference static_assert.) */

/* Protocol numbers for DNS client identifier (from <netinet/in.h>) */
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/* Networking modes (for QueryNetworkingMode response) */
#define LxInitNetworkingModeNat       0
#define LxInitNetworkingModeMirrored  1
#define LxInitNetworkingModeBridged   2

/* ---- Helper: reliable send/recv over TCP ---- */
/* Handles EAGAIN on non-blocking sockets by polling. */

static inline int send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, 5000) <= 0) return -1; /* 5s timeout */
        } else {
            return -1;
        }
    }
    return 0;
}

static inline int recv_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) return -1; /* 5s timeout */
        } else {
            return -1;
        }
    }
    return 0;
}

/* Receive a full WSL message: read header first, then payload. */
static inline void *recv_message(int fd, struct MESSAGE_HEADER *out_hdr)
{
    struct MESSAGE_HEADER hdr;
    if (recv_all(fd, &hdr, sizeof(hdr)) < 0) return NULL;
    if (hdr.MessageSize < sizeof(hdr)) return NULL;

    size_t payload = hdr.MessageSize - sizeof(hdr);
    char *msg = malloc(hdr.MessageSize);
    if (!msg) return NULL;
    memcpy(msg, &hdr, sizeof(hdr));
    if (payload > 0) {
        if (recv_all(fd, msg + sizeof(hdr), payload) < 0) {
            free(msg);
            return NULL;
        }
    }
    if (out_hdr) *out_hdr = hdr;
    return msg;
}

#endif /* WSL_PROTOCOL_H */
