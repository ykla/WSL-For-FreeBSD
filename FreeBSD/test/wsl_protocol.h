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
#define PORT_HVS_BSD          60000  /* hvbridge listen port (session/interop) */

/* ---- WSL message type values (from lxinitshared.h LX_MESSAGE_TYPE enum) ---- */
#define LxInitMessageCreateSession               2
#define LxInitMessageCreateSessionResponse       3
#define LxInitMessageInitialize                  5
#define LxInitMessageInitializeResponse          6
#define LxInitMessageCreateProcessUtilityVm      8
#define LxInitMessageExitStatus                  9
#define LxInitMessageWindowSizeChanged           10
#define LxMiniInitMessageCreateInstanceResult    33
#define LxMiniInitMessageGuestCapabilities       43
#define LxMessageResultUint32                    78

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

/* Initialize (host -> guest, type 5) — we only need the header for testing */
typedef struct LX_INIT_INITIALIZE {
    struct MESSAGE_HEADER Header;
    char Buffer[];
} LX_INIT_INITIALIZE;

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
/* CreateProcess common structure (matches official lxinitshared.h) */
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
