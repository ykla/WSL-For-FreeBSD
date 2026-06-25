/*
 * SPDX-License-Identifier: MIT
 *
 * interop_server.h - WSL interop server module (Task Group D).
 *
 * Handles interop query messages on the 5th hvsock channel. The interop
 * channel carries query/response messages between the guest and host:
 *
 *   - QueryDrvfsElevated(12)      -> RESULT_MESSAGE<bool>
 *   - QueryEnvironmentVariable(16)-> same struct with value in Buffer
 *   - QueryFeatureFlags(17)       -> RESULT_MESSAGE<int32_t>
 *   - CreateLoginSession(23)      -> RESULT_MESSAGE<bool>
 *   - QueryNetworkingMode(25)     -> RESULT_MESSAGE<uint8_t>
 *   - QueryVmId(26)               -> same struct with VmId in Buffer
 *   - CreateProcess(1)            -> CreateProcessResponse(11)
 *
 * Prerequisites: struct MESSAGE_HEADER and send_all() must be defined
 * before including this header.
 *
 * Usage:
 *   #include "interop_server.h"
 *
 *   struct interop_reader ir;
 *   interop_reader_init(&ir);
 *
 *   // In poll loop, when interop_fd is readable:
 *   void *msg = NULL;
 *   int r = interop_try_read(interop_fd, &ir, &msg);
 *   if (r > 0 && msg) {
 *       interop_process_message(interop_fd, msg, ir.len);
 *       interop_consume(&ir, ((struct MESSAGE_HEADER *)msg)->MessageSize);
 *   }
 */
#ifndef INTEROP_SERVER_H
#define INTEROP_SERVER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

/* ---- Interop message types (from lxinitshared.h LX_MESSAGE_TYPE enum) ---- */
#ifndef LxInitMessageCreateProcess
#define LxInitMessageCreateProcess               1
#endif
#ifndef LxInitMessageCreateProcessResponse
#define LxInitMessageCreateProcessResponse       11
#endif
#ifndef LxInitMessageQueryDrvfsElevated
#define LxInitMessageQueryDrvfsElevated          12
#endif
#ifndef LxInitMessageQueryEnvironmentVariable
#define LxInitMessageQueryEnvironmentVariable    16
#endif
#ifndef LxInitMessageQueryFeatureFlags
#define LxInitMessageQueryFeatureFlags           17
#endif
#ifndef LxInitMessageCreateLoginSession
#define LxInitMessageCreateLoginSession          23
#endif
#ifndef LxInitMessageQueryNetworkingMode
#define LxInitMessageQueryNetworkingMode         25
#endif
#ifndef LxInitMessageQueryVmId
#define LxInitMessageQueryVmId                   26
#endif

/* Result message types */
#ifndef LxMessageResultBool
#define LxMessageResultBool                      76
#endif
#ifndef LxMessageResultInt32
#define LxMessageResultInt32                     77
#endif
#ifndef LxMessageResultUint8
#define LxMessageResultUint8                     79
#endif

/* Feature flags (LX_INIT_FEATURE_FLAGS) */
#ifndef LxInitFeatureNone
#define LxInitFeatureNone               0x00
#define LxInitFeatureVirtIo9p           0x01
#define LxInitFeatureVirtIoFs           0x02
#define LxInitFeatureDisable9pServer    0x04
#define LxInitFeatureRootfsCompressed   0x08
#define LxInitFeatureSystemDistro       0x10
#define LxInitFeatureDnsTunneling       0x20
#endif

/* Networking modes */
#ifndef LxInitNetworkingModeNat
#define LxInitNetworkingModeNat       0
#define LxInitNetworkingModeMirrored  1
#define LxInitNetworkingModeBridged   2
#endif

/* CreateProcess result flags */
#ifndef LX_INIT_CREATE_PROCESS_RESULT_FLAG_GUI_APPLICATION
#define LX_INIT_CREATE_PROCESS_RESULT_FLAG_GUI_APPLICATION 0x1
#endif

/* ---- Struct definitions ----
 * Guarded to avoid redefinition when wsl_protocol.h is already included. */
#ifndef WSL_PROTOCOL_H

/* RESULT_MESSAGE<bool> — bool stored as uint32_t for 4-byte alignment.
 * sizeof = 16 bytes (12 header + 4 result), matching C++ layout. */
struct RESULT_MESSAGE_BOOL {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
};

/* RESULT_MESSAGE<int32_t> — sizeof = 16 bytes */
struct RESULT_MESSAGE_INT32 {
    struct MESSAGE_HEADER Header;
    int32_t Result;
};

/* RESULT_MESSAGE<uint8_t> — uint8_t stored as uint32_t for alignment.
 * sizeof = 16 bytes */
struct RESULT_MESSAGE_UINT8 {
    struct MESSAGE_HEADER Header;
    uint32_t Result;
};

/* QueryEnvironmentVariable (type 16) */
struct LX_INIT_QUERY_ENVIRONMENT_VARIABLE {
    struct MESSAGE_HEADER Header;
    char Buffer[];
};

/* QueryVmId (type 26) */
struct LX_INIT_QUERY_VM_ID {
    struct MESSAGE_HEADER Header;
    char Buffer[];
};

/* CreateLoginSession (type 23) */
struct LX_INIT_CREATE_LOGIN_SESSION {
    struct MESSAGE_HEADER Header;
    unsigned int Uid;
    unsigned int Gid;
    char Buffer[];
};

/* CreateProcessResponse (type 11) */
struct LX_INIT_CREATE_PROCESS_RESPONSE {
    struct MESSAGE_HEADER Header;
    int Result;
    int64_t SignalPipeId;
    unsigned int Flags;
};

#endif /* WSL_PROTOCOL_H */

/* ---- Buffered reader for interop channel ----
 * Similar to control_reader — handles partial reads on non-blocking sockets. */
struct interop_reader {
    char buf[1024];
    size_t len;
};

static inline void interop_reader_init(struct interop_reader *ir)
{
    ir->len = 0;
}

/* Try to read a complete message from the interop channel.
 * Returns: 1 = message available (pointed to by *out_msg),
 *          0 = need more data,
 *         -1 = error/disconnect. */
static inline int interop_try_read(int fd, struct interop_reader *ir,
                                   void **out_msg)
{
    if (ir->len < sizeof(ir->buf)) {
        ssize_t n = recv(fd, ir->buf + ir->len, sizeof(ir->buf) - ir->len, 0);
        if (n > 0) {
            ir->len += (size_t)n;
        } else if (n == 0) {
            return -1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
    }

    if (ir->len < sizeof(struct MESSAGE_HEADER)) return 0;

    struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)ir->buf;
    if (hdr->MessageSize < sizeof(*hdr) || hdr->MessageSize > sizeof(ir->buf))
        return -1;
    if (ir->len < hdr->MessageSize) return 0;

    *out_msg = ir->buf;
    return 1;
}

static inline void interop_consume(struct interop_reader *ir, size_t msg_size)
{
    if (ir->len > msg_size) {
        memmove(ir->buf, ir->buf + msg_size, ir->len - msg_size);
        ir->len -= msg_size;
    } else {
        ir->len = 0;
    }
}

/* ---- Response senders ---- */

static inline void interop_send_bool(int fd, unsigned int seq, uint32_t value)
{
    struct RESULT_MESSAGE_BOOL resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultBool;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;
    resp.Result = value;
    send_all(fd, &resp, sizeof(resp));
}

static inline void interop_send_int32(int fd, unsigned int seq, int32_t value)
{
    struct RESULT_MESSAGE_INT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultInt32;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;
    resp.Result = value;
    send_all(fd, &resp, sizeof(resp));
}

static inline void interop_send_uint8(int fd, unsigned int seq, uint8_t value)
{
    struct RESULT_MESSAGE_UINT8 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint8;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;
    resp.Result = value;
    send_all(fd, &resp, sizeof(resp));
}

/* Send a QueryEnvironmentVariable response with the value string in Buffer. */
static inline void interop_send_env_var_response(int fd, unsigned int seq,
                                                 const char *value)
{
    size_t value_len = strlen(value) + 1;
    size_t msg_size = sizeof(struct MESSAGE_HEADER) + value_len;
    char *buf = malloc(msg_size);
    if (!buf) return;

    struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)buf;
    hdr->MessageType = LxInitMessageQueryEnvironmentVariable;
    hdr->MessageSize = (unsigned int)msg_size;
    hdr->SequenceNumber = seq;
    memcpy(buf + sizeof(*hdr), value, value_len);

    send_all(fd, buf, msg_size);
    free(buf);
}

/* Send a QueryVmId response with the VmId string in Buffer. */
static inline void interop_send_vm_id_response(int fd, unsigned int seq,
                                               const char *vm_id)
{
    size_t id_len = strlen(vm_id) + 1;
    size_t msg_size = sizeof(struct MESSAGE_HEADER) + id_len;
    char *buf = malloc(msg_size);
    if (!buf) return;

    struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)buf;
    hdr->MessageType = LxInitMessageQueryVmId;
    hdr->MessageSize = (unsigned int)msg_size;
    hdr->SequenceNumber = seq;
    memcpy(buf + sizeof(*hdr), vm_id, id_len);

    send_all(fd, buf, msg_size);
    free(buf);
}

/* Send a CreateProcessResponse (type 11). */
static inline void interop_send_create_process_response(int fd,
                                                        unsigned int seq,
                                                        int result,
                                                        int64_t signal_pipe_id,
                                                        unsigned int flags)
{
    struct LX_INIT_CREATE_PROCESS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxInitMessageCreateProcessResponse;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;
    resp.Result = result;
    resp.SignalPipeId = signal_pipe_id;
    resp.Flags = flags;
    send_all(fd, &resp, sizeof(resp));
}

/* ---- Message dispatcher ----
 * Process one complete interop message and send the appropriate response.
 * Returns: 0 = handled, -1 = error. */
static inline int interop_process_message(int fd, void *msg, size_t msg_size)
{
    struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)msg;

    switch (hdr->MessageType) {
    case LxInitMessageQueryDrvfsElevated:
        /* No DrvFs yet — always return false (not elevated). */
        printf("[interop] QueryDrvfsElevated -> false\n");
        interop_send_bool(fd, hdr->SequenceNumber, 0);
        break;

    case LxInitMessageQueryEnvironmentVariable: {
        /* Buffer starts right after the 12-byte header. */
        const char *var_name = (const char *)msg + sizeof(struct MESSAGE_HEADER);
        /* Ensure NUL-terminated (buffer may be exactly the var name). */
        const char *value = getenv(var_name);
        if (!value) value = "";
        printf("[interop] QueryEnvironmentVariable '%s' -> '%s'\n",
               var_name, value);
        interop_send_env_var_response(fd, hdr->SequenceNumber, value);
        break;
    }

    case LxInitMessageQueryFeatureFlags:
        /* Return 0 — no features enabled (no systemd, no 9p, no virtiofs). */
        printf("[interop] QueryFeatureFlags -> 0\n");
        interop_send_int32(fd, hdr->SequenceNumber, 0);
        break;

    case LxInitMessageCreateLoginSession: {
        /* Parse Uid, Gid, username from the message. */
        struct LX_INIT_CREATE_LOGIN_SESSION *cls =
            (struct LX_INIT_CREATE_LOGIN_SESSION *)msg;
        if (msg_size >= sizeof(struct MESSAGE_HEADER) + sizeof(unsigned int) * 2) {
            printf("[interop] CreateLoginSession uid=%u gid=%u username='%s' -> true\n",
                   cls->Uid, cls->Gid, cls->Buffer);
        }
        /* Minimal implementation: return success without actually creating
         * a login session. Full implementation would forkpty + /bin/login. */
        interop_send_bool(fd, hdr->SequenceNumber, 1);
        break;
    }

    case LxInitMessageQueryNetworkingMode:
        /* Return NAT mode (0) as default. */
        printf("[interop] QueryNetworkingMode -> NAT(0)\n");
        interop_send_uint8(fd, hdr->SequenceNumber, LxInitNetworkingModeNat);
        break;

    case LxInitMessageQueryVmId:
        /* No VM ID configured — return empty string. */
        printf("[interop] QueryVmId -> (empty)\n");
        interop_send_vm_id_response(fd, hdr->SequenceNumber, "");
        break;

    case LxInitMessageCreateProcess:
        /* Cannot create Windows NT processes from FreeBSD.
         * Return ENOENT (no such file or directory). */
        printf("[interop] CreateProcess -> ENOENT (cannot launch Windows binaries)\n");
        interop_send_create_process_response(fd, hdr->SequenceNumber,
                                             ENOENT, 0, 0);
        break;

    default:
        printf("[interop] unhandled message type=%u (size=%u, seq=%u)\n",
               hdr->MessageType, hdr->MessageSize, hdr->SequenceNumber);
        break;
    }

    return 0;
}

#endif /* INTEROP_SERVER_H */
