/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 Balaje Sankar */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>


struct sockaddr_hvs {
    unsigned char   sa_len;
    sa_family_t     sa_family;
    unsigned int    hvs_port;
unsigned char   hvs_zero[sizeof(struct sockaddr) -
                             sizeof(sa_family_t) -
                             sizeof(unsigned char) -
                             sizeof(unsigned int)];
};

#define PORT_HVS              50000  // same port for all connections
#define PORT_HVS_BSD          60000
#define LxMiniInitMessageGuestCapabilities 1

typedef struct LX_INIT_GUEST_CAPABILITIES {
    uint32_t Header;          // message type
    bool SeccompAvailable;
    char Buffer[];            // kernel version string
} LX_INIT_GUEST_CAPABILITIES;



/* MESSAGE_HEADER in C */
struct MESSAGE_HEADER {
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};
typedef struct MESSAGE_HEADER MESSAGE_HEADER;

typedef struct _RESULT_MESSAGE_UINT32 {
    MESSAGE_HEADER Header;
    uint32_t Result;
} RESULT_MESSAGE_UINT32;

typedef struct _LX_INIT_CREATE_SESSION {
    MESSAGE_HEADER Header;
    int64_t ConsoleId;
} LX_INIT_CREATE_SESSION;

typedef struct _LX_INIT_CREATE_SESSION_RESPONSE {
    MESSAGE_HEADER Header;
    unsigned int Port;   // port to return
} LX_INIT_CREATE_SESSION_RESPONSE;


typedef struct _LX_INIT_CONFIGURATION_INFORMATION_RESPONSE {
    MESSAGE_HEADER Header;
    uint32_t Plan9Port;
    uint32_t DefaultUid;
    uint32_t InteropPort;
    bool SystemdEnabled;
    uint64_t PidNamespace;
    uint32_t FlavorIndex;
    uint32_t VersionIndex;
    char Buffer[]; // optional extra data
} LX_INIT_CONFIGURATION_INFORMATION_RESPONSE;


/* Equivalent of LX_MINI_INIT_CREATE_INSTANCE_RESULT in C */
#define LX_MINI_INIT_CREATE_INSTANCE_RESULT_TYPE 33

typedef struct _LX_MINI_INIT_CREATE_INSTANCE_RESULT {
    struct MESSAGE_HEADER Header;
    int Result;
    unsigned int FailureStep;
    uint64_t Pid;
    uint32_t ConnectPort;
    unsigned int WarningsOffset;
    char Buffer[];
} LX_MINI_INIT_CREATE_INSTANCE_RESULT;

void send_create_session_response(int init_fd, unsigned int port, unsigned int seq)
{
    LX_INIT_CREATE_SESSION_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));

    resp.Header.MessageType = /*LxInitMessageCreateSessionResponse*/ 3; // adjust as needed
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = 3; // echo or increment host’s seq
    resp.Port = PORT_HVS_BSD;

    ssize_t sent = send(init_fd, &resp, sizeof(resp), 0);
    if (sent < 0) {
        perror("[init] send create_session_response");
    } else {
        printf("[init] sent LX_INIT_CREATE_SESSION_RESPONSE (%zd bytes)\n", sent);
    }
}

void handle_create_process_utility_vm(int sock)
{
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <=0) {
        perror("recv");
        return;
    }

    // Just to show we got the request:
    printf("Received LX_INIT_CREATE_PROCESS_UTILITY_VM message (%zd bytes)\n", n);

    // Build RESULT_MESSAGE<uint32_t> with port=60000
    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType=8;
resp.Header.MessageSize= sizeof(resp);
resp.Header.SequenceNumber=4;
    resp.Result = 60000;

    // Send back
    if (send(sock, &resp, sizeof(resp), 0) != sizeof(resp)) {
        perror("send");
    } else {
        printf("Sent RESULT_MESSAGE<uint32_t> with Type=%u Seq=%u Port=%u\n",
               resp.Header.MessageType, resp.Header.SequenceNumber, resp.Result);
    }
}

void send_configuration_info_response(int init_fd) {
    const char *flavor = "GenericFlavor";
    const char *version = "1.0.0";

    size_t payload_len = strlen(flavor) + 1 + strlen(version) + 1;
    size_t msglen = sizeof(LX_INIT_CONFIGURATION_INFORMATION_RESPONSE) + payload_len;

    LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *resp = malloc(msglen);
    if (!resp) { perror("malloc"); return; }

    // Fill MESSAGE_HEADER
    resp->Header.MessageType = 6; // replace with LxInitMessageInitializeResponse if defined
    resp->Header.MessageSize = (unsigned int)msglen;
    resp->Header.SequenceNumber = 2; // example, or track real sequence

    // Fill fields
    resp->Plan9Port = 0;           // example
    resp->DefaultUid = 1;
    resp->InteropPort = 60000;        // example
    resp->SystemdEnabled =1 ;
    resp->PidNamespace = 0;           // adjust if needed
    resp->FlavorIndex = 0;            // optional, we can copy to buffer instead
    resp->VersionIndex = 0;           // optional, copy to buffer

    // Copy strings sequentially in Buffer
    char *buf_ptr = resp->Buffer;
    strcpy(buf_ptr, flavor);
    buf_ptr += strlen(flavor) + 1;
    strcpy(buf_ptr, version);

    ssize_t sent = send(init_fd, resp, msglen, 0);
    if (sent < 0) {
        perror("[init] send configuration_info_response");
    } else {
        printf("[init] sent LX_INIT_CONFIGURATION_INFORMATION_RESPONSE (%zd bytes)\n", sent);
    }

    free(resp);
}

void send_create_instance_result(int init_fd)
{
    const char *warning_str = "No warnings";

    size_t payload_len = strlen(warning_str) + 1;
    size_t msglen = sizeof(LX_MINI_INIT_CREATE_INSTANCE_RESULT) + payload_len;

    LX_MINI_INIT_CREATE_INSTANCE_RESULT *msg = malloc(msglen);
    if (!msg) { perror("malloc"); return; }

    // Fill header
    msg->Header.MessageType = 33;
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1; // example sequence number

    // Fill message fields
    msg->Result = 0;            // success
    msg->FailureStep = 0;       // example
    msg->Pid = 1;
    msg->ConnectPort = PORT_HVS_BSD;
    msg->WarningsOffset = 0;    // offset in Buffer

    // Copy Buffer content
    strcpy(msg->Buffer, warning_str);

    // Send over init_fd
    ssize_t sent = send(init_fd, msg, msglen, 0);
    if (sent < 0) {
        perror("[init] send create_instance_result");
    } else {
        printf("[init] sent LX_MINI_INIT_CREATE_INSTANCE_RESULT (%zd bytes)\n", sent);
    }

    free(msg);
}

static int hv_connect(unsigned int port) {
    int s = socket(AF_HYPERV, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_hvs addr;
    memset(&addr, 0, sizeof(addr));
    addr.sa_len = sizeof(addr);
    addr.sa_family = AF_HYPERV;
    addr.hvs_port = port;

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(s);
        return -1;
    }
    return s;
}

int main(void) {
    /* === 1. Capability socket === */
    int cap_fd = hv_connect(PORT_HVS);
    if (cap_fd < 0) {
        fprintf(stderr, "Failed to establish capability socket\n");
        return 1;
    }

    const char *kver = "FreeBSD-13.3-HVPoC";
    size_t msglen = sizeof(LX_INIT_GUEST_CAPABILITIES) + strlen(kver) + 1;
LX_INIT_GUEST_CAPABILITIES *msg = malloc(msglen);
    msg->Header = LxMiniInitMessageGuestCapabilities;
    msg->SeccompAvailable = false;
    strcpy(msg->Buffer, kver);

    if (send(cap_fd, msg, msglen, 0) < 0) {
        perror("send mini_init");
        free(msg);
        close(cap_fd);
        return 1;
    }
    free(msg);

printf("[capability] sent capabilities: %s\n", kver);

    /* === 2. Notify socket === */
    int notify_fd = hv_connect(PORT_HVS);
    if (notify_fd < 0) {
        fprintf(stderr, "Failed to establish notify socket\n");
        // continue anyway, still have cap_fd
    } else {
        printf("[notify] socket connected (fd=%d)\n", notify_fd);
    }
    /* === 3. Receive first message on capability socket === */
    char buf[256];
    ssize_t r = recv(cap_fd, buf, sizeof(buf)-1, 0);
    if (r > 0) {
        buf[r] = '\0';
        printf("[capability] first message received (%zd bytes): %s\n", r, buf);
    } else if (r == 0) {
printf("[capability] Host closed connection before first message\n");
        close(cap_fd);
        if (notify_fd >= 0) close(notify_fd);
        return 1;
    } else {
        perror("[capability] recv");
        close(cap_fd);
        if (notify_fd >= 0) close(notify_fd);
        return 1;
    }
    /* === 4. Create init socket after first message === */
    int init_fd = hv_connect(PORT_HVS);
    if (init_fd < 0) {
        fprintf(stderr, "Failed to establish init socket\n");
    } else {
        printf("[init] socket connected (fd=%d)\n", init_fd);
    }
    /* === 5. Keep all three sockets open === */
    printf("[main] All sockets are open: cap_fd=%d notify_fd=%d init_fd=%d\n",
           cap_fd, notify_fd, init_fd);
    printf("Press Ctrl+C to exit; sockets stay open.\n");
    send_create_instance_result(init_fd);

//handle send and receive message from void WslCoreInstance::Initialize()

char recv_buf[512];
ssize_t r1 = recv(init_fd, recv_buf, sizeof(recv_buf)-1, 0);
if (r1 > 0) {
    recv_buf[r] = '\0';
    printf("[init] received configuration information (%zd bytes)\n", r1);
    send_configuration_info_response(init_fd);
} else {
    perror("[init] recv configuration info");
}

// --- 6. Receive LX_INIT_CREATE_SESSION ---
LX_INIT_CREATE_SESSION create_sess;
ssize_t r2 = recv(init_fd, &create_sess, sizeof(create_sess), 0);
if (r2 <= 0) {
    perror("[init] recv create_session");
} else {
    printf("[init] received LX_INIT_CREATE_SESSION (%zd bytes): ConsoleId=%lld\n",
           r2, (long long)create_sess.ConsoleId);

    // Send back LX_INIT_CREATE_SESSION_RESPONSE
    // echo the sequence number from host
    send_create_session_response(init_fd, PORT_HVS_BSD, create_sess.Header.SequenceNumber);
}

// --- 7. Receive and echo LX_INIT_CREATE_PROCESS_UTILITY_VM ---
// handle_create_process_utility_vm(init_fd);
    while (1) {
        pause();  // keep process alive without closing sockets
    }
    // (never reached normally)
    close(cap_fd);
    if (notify_fd >= 0) close(notify_fd);
    if (init_fd >= 0) close(init_fd);
    return 0;
} 
