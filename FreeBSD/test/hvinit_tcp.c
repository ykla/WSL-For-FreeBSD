/*
 * SPDX-License-Identifier: MIT
 *
 * hvinit_tcp.c - TCP-adapted version of hvinit.c for local testing.
 *
 * Replaces AF_HYPERV with AF_INET so the guest can run on Linux.
 * Protocol logic is identical to the Phase 0 fixed hvinit.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>

#include "wsl_protocol.h"
#include "gns_engine.h"

/* Phase 1: additional message types for event loop */
#define LxInitMessageTerminateInstance  14

/* Phase 1: SIGCHLD self-pipe */
static int g_sigchld_pipe[2] = {-1, -1};

static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_sigchld_pipe[1] >= 0) {
        char c = 'c';
        (void)write(g_sigchld_pipe[1], &c, 1);
    }
}

static void reap_children(void)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        printf("[init] child pid %d exited (status=%d)\n", pid, status);
    }
}

/* Phase 1: Handle TerminateInstance (type 14) — clean shutdown */
static void handle_terminate_instance(int init_fd, struct MESSAGE_HEADER *hdr)
{
    printf("[init] received TerminateInstance, shutting down\n");

    RESULT_MESSAGE_UINT32 resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxMessageResultUint32;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = hdr->SequenceNumber;
    resp.Result = 0;
    send_all(init_fd, &resp, sizeof(resp));

    sync();
    exit(0);
}

/* Phase 1: Handle WindowSizeChanged (type 10) — forward to notify channel */
static void handle_window_size_changed(int notify_fd, void *msg_buf, size_t msg_size)
{
    if (msg_size < sizeof(LX_INIT_WINDOW_SIZE_CHANGED)) return;
    LX_INIT_WINDOW_SIZE_CHANGED *wsc = (LX_INIT_WINDOW_SIZE_CHANGED *)msg_buf;
    printf("[init] WindowSizeChanged: rows=%u, cols=%u\n", wsc->Rows, wsc->Columns);

    if (notify_fd >= 0) {
        send_all(notify_fd, msg_buf, msg_size);
    }
}

/* Phase 1: Event loop — replaces pause() */
static void event_loop(int init_fd, int notify_fd)
{
    printf("[init] entering event loop (init_fd=%d, notify_fd=%d)\n", init_fd, notify_fd);

    /* FIX: set init_fd non-blocking so recv_all can handle partial reads
     * without blocking the event loop (and missing SIGCHLD). */
    fcntl(init_fd, F_SETFL, fcntl(init_fd, F_GETFL) | O_NONBLOCK);

    if (pipe(g_sigchld_pipe) < 0) {
        perror("[init] pipe");
        g_sigchld_pipe[0] = g_sigchld_pipe[1] = -1;
    } else {
        fcntl(g_sigchld_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(g_sigchld_pipe[1], F_SETFL, O_NONBLOCK);
        signal(SIGCHLD, sigchld_handler);
    }

    for (;;) {
        struct pollfd pfds[2];
        int nfds = 0;

        pfds[nfds].fd = init_fd;  pfds[nfds].events = POLLIN;  nfds++;
        if (g_sigchld_pipe[0] >= 0) {
            pfds[nfds].fd = g_sigchld_pipe[0];  pfds[nfds].events = POLLIN;  nfds++;
        }

        int rc = poll(pfds, nfds, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[init] poll");
            break;
        }

        /* SIGCHLD — reap zombie children */
        if (nfds > 1 && (pfds[1].revents & POLLIN)) {
            char c;
            while (read(g_sigchld_pipe[0], &c, 1) > 0) {}
            reap_children();
        }

        /* Message from host on init channel */
        if (pfds[0].revents & POLLIN) {
            struct MESSAGE_HEADER hdr;
            if (recv_all(init_fd, &hdr, sizeof(hdr)) < 0) {
                printf("[init] host disconnected from init channel\n");
                break;
            }

            if (hdr.MessageSize < sizeof(hdr)) {
                printf("[init] invalid message size %u\n", hdr.MessageSize);
                continue;
            }

            size_t payload_len = hdr.MessageSize - sizeof(hdr);
            char *payload = NULL;
            if (payload_len > 0) {
                payload = malloc(payload_len);
                if (!payload) { perror("[init] malloc"); break; }
                if (recv_all(init_fd, payload, payload_len) < 0) {
                    printf("[init] failed to read payload\n");
                    free(payload);
                    break;
                }
            }

            /* Build full message for handlers */
            char *full_msg = malloc(hdr.MessageSize);
            if (full_msg) {
                memcpy(full_msg, &hdr, sizeof(hdr));
                if (payload_len > 0)
                    memcpy(full_msg + sizeof(hdr), payload, payload_len);

                switch (hdr.MessageType) {
                case LxInitMessageTerminateInstance:
                    handle_terminate_instance(init_fd, &hdr);
                    break; /* not reached */

                case LxInitMessageWindowSizeChanged:
                    handle_window_size_changed(notify_fd, full_msg, hdr.MessageSize);
                    break;

                /* Phase 9 (Task Group C): networking messages */
                case LxInitMessageNetworkInformation:
                    gns_handle_network_information(full_msg, hdr.MessageSize);
                    break;

                case LxInitMessageStartSocketRelay: {
                    struct relay_state rs;
                    memset(&rs, 0, sizeof(rs));
                    int r = gns_handle_start_socket_relay(init_fd, full_msg,
                                                          hdr.MessageSize, &rs);
                    if (r < 0) {
                        fprintf(stderr, "[init] StartSocketRelay failed\n");
                    }
                    break;
                }

                case LxInitMessageQueryNetworkingMode:
                    gns_handle_query_networking_mode(init_fd, full_msg,
                                                    hdr.MessageSize);
                    break;

                case LxInitMessageQueryVmId:
                    gns_handle_query_vm_id(init_fd, full_msg, hdr.MessageSize);
                    break;

                default:
                    printf("[init] unhandled message type %u (size=%u, seq=%u)\n",
                           hdr.MessageType, hdr.MessageSize, hdr.SequenceNumber);
                    break;
                }
                free(full_msg);
            }
            free(payload);
        }
    }
}

/* Connect to a TCP port on localhost. Returns fd or -1. */
static int hv_connect(unsigned int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

/* Send CreateInstanceResult (type 33) with ConnectPort=60000. */
static void send_create_instance_result(int init_fd)
{
    size_t msglen = sizeof(LX_MINI_INIT_CREATE_INSTANCE_RESULT);
    LX_MINI_INIT_CREATE_INSTANCE_RESULT *msg = malloc(msglen);
    if (!msg) return;
    memset(msg, 0, msglen);

    msg->Header.MessageType = LxMiniInitMessageCreateInstanceResult;
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1;
    msg->Result = 0;
    msg->Pid = (uint64_t)getpid();
    msg->ConnectPort = PORT_HVS_BSD;

    if (send_all(init_fd, msg, msglen) < 0)
        perror("[init] send create_instance_result");
    else
        printf("[init] sent CreateInstanceResult (type=%u, seq=%u, ConnectPort=%u)\n",
               msg->Header.MessageType, msg->Header.SequenceNumber, msg->ConnectPort);
    free(msg);
}

/* Send ConfigurationInformationResponse (type 6), echoing host's seq. */
static void send_configuration_info_response(int init_fd, unsigned int seq)
{
    const char *flavor = "GenericFlavor";
    const char *version = "1.0.0";
    size_t payload_len = strlen(flavor) + 1 + strlen(version) + 1;
    size_t msglen = sizeof(LX_INIT_CONFIGURATION_INFORMATION_RESPONSE) + payload_len;

    LX_INIT_CONFIGURATION_INFORMATION_RESPONSE *resp = malloc(msglen);
    if (!resp) return;
    memset(resp, 0, msglen);

    resp->Header.MessageType = LxInitMessageInitializeResponse;
    resp->Header.MessageSize = (unsigned int)msglen;
    resp->Header.SequenceNumber = seq;  /* Phase 0 fix: echo host's seq */
    resp->Plan9Port = 0;
    resp->DefaultUid = 1;
    resp->InteropPort = PORT_HVS_BSD;
    resp->SystemdEnabled = false;  /* Phase 0 fix: FreeBSD has no systemd */
    resp->PidNamespace = 0;
    resp->FlavorIndex = 0;
    resp->VersionIndex = 0;
    memcpy(resp->Buffer, flavor, strlen(flavor) + 1);
    memcpy(resp->Buffer + strlen(flavor) + 1, version, strlen(version) + 1);

    if (send_all(init_fd, resp, msglen) < 0)
        perror("[init] send config_response");
    else
        printf("[init] sent InitializeResponse (type=%u, seq=%u, InteropPort=%u, Systemd=%d)\n",
               resp->Header.MessageType, resp->Header.SequenceNumber,
               resp->InteropPort, resp->SystemdEnabled);
    free(resp);
}

/* Send CreateSessionResponse (type 3), echoing host's seq. */
static void send_create_session_response(int init_fd, unsigned int port, unsigned int seq)
{
    LX_INIT_CREATE_SESSION_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.Header.MessageType = LxInitMessageCreateSessionResponse;
    resp.Header.MessageSize = sizeof(resp);
    resp.Header.SequenceNumber = seq;  /* Phase 0 fix: echo host's seq */
    resp.Port = port;

    if (send_all(init_fd, &resp, sizeof(resp)) < 0)
        perror("[init] send session_response");
    else
        printf("[init] sent CreateSessionResponse (type=%u, seq=%u, Port=%u)\n",
               resp.Header.MessageType, resp.Header.SequenceNumber, resp.Port);
}

int main(void)
{
    printf("[init] hvinit_tcp starting (pid=%d)\n", getpid());

    /* 1. Capability channel: connect and send GuestCapabilities */
    int cap_fd = hv_connect(PORT_HVS);
    if (cap_fd < 0) { fprintf(stderr, "[init] FATAL: cannot connect to host\n"); return 1; }

    const char *kver = "FreeBSD-13.3-HVPoC";
    size_t msglen = sizeof(LX_INIT_GUEST_CAPABILITIES) + strlen(kver) + 1;
    LX_INIT_GUEST_CAPABILITIES *msg = malloc(msglen);
    memset(msg, 0, msglen);
    /* Phase 0 fix: full 12-byte MESSAGE_HEADER instead of uint32_t */
    msg->Header.MessageType = LxMiniInitMessageGuestCapabilities;  /* 43, not 1 */
    msg->Header.MessageSize = (unsigned int)msglen;
    msg->Header.SequenceNumber = 1;
    msg->SeccompAvailable = false;
    strcpy(msg->Buffer, kver);

    if (send_all(cap_fd, msg, msglen) < 0) {
        perror("[init] send capabilities");
        free(msg);
        return 1;
    }
    printf("[init] sent GuestCapabilities (type=%u, size=%zu, Seccomp=%d, kver='%s')\n",
           msg->Header.MessageType, msglen, msg->SeccompAvailable, msg->Buffer);
    free(msg);

    /* 2. Notify channel */
    int notify_fd = hv_connect(PORT_HVS);
    if (notify_fd < 0) return 1;
    printf("[init] notify channel connected\n");

    /* 3. Init channel */
    int init_fd = hv_connect(PORT_HVS);
    if (init_fd < 0) return 1;
    printf("[init] init channel connected\n");

    /* 4. Send CreateInstanceResult */
    send_create_instance_result(init_fd);

    /* 5. Receive Initialize(5), respond with InitializeResponse(6) */
    char recv_buf[512];
    ssize_t r1 = recv(init_fd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (r1 > 0) {
        recv_buf[r1] = '\0';  /* Phase 0 fix: was recv_buf[r] — buffer overflow */
        printf("[init] received Initialize (%zd bytes)\n", r1);
        unsigned int init_seq = 1;
        if ((size_t)r1 >= sizeof(struct MESSAGE_HEADER)) {
            struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)recv_buf;
            printf("[init]   host Initialize: type=%u, seq=%u\n",
                   hdr->MessageType, hdr->SequenceNumber);
            init_seq = hdr->SequenceNumber;
        }
        send_configuration_info_response(init_fd, init_seq);
    } else {
        perror("[init] recv Initialize");
    }

    /* 6. Receive CreateSession(2), respond with CreateSessionResponse(3) */
    r1 = recv(init_fd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (r1 > 0) {
        recv_buf[r1] = '\0';
        printf("[init] received CreateSession (%zd bytes)\n", r1);
        unsigned int sess_seq = 1;
        if ((size_t)r1 >= sizeof(struct MESSAGE_HEADER)) {
            struct MESSAGE_HEADER *hdr = (struct MESSAGE_HEADER *)recv_buf;
            printf("[init]   host CreateSession: type=%u, seq=%u\n",
                   hdr->MessageType, hdr->SequenceNumber);
            sess_seq = hdr->SequenceNumber;
        }
        send_create_session_response(init_fd, PORT_HVS_BSD, sess_seq);
    } else {
        perror("[init] recv CreateSession");
    }

    printf("[init] handshake complete, entering event loop\n");
    /* Phase 1: event loop replaces pause() */
    event_loop(init_fd, notify_fd);

    /* Clean up (only reached if event loop exits) */
    close(cap_fd);
    if (notify_fd >= 0) close(notify_fd);
    if (init_fd >= 0) close(init_fd);
    return 0;
}
