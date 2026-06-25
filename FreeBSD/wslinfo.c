/* SPDX-License-Identifier: MIT */
/*
 * wslinfo.c - Query WSL environment information.
 *
 * This is the FreeBSD C port of the Linux wslinfo.cpp reference
 * (src/linux/init/wslinfo.cpp). It prints WSL environment details
 * such as the VM GUID, networking mode, WSL version, and distro name.
 *
 * Usage:
 *   wslinfo [OPTION]
 *     --vm-id            Print the VM GUID (from /etc/hostid on FreeBSD)
 *     --networking-mode  Print the networking mode (NAT or MIRRORED)
 *     --version          Print the WSL version string
 *     --wsl-version      Print the WSL version number (1 or 2)
 *     --name             Print the distribution name (from WSL_DISTRO_NAME)
 *     -n                 Do not print a trailing newline
 *     --help             Show this help message
 *
 * Examples:
 *   wslinfo --vm-id             ->  12345678-1234-1234-1234-123456789abc
 *   wslinfo --networking-mode   ->  NAT
 *   wslinfo --version           ->  2.3.24.0
 *
 * The tool degrades gracefully when not running under WSL:
 *   --networking-mode defaults to NAT if the interop channel is unavailable.
 *   --vm-id reads /etc/hostid or /etc/machine-id; prints all-zeros if absent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

/* ---- WSL interop message types (from lxinitshared.h) ---- */
#define LxInitMessageQueryNetworkingMode  25
#define LxInitMessageQueryVmId            26

/* Result message types */
#define LxMessageResultUint32             78
#define LxMessageResultUint8              79

/* Networking mode values */
#define LX_INIT_NETWORKING_MODE_NAT       0
#define LX_INIT_NETWORKING_MODE_MIRRORED  1
#define LX_INIT_NETWORKING_MODE_BRIDGED   2

/* ---- Interop socket discovery (matching wsl_interop.h) ---- */
#define WSL_INTEROP_ENV                   "WSL_INTEROP"
#define WSL_INTEROP_TEMP_FOLDER           "/run/WSL"
#define WSL_INTEROP_SOCKET_NAME           "interop"

/* ---- WSL version string ---- */
#ifndef WSL_PACKAGE_VERSION
#define WSL_PACKAGE_VERSION "2.3.24.0"
#endif

/* ---- Environment variable for the distro name ---- */
#define WSL_DISTRO_NAME_ENV "WSL_DISTRO_NAME"

/*
 * Maximum size of the interop socket path.
 * /run/WSL/<pid>_interop — pid can be up to 10 digits.
 */
#define SOCK_PATH_MAX 64

/* -----------------------------------------------------------------------
 * usage - Print usage information to stderr.
 * ----------------------------------------------------------------------- */
static void
usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTION]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Query WSL environment information.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --vm-id            Print the VM GUID\n");
    fprintf(stderr, "  --networking-mode  Print the networking mode (NAT or MIRRORED)\n");
    fprintf(stderr, "  --version          Print the WSL version string\n");
    fprintf(stderr, "  --wsl-version      Print the WSL version number (1 or 2)\n");
    fprintf(stderr, "  --name             Print the distribution name\n");
    fprintf(stderr, "  -n                 Do not print a trailing newline\n");
    fprintf(stderr, "  --help             Show this help message\n");
}

/* -----------------------------------------------------------------------
 * Message header (12 bytes, matching the WSL protocol).
 * ----------------------------------------------------------------------- */
struct MESSAGE_HEADER
{
    unsigned int MessageType;
    unsigned int MessageSize;
    unsigned int SequenceNumber;
};

/* -----------------------------------------------------------------------
 * Result message (16 bytes: 12-byte header + 4-byte result).
 * Used for both ResultUint32(78) and ResultUint8(79) responses.
 * ----------------------------------------------------------------------- */
struct RESULT_MESSAGE
{
    struct MESSAGE_HEADER Header;
    uint32_t Result;
};

/* -----------------------------------------------------------------------
 * find_interop_socket - Locate the WSL interop Unix socket.
 *
 * Checks the WSL_INTEROP environment variable first, then searches
 * /run/WSL/<ppid>_interop (matching the reference util.cpp behaviour).
 *
 * Returns 0 on success (path_buf filled), -1 if not found.
 * ----------------------------------------------------------------------- */
static int
find_interop_socket(char *path_buf, size_t path_len)
{
    /* Check WSL_INTEROP environment variable first */
    const char *env_path = getenv(WSL_INTEROP_ENV);
    if (env_path && env_path[0] != '\0' && access(env_path, F_OK) == 0)
    {
        strncpy(path_buf, env_path, path_len - 1);
        path_buf[path_len - 1] = '\0';
        return 0;
    }

    /* Search /run/WSL/<ppid>_interop */
    pid_t parent = getppid();
    if (parent > 0)
    {
        snprintf(path_buf, path_len, "%s/%d_%s",
                 WSL_INTEROP_TEMP_FOLDER, (int)parent,
                 WSL_INTEROP_SOCKET_NAME);
        if (access(path_buf, F_OK) == 0)
        {
            return 0;
        }
    }

    return -1;
}

/* -----------------------------------------------------------------------
 * query_networking_mode - Query the WSL networking mode via the interop
 * channel.
 *
 * Connects to the interop Unix socket, sends a QueryNetworkingMode(25)
 * message, and reads the response. The interop relay (wsl_interop.h)
 * acknowledges non-CreateProcessUtilityVm messages with ResultUint32(0),
 * which corresponds to NAT mode. The hvsock interop channel
 * (interop_server.h) responds with ResultUint8(0) for NAT.
 *
 * Returns 0 on success (mode stored in *out_mode), -1 on failure.
 * ----------------------------------------------------------------------- */
static int
query_networking_mode(uint32_t *out_mode)
{
    char sock_path[SOCK_PATH_MAX];
    if (find_interop_socket(sock_path, sizeof(sock_path)) < 0)
    {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    /* Set a receive timeout so we don't block forever */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Build and send the QueryNetworkingMode(25) message */
    struct MESSAGE_HEADER query;
    memset(&query, 0, sizeof(query));
    query.MessageType = LxInitMessageQueryNetworkingMode;
    query.MessageSize = sizeof(query);
    query.SequenceNumber = 1;

    size_t total = 0;
    while (total < sizeof(query))
    {
        ssize_t n = send(fd, (char *)&query + total,
                         sizeof(query) - total, 0);
        if (n <= 0)
        {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }

    /* Read the response (16 bytes expected) */
    struct RESULT_MESSAGE resp;
    memset(&resp, 0, sizeof(resp));

    size_t need = sizeof(resp);
    total = 0;
    while (total < need)
    {
        ssize_t n = recv(fd, (char *)&resp + total, need - total,
                         MSG_WAITALL);
        if (n <= 0)
        {
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }

    close(fd);

    /* Validate the response: accept both ResultUint32(78) and
     * ResultUint8(79), both of which are 16-byte messages with the
     * result in the same position. */
    if (resp.Header.MessageType != LxMessageResultUint32 &&
        resp.Header.MessageType != LxMessageResultUint8)
    {
        return -1;
    }

    *out_mode = resp.Result;
    return 0;
}

/* -----------------------------------------------------------------------
 * networking_mode_string - Map a numeric networking mode to a string.
 * ----------------------------------------------------------------------- */
static const char *
networking_mode_string(uint32_t mode)
{
    switch (mode)
    {
    case LX_INIT_NETWORKING_MODE_NAT:
        return "NAT";
    case LX_INIT_NETWORKING_MODE_MIRRORED:
        return "Mirrored";
    case LX_INIT_NETWORKING_MODE_BRIDGED:
        return "Bridged";
    default:
        return "none";
    }
}

/* -----------------------------------------------------------------------
 * format_guid - Format a raw hex string into GUID format.
 *
 * Accepts hex digits with or without dashes and formats the result as
 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. If fewer than 32 hex digits are
 * available, pads with zeros. If no hex digits are found, produces the
 * all-zeros GUID.
 * ----------------------------------------------------------------------- */
static void
format_guid(const char *input, char *output, size_t out_size)
{
    if (out_size < 37)
    {
        if (out_size > 0) output[0] = '\0';
        return;
    }

    /* Collect up to 32 hex digits from the input */
    char hex[33];
    int h = 0;
    for (const char *p = input; *p && h < 32; p++)
    {
        if (isxdigit((unsigned char)*p))
        {
            hex[h++] = (char)tolower((unsigned char)*p);
        }
    }

    /* Pad with zeros if necessary */
    while (h < 32)
    {
        hex[h++] = '0';
    }
    hex[32] = '\0';

    /* Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
    snprintf(output, out_size, "%.8s-%.4s-%.4s-%.4s-%.12s",
             hex, hex + 8, hex + 12, hex + 16, hex + 20);
}

/* -----------------------------------------------------------------------
 * get_vm_id - Read the VM GUID from /etc/hostid (FreeBSD) or
 * /etc/machine-id (Linux), formatted as a GUID string.
 *
 * If no host ID file is available, the all-zeros GUID is produced.
 * ----------------------------------------------------------------------- */
static void
get_vm_id(char *buf, size_t buf_size)
{
    static const char *const try_paths[] = {
        "/etc/hostid",                     /* FreeBSD */
        "/etc/machine-id",                 /* Linux */
        "/proc/sys/kernel/random/boot_id", /* Linux fallback */
        NULL,
    };

    char raw[256];
    raw[0] = '\0';

    for (int i = 0; try_paths[i] != NULL; i++)
    {
        FILE *f = fopen(try_paths[i], "r");
        if (!f) continue;

        size_t n = fread(raw, 1, sizeof(raw) - 1, f);
        fclose(f);
        if (n > 0)
        {
            raw[n] = '\0';
            /* Strip trailing whitespace */
            while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' ||
                             raw[n - 1] == ' '  || raw[n - 1] == '\t'))
            {
                raw[--n] = '\0';
            }
            if (n > 0) break;
        }
        raw[0] = '\0';
    }

    /* Format whatever we found (or didn't) as a GUID */
    format_guid(raw, buf, buf_size);
}

/* -----------------------------------------------------------------------
 * main - wslinfo entry point.
 * ----------------------------------------------------------------------- */
int
main(int argc, char *argv[])
{
    /*
     * Mode of operation. Only one query option may be specified.
     */
    enum
    {
        MODE_NONE,
        MODE_VM_ID,
        MODE_NETWORKING_MODE,
        MODE_VERSION,
        MODE_WSL_VERSION,
        MODE_NAME
    } mode = MODE_NONE;

    bool no_newline = false;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--vm-id") == 0)
        {
            mode = MODE_VM_ID;
        }
        else if (strcmp(argv[i], "--networking-mode") == 0)
        {
            mode = MODE_NETWORKING_MODE;
        }
        else if (strcmp(argv[i], "--version") == 0)
        {
            mode = MODE_VERSION;
        }
        else if (strcmp(argv[i], "--wsl-version") == 0)
        {
            mode = MODE_WSL_VERSION;
        }
        else if (strcmp(argv[i], "--name") == 0)
        {
            mode = MODE_NAME;
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            no_newline = true;
        }
        else
        {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (mode == MODE_NONE)
    {
        usage(argv[0]);
        return 1;
    }

    int rc = 0;
    const char *result = NULL;
    char buf[128];

    switch (mode)
    {
    case MODE_VM_ID:
        get_vm_id(buf, sizeof(buf));
        result = buf;
        break;

    case MODE_NETWORKING_MODE:
    {
        uint32_t net_mode = 0;
        if (query_networking_mode(&net_mode) < 0)
        {
            /* Graceful degradation: default to NAT */
            net_mode = LX_INIT_NETWORKING_MODE_NAT;
        }
        snprintf(buf, sizeof(buf), "%s", networking_mode_string(net_mode));
        result = buf;
        break;
    }

    case MODE_VERSION:
        result = WSL_PACKAGE_VERSION;
        break;

    case MODE_WSL_VERSION:
        result = "2"; /* This is WSL2 only */
        break;

    case MODE_NAME:
    {
        const char *name = getenv(WSL_DISTRO_NAME_ENV);
        if (!name || name[0] == '\0')
        {
            fprintf(stderr, "%s: no value found\n", argv[0]);
            return 1;
        }
        result = name;
        break;
    }

    default:
        fprintf(stderr, "%s: invalid mode\n", argv[0]);
        return 1;
    }

    /* Print the result */
    if (result)
    {
        fputs(result, stdout);
    }

    if (!no_newline)
    {
        fputc('\n', stdout);
    }

    return rc;
}
