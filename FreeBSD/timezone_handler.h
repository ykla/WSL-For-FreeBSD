/*
 * SPDX-License-Identifier: MIT
 *
 * timezone_handler.h - Timezone application for WSL-For-FreeBSD.
 *
 * Implements the guest-side timezone update logic, mirroring the reference
 * WSL implementation in src/linux/init/timezone.cpp.
 *
 * When the host sends a timezone (either in the Initialize(5) message or
 * via a standalone TimezoneInformation(7) message), the guest applies it by:
 *   1. Symlinking /etc/localtime -> /usr/share/zoneinfo/<IANA_tz>
 *   2. Writing the IANA identifier to /etc/timezone
 *
 * The time.useWindowsTimezone setting from /etc/wsl.conf gates this behavior:
 *   - true (default): apply timezone updates from the host
 *   - false: do not modify /etc/localtime or /etc/timezone
 *
 * Reference: src/linux/init/timezone.cpp UpdateTimezone()
 *
 * Usage:
 *   #include "timezone_handler.h"
 *
 *   // From Initialize(5) message:
 *   timezone_apply(g_config.timezone, g_wsl_conf.time_use_windows_timezone);
 *
 *   // From TimezoneInformation(7) message:
 *   timezone_handle_message(msg_buf, msg_size, g_wsl_conf.time_use_windows_timezone);
 */
#ifndef TIMEZONE_HANDLER_H
#define TIMEZONE_HANDLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

/* ---- Constants matching reference implementation ---- */
#define TZ_LOCALTIME_FILE  "/etc/localtime"
#define TZ_SETTING_FILE    "/etc/timezone"
#define TZ_ZONEINFO_BASE   "/usr/share/zoneinfo/"

/* ---- A3: Timezone application ----
 *
 * Apply an IANA timezone string by creating the /etc/localtime symlink
 * and writing /etc/timezone.
 *
 * Parameters:
 *   timezone       - NUL-terminated IANA timezone (e.g. "Asia/Shanghai").
 *                    NULL or empty string is a no-op (logs warning).
 *   auto_update    - 1 if time.useWindowsTimezone is true (default),
 *                    0 to skip timezone updates entirely.
 *
 * Returns:
 *   0 on success (or skipped), -1 on error.
 *
 * Reference: timezone.cpp UpdateTimezone(string_view, Config) */
static inline int timezone_apply(const char *timezone, int auto_update)
{
    if (!auto_update) {
        printf("[tz] time.useWindowsTimezone=false, skipping timezone update\n");
        return 0;
    }

    if (!timezone || timezone[0] == '\0') {
        fprintf(stderr, "[tz] Windows to Linux timezone mapping was not possible\n");
        return 0;
    }

    /* Build zoneinfo target path: /usr/share/zoneinfo/<IANA> */
    char target[256];
    int n = snprintf(target, sizeof(target), "%s%s", TZ_ZONEINFO_BASE, timezone);
    if (n < 0 || (size_t)n >= sizeof(target)) {
        fprintf(stderr, "[tz] timezone path too long: %s\n", timezone);
        return -1;
    }

    /* Verify zoneinfo file exists */
    if (access(target, F_OK) < 0) {
        fprintf(stderr, "[tz] %s not found. Is the tzdata package installed?\n",
                target);
        return -1;
    }

    /* Remove existing /etc/localtime (ignore ENOENT) */
    if (unlink(TZ_LOCALTIME_FILE) < 0 && errno != ENOENT) {
        fprintf(stderr, "[tz] unlink %s: %s\n", TZ_LOCALTIME_FILE, strerror(errno));
        /* Continue anyway — symlink() may still succeed */
    }

    /* Create symlink: /etc/localtime -> /usr/share/zoneinfo/<IANA> */
    if (symlink(target, TZ_LOCALTIME_FILE) < 0) {
        fprintf(stderr, "[tz] symlink %s -> %s: %s\n",
                TZ_LOCALTIME_FILE, target, strerror(errno));
        return -1;
    }
    printf("[tz] symlinked %s -> %s\n", TZ_LOCALTIME_FILE, target);

    /* Write /etc/timezone with IANA identifier + newline */
    FILE *fp = fopen(TZ_SETTING_FILE, "w");
    if (!fp) {
        fprintf(stderr, "[tz] fopen %s: %s\n", TZ_SETTING_FILE, strerror(errno));
        return -1;
    }
    fprintf(fp, "%s\n", timezone);
    fclose(fp);
    printf("[tz] wrote %s to %s\n", timezone, TZ_SETTING_FILE);

    /* Set TZ environment variable for libc timezone functions */
    setenv("TZ", timezone, 1);

    return 0;
}

/* ---- A3: Handle TimezoneInformation(7) message ----
 *
 * Extracts the IANA timezone string from the message buffer and applies it.
 * The message structure is LX_INIT_TIMEZONE_INFORMATION with TimezoneOffset
 * pointing into Buffer[].
 *
 * Parameters:
 *   msg_buf     - Pointer to the full message (including header)
 *   msg_size    - Total message size in bytes
 *   auto_update - 1 if time.useWindowsTimezone is true, 0 to skip
 *
 * Returns:
 *   0 on success, -1 on error.
 *
 * Reference: timezone.cpp UpdateTimezone(span, Config) */
static inline int timezone_handle_message(void *msg_buf, size_t msg_size,
                                          int auto_update)
{
    if (!msg_buf || msg_size < 16) {  /* 12-byte header + 4-byte TimezoneOffset */
        fprintf(stderr, "[tz] TimezoneInformation: message too small (%zu)\n", msg_size);
        return -1;
    }

    /* The message layout is:
     *   [0..11]  MESSAGE_HEADER (12 bytes)
     *   [12..15] TimezoneOffset (4 bytes, offset into Buffer[])
     *   [16+]    Buffer[] (variable length)
     */
    unsigned int tz_offset;
    memcpy(&tz_offset, (char *)msg_buf + 12, sizeof(tz_offset));

    size_t header_fixed = 16;  /* sizeof(header) + sizeof(TimezoneOffset) */
    if (msg_size <= header_fixed) {
        fprintf(stderr, "[tz] TimezoneInformation: no buffer data\n");
        return -1;
    }

    size_t buf_size = msg_size - header_fixed;
    const char *buf_start = (const char *)msg_buf + header_fixed;

    /* Validate offset is within buffer bounds */
    if (tz_offset >= buf_size) {
        fprintf(stderr, "[tz] TimezoneInformation: offset %u out of bounds (buf_size=%zu)\n",
                tz_offset, buf_size);
        return -1;
    }

    const char *timezone = buf_start + tz_offset;
    printf("[tz] TimezoneInformation: timezone='%s'\n", timezone);

    return timezone_apply(timezone, auto_update);
}

#endif /* TIMEZONE_HANDLER_H */
