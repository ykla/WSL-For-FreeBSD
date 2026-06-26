/* SPDX-License-Identifier: MIT */
/*
 * logger.h - Unified logging interface for WSL-For-FreeBSD.
 *
 * Provides structured logging with timestamps, log levels, and
 * syslog integration. Replaces bare printf() calls with consistent
 * log formatting across all modules.
 *
 * Usage:
 *   #include "logger.h"
 *
 *   LOG_ERROR("init", "failed to open socket: %s", strerror(errno));
 *   LOG_WARN("bridge", "child pid=%d still running after SIGHUP", pid);
 *   LOG_INFO("plan9", "server started on port %u", port);
 *   LOG_DEBUG("dns", "relay: %u bytes UDP -> host", len);
 *
 * Log levels (increasing verbosity):
 *   LOG_ERROR   - Fatal errors, always printed
 *   LOG_WARN    - Warnings, recovery actions
 *   LOG_INFO    - Status messages, milestones
 *   LOG_DEBUG   - Debug details, disabled by default
 *
 * The default log level is LOG_INFO. Set LOG_LEVEL environment
 * variable to "debug" to enable debug output, or "warn" to suppress
 * info messages.
 *
 * Syslog integration:
 *   When compiled with -DUSE_SYSLOG, log messages are also sent to
 *   syslog. The facility is LOG_DAEMON. The ident is "wsl-init".
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef USE_SYSLOG
#include <syslog.h>
#endif

/* ---- Log level constants ---- */
#define LOG_LVL_ERROR  0
#define LOG_LVL_WARN   1
#define LOG_LVL_INFO   2
#define LOG_LVL_DEBUG  3

/* ---- Configuration ---- */
#ifndef LOG_DEFAULT_LEVEL
#define LOG_DEFAULT_LEVEL  LOG_LVL_INFO
#endif

#ifndef LOG_TIMESTAMP_ENABLED
#define LOG_TIMESTAMP_ENABLED  1
#endif

/* ---- Global log level (can be changed at runtime) ---- */
static int g_log_level = LOG_DEFAULT_LEVEL;

/* ---- Syslog initialization ---- */
static inline void log_init(const char *ident)
{
#ifdef USE_SYSLOG
    openlog(ident ? ident : "wsl-init", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
    (void)ident;

    /* Check LOG_LEVEL environment variable override */
    const char *env = getenv("LOG_LEVEL");
    if (env) {
        if (strcasecmp(env, "debug") == 0)
            g_log_level = LOG_LVL_DEBUG;
        else if (strcasecmp(env, "info") == 0)
            g_log_level = LOG_LVL_INFO;
        else if (strcasecmp(env, "warn") == 0 || strcasecmp(env, "warning") == 0)
            g_log_level = LOG_LVL_WARN;
        else if (strcasecmp(env, "error") == 0)
            g_log_level = LOG_LVL_ERROR;
    }
}

/* ---- Internal: get current timestamp string ---- */
static inline const char *log_timestamp(void)
{
    static char buf[32];
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec / 1000000);
    return buf;
}

/* ---- Level to string mapping ---- */
static inline const char *log_level_str(int level)
{
    switch (level) {
    case LOG_LVL_ERROR: return "ERROR";
    case LOG_LVL_WARN:  return "WARN";
    case LOG_LVL_INFO:  return "INFO";
    case LOG_LVL_DEBUG: return "DEBUG";
    default:            return "????";
    }
}

/* ---- Syslog level mapping ---- */
#ifdef USE_SYSLOG
static inline int log_to_syslog_level(int level)
{
    switch (level) {
    case LOG_LVL_ERROR: return LOG_ERR;
    case LOG_LVL_WARN:  return LOG_WARNING;
    case LOG_LVL_INFO:  return LOG_INFO;
    case LOG_LVL_DEBUG: return LOG_DEBUG;
    default:            return LOG_INFO;
    }
}
#endif

/* ---- Core logging function ---- */
static inline void log_write(int level, const char *module,
                             const char *fmt, ...)
{
    if (level > g_log_level) return;

    va_list ap;
    char msg[1024];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Console output with timestamp and module tag */
#if LOG_TIMESTAMP_ENABLED
    fprintf(stderr, "%s [%s] [%s] %s\n",
            log_timestamp(), log_level_str(level), module, msg);
#else
    fprintf(stderr, "[%s] [%s] %s\n",
            log_level_str(level), module, msg);
#endif

    /* Syslog output */
#ifdef USE_SYSLOG
    syslog(log_to_syslog_level(level), "[%s] %s", module, msg);
#endif
}

/* ---- Convenience macros ---- */
#define LOG_ERROR(mod, ...)   log_write(LOG_LVL_ERROR, mod, __VA_ARGS__)
#define LOG_WARN(mod, ...)    log_write(LOG_LVL_WARN,  mod, __VA_ARGS__)
#define LOG_INFO(mod, ...)    log_write(LOG_LVL_INFO,  mod, __VA_ARGS__)
#define LOG_DEBUG(mod, ...)   log_write(LOG_LVL_DEBUG, mod, __VA_ARGS__)

/* ---- Diagnostic counters (for wslinfo --diag) ---- */

/* Per-module message counters. These are atomically incremented
 * by each message handler and can be queried at runtime. */
typedef struct log_stats {
    unsigned long messages_rx;     /* total messages received */
    unsigned long messages_tx;     /* total messages sent */
    unsigned long errors;          /* error count */
    unsigned long plan9_conns;     /* Plan9 connections served */
    unsigned long dns_relays;      /* DNS packets relayed */
    unsigned long port_events;     /* port tracking events */
    unsigned long sessions;        /* terminal sessions created */
    time_t start_time;             /* process start time */
} log_stats_t;

/* Global statistics instance */
static log_stats_t g_log_stats;

/* Initialize statistics */
static inline void log_stats_init(void)
{
    memset(&g_log_stats, 0, sizeof(g_log_stats));
    g_log_stats.start_time = time(NULL);
}

/* Format uptime as a human-readable string */
static inline const char *log_stats_uptime(void)
{
    static char buf[64];
    time_t now = time(NULL);
    time_t uptime = now - g_log_stats.start_time;
    unsigned int days  = (unsigned int)(uptime / 86400);
    unsigned int hours = (unsigned int)((uptime % 86400) / 3600);
    unsigned int mins  = (unsigned int)((uptime % 3600) / 60);
    unsigned int secs  = (unsigned int)(uptime % 60);
    if (days > 0)
        snprintf(buf, sizeof(buf), "%ud %uh %um %us", days, hours, mins, secs);
    else if (hours > 0)
        snprintf(buf, sizeof(buf), "%uh %um %us", hours, mins, secs);
    else
        snprintf(buf, sizeof(buf), "%um %us", mins, secs);
    return buf;
}

/* Print diagnostic summary to stdout */
static inline void log_stats_print(void)
{
    printf("WSL-For-FreeBSD Diagnostic Report\n");
    printf("================================\n");
    printf("  Uptime:           %s\n", log_stats_uptime());
    printf("  Messages RX:      %lu\n", g_log_stats.messages_rx);
    printf("  Messages TX:      %lu\n", g_log_stats.messages_tx);
    printf("  Errors:           %lu\n", g_log_stats.errors);
    printf("  Plan9 connections: %lu\n", g_log_stats.plan9_conns);
    printf("  DNS relays:       %lu\n", g_log_stats.dns_relays);
    printf("  Port events:      %lu\n", g_log_stats.port_events);
    printf("  Sessions:         %lu\n", g_log_stats.sessions);
    printf("  Log level:        %s\n",
           g_log_level == LOG_LVL_DEBUG ? "DEBUG" :
           g_log_level == LOG_LVL_INFO  ? "INFO" :
           g_log_level == LOG_LVL_WARN  ? "WARN" : "ERROR");
}

#endif /* LOGGER_H */