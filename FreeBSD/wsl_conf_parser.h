/*
 * SPDX-License-Identifier: MIT
 *
 * wsl_conf_parser.h - /etc/wsl.conf configuration file parser.
 *
 * Parses the per-distribution WSL configuration file (/etc/wsl.conf) using
 * the same .gitconfig-style format as the reference WSL implementation
 * (src/shared/configfile/configfile.cpp).
 *
 * Supported sections and keys (case-insensitive matching):
 *
 *   [automount]
 *     enabled       = true|false     (default: true)
 *     root          = "/mnt"         (default: "/mnt")
 *     options       = "..."          (default: none)
 *     mountFsTab    = true|false     (default: true)
 *     ldconfig      = true|false     (default: true)
 *
 *   [filesystem]
 *     umask         = 0022           (default: 0022 octal)
 *
 *   [interop]
 *     enabled       = true|false     (default: true)
 *     appendWindowsPath = true|false (default: true)
 *
 *   [network]
 *     generateHosts    = true|false  (default: true)
 *     generateResolvConf = true|false (default: true)
 *     hostname      = "..."          (default: none)
 *
 *   [time]
 *     useWindowsTimezone = true|false (default: true)
 *
 *   [fileServer]
 *     enabled       = true|false     (default: true)
 *     logFile       = "..."          (default: none)
 *     logLevel      = N              (default: 2)
 *     logTruncate   = true|false     (default: true)
 *
 *   [gpu]
 *     enabled       = true|false     (default: true)
 *     appendLibPath = true|false     (default: true)
 *
 *   [user]
 *     default       = "..."          (default: none)
 *
 *   [boot]
 *     command       = "..."          (default: none)
 *     systemd       = true|false     (default: false, forced false for FreeBSD)
 *     initTimeout   = 10000          (default: 10000 ms)
 *     protectBinfmt = true|false     (default: true)
 *
 *   [general]
 *     guiApplications = true|false   (default: false)
 *
 * Format rules:
 *   - Sections: [sectionname], case-insensitive
 *   - Keys: key = value, case-insensitive key matching
 *   - Comments: # to end of line (ignored unless inside double quotes)
 *   - Quoted values: "..." preserves spaces and # characters
 *   - Booleans: "true"/"1" or "false"/"0" (case-insensitive)
 *   - Integers: decimal, 0x hex, or 0 octal (auto-detected)
 *   - Duplicate keys: first occurrence wins
 *   - Line continuation: backslash-newline
 *
 * Usage:
 *   #include "wsl_conf_parser.h"
 *
 *   struct wsl_conf conf;
 *   wsl_conf_init(&conf);              // set defaults
 *   wsl_conf_parse_file(&conf, "/etc/wsl.conf");  // parse (missing file = OK)
 *   wsl_conf_dump(&conf);              // debug output
 *   // use conf.automount_enabled, conf.interop_enabled, etc.
 *   wsl_conf_free(&conf);              // free heap-allocated strings
 */
#ifndef WSL_CONF_PARSER_H
#define WSL_CONF_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>  /* INT_MIN, INT_MAX */

/* ---- Parsed configuration storage ----
 * All string fields are heap-allocated (strdup) and must be freed via
 * wsl_conf_free(). NULL means "not set in config file" (use default). */
struct wsl_conf {
    /* [automount] */
    int automount_enabled;           /* bool, default 1 (true) */
    char *automount_root;            /* string, default "/mnt/" */
    char *automount_options;         /* optional string, default NULL */
    int automount_mountfstab;        /* bool, default 1 (true) */
    int automount_ldconfig;          /* bool, default 1 (true) */

    /* [filesystem] */
    int filesystem_umask;            /* int (octal), default 0022 */

    /* [interop] */
    int interop_enabled;             /* bool, default 1 (true) */
    int interop_append_windows_path; /* bool, default 1 (true) */

    /* [network] */
    int network_generate_hosts;      /* bool, default 1 (true) */
    int network_generate_resolvconf; /* bool, default 1 (true) */
    char *network_hostname;          /* optional string, default NULL */

    /* [time] */
    int time_use_windows_timezone;   /* bool, default 1 (true) */

    /* [fileServer] */
    int fileserver_enabled;          /* bool, default 1 (true) */
    char *fileserver_log_file;       /* optional string, default NULL */
    int fileserver_log_level;        /* int, default 2 */
    int fileserver_log_truncate;     /* bool, default 1 (true) */

    /* [gpu] */
    int gpu_enabled;                 /* bool, default 1 (true) */
    int gpu_append_lib_path;         /* bool, default 1 (true) */

    /* [user] */
    char *user_default;              /* optional string, default NULL */

    /* [boot] */
    char *boot_command;              /* optional string, default NULL */
    int boot_systemd;                /* bool, default 0 (false, forced for FreeBSD) */
    int boot_init_timeout;           /* int (ms), default 10000 */
    int boot_protect_binfmt;         /* bool, default 1 (true) */

    /* [general] */
    int general_gui_applications;    /* bool, default 0 (false) */

    /* Parse metadata */
    int parsed;                      /* 1 if file was successfully parsed */
    int key_count;                   /* Number of keys found */
    uint32_t seen_mask;              /* Bitmask of seen keys (for duplicate detection) */
};

/* Initialize a wsl_conf struct to default values.
 * All bools get WSL defaults, all strings get NULL. */
static inline void wsl_conf_init(struct wsl_conf *conf)
{
    if (!conf) return;
    memset(conf, 0, sizeof(*conf));

    /* [automount] defaults */
    conf->automount_enabled = 1;
    conf->automount_root = strdup("/mnt/");
    conf->automount_mountfstab = 1;
    conf->automount_ldconfig = 1;

    /* [filesystem] defaults */
    conf->filesystem_umask = 0022;

    /* [interop] defaults */
    conf->interop_enabled = 1;
    conf->interop_append_windows_path = 1;

    /* [network] defaults */
    conf->network_generate_hosts = 1;
    conf->network_generate_resolvconf = 1;

    /* [time] defaults */
    conf->time_use_windows_timezone = 1;

    /* [fileServer] defaults */
    conf->fileserver_enabled = 1;
    conf->fileserver_log_level = 2;
    conf->fileserver_log_truncate = 1;

    /* [gpu] defaults */
    conf->gpu_enabled = 1;
    conf->gpu_append_lib_path = 1;

    /* [boot] defaults */
    conf->boot_systemd = 0;  /* Always false for FreeBSD */
    conf->boot_init_timeout = 10000;
    conf->boot_protect_binfmt = 1;

    /* [general] defaults */
    conf->general_gui_applications = 0;
}

/* Free all heap-allocated strings in a wsl_conf struct. */
static inline void wsl_conf_free(struct wsl_conf *conf)
{
    if (!conf) return;
    free(conf->automount_root);
    free(conf->automount_options);
    free(conf->network_hostname);
    free(conf->fileserver_log_file);
    free(conf->user_default);
    free(conf->boot_command);
    memset(conf, 0, sizeof(*conf));
}

/* ---- Internal parsing helpers ---- */

/* Parse a boolean value string.
 * Returns 1 for true, 0 for false, -1 for invalid. */
static inline int wsl_conf_parse_bool(const char *value)
{
    if (!value) return -1;
    if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) return 1;
    if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) return 0;
    return -1;
}

/* Parse an integer value string with auto base detection.
 * Returns 0 on success, -1 on failure. Result stored in *out. */
static inline int wsl_conf_parse_int(const char *value, int *out)
{
    if (!value || !out) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(value, &end, 0);  /* base 0 = auto-detect */
    if (errno != 0 || !end || *end != '\0' || end == value) return -1;
    if (v < INT_MIN || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

/* Strip leading/trailing whitespace from a string in-place.
 * Returns a pointer into the same buffer. */
static inline char *wsl_conf_strip(char *s)
{
    if (!s) return NULL;
    /* Skip leading spaces/tabs */
    while (*s == ' ' || *s == '\t') s++;
    /* Strip trailing spaces/tabs */
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

/* Process escape sequences in a value string in-place.
 * Handles: \\ \" \b \n \t and line continuation (\ + newline). */
static inline void wsl_conf_unescape(char *s)
{
    if (!s) return;
    char *dst = s;
    char *src = s;
    while (*src) {
        if (*src == '\\' && src[1]) {
            switch (src[1]) {
                case '\\': *dst++ = '\\'; src += 2; break;
                case '"':  *dst++ = '"';  src += 2; break;
                case 'b':  *dst++ = '\b'; src += 2; break;
                case 'n':  *dst++ = '\n'; src += 2; break;
                case 't':  *dst++ = '\t'; src += 2; break;
                case '\n': src += 2; break;  /* line continuation: skip */
                default:   *dst++ = *src++; break;  /* unknown: keep backslash */
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

/* Extract the value part from a "key = value" line.
 * Handles quoted values (removes quotes, preserves internal # and spaces).
 * Returns a pointer to the processed value (may be in a different buffer).
 * Caller must free the returned string. */
static inline char *wsl_conf_extract_value(char *line)
{
    /* Find '=' separator */
    char *eq = strchr(line, '=');
    if (!eq) return NULL;

    /* Value starts after '=' */
    char *value = eq + 1;
    value = wsl_conf_strip(value);

    if (*value == '\0') {
        /* Empty value */
        return strdup("");
    }

    /* Check for quoted value */
    if (*value == '"') {
        /* Find closing quote (not escaped) */
        char *start = value + 1;
        char *end = start;
        while (*end) {
            if (*end == '\\' && end[1]) {
                end += 2;
            } else if (*end == '"') {
                break;
            } else {
                end++;
            }
        }
        if (*end == '"') {
            /* Extract content between quotes */
            size_t len = end - start;
            char *result = malloc(len + 1);
            if (!result) return NULL;
            memcpy(result, start, len);
            result[len] = '\0';
            wsl_conf_unescape(result);
            return result;
        }
        /* No closing quote — take rest of line */
        char *result = strdup(start);
        if (result) wsl_conf_unescape(result);
        return result;
    }

    /* Unquoted value: strip inline comments (# not in quotes) */
    char *hash = value;
    while (*hash) {
        if (*hash == '#') {
            *hash = '\0';
            break;
        }
        hash++;
    }

    /* Strip trailing whitespace again (after comment removal) */
    value = wsl_conf_strip(value);

    /* Unescape and return */
    char *result = strdup(value);
    if (result) wsl_conf_unescape(result);
    return result;
}

/* Apply a parsed key-value pair to the config struct.
 * section and key are matched case-insensitively.
 * Duplicate keys are skipped (first occurrence wins, matching reference behavior).
 * Returns 1 if the key was recognized (including skipped duplicates), 0 if unknown. */
static inline int wsl_conf_apply(struct wsl_conf *conf,
                                 const char *section, const char *key,
                                 const char *value)
{
    if (!conf || !section || !key || !value) return 0;

    /* Helper macros for matching and duplicate detection.
     * Each known key is assigned a bit position (0-23) in seen_mask.
     * First occurrence sets the bit and applies the value;
     * subsequent duplicates are skipped. */
    #define MATCH(s, k, bit) \
        (strcasecmp(section, s) == 0 && strcasecmp(key, k) == 0 && \
         ((conf->seen_mask & (1u << (bit))) ? 0 : (conf->seen_mask |= (1u << (bit)), 1)))

    /* [automount] */
    if (MATCH("automount", "enabled", 0)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->automount_enabled = b; conf->key_count++; }
        return 1;
    } else if (MATCH("automount", "root", 1)) {
        free(conf->automount_root);
        conf->automount_root = strdup(value);
        /* Normalize: ensure trailing '/' */
        if (conf->automount_root) {
            size_t len = strlen(conf->automount_root);
            if (len > 0 && conf->automount_root[len-1] != '/') {
                char *tmp = malloc(len + 2);
                if (tmp) {
                    memcpy(tmp, conf->automount_root, len);
                    tmp[len] = '/';
                    tmp[len+1] = '\0';
                    free(conf->automount_root);
                    conf->automount_root = tmp;
                }
            }
        }
        conf->key_count++;
        return 1;
    } else if (MATCH("automount", "options", 2)) {
        free(conf->automount_options);
        conf->automount_options = strdup(value);
        conf->key_count++;
        return 1;
    } else if (MATCH("automount", "mountfstab", 3)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->automount_mountfstab = b; conf->key_count++; }
        return 1;
    } else if (MATCH("automount", "ldconfig", 4)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->automount_ldconfig = b; conf->key_count++; }
        return 1;

    /* [filesystem] */
    } else if (MATCH("filesystem", "umask", 5)) {
        int v;
        if (wsl_conf_parse_int(value, &v) == 0) { conf->filesystem_umask = v; conf->key_count++; }
        return 1;

    /* [interop] */
    } else if (MATCH("interop", "enabled", 6)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->interop_enabled = b; conf->key_count++; }
        return 1;
    } else if (MATCH("interop", "appendwindowspath", 7)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->interop_append_windows_path = b; conf->key_count++; }
        return 1;

    /* [network] */
    } else if (MATCH("network", "generatehosts", 8)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->network_generate_hosts = b; conf->key_count++; }
        return 1;
    } else if (MATCH("network", "generateresolvconf", 9)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->network_generate_resolvconf = b; conf->key_count++; }
        return 1;
    } else if (MATCH("network", "hostname", 10)) {
        free(conf->network_hostname);
        conf->network_hostname = strdup(value);
        conf->key_count++;
        return 1;

    /* [time] */
    } else if (MATCH("time", "usewindowstimezone", 11)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->time_use_windows_timezone = b; conf->key_count++; }
        return 1;

    /* [fileServer] */
    } else if (MATCH("fileserver", "enabled", 12)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->fileserver_enabled = b; conf->key_count++; }
        return 1;
    } else if (MATCH("fileserver", "logfile", 13)) {
        free(conf->fileserver_log_file);
        conf->fileserver_log_file = strdup(value);
        conf->key_count++;
        return 1;
    } else if (MATCH("fileserver", "loglevel", 14)) {
        int v;
        if (wsl_conf_parse_int(value, &v) == 0) { conf->fileserver_log_level = v; conf->key_count++; }
        return 1;
    } else if (MATCH("fileserver", "logtruncate", 15)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->fileserver_log_truncate = b; conf->key_count++; }
        return 1;

    /* [gpu] */
    } else if (MATCH("gpu", "enabled", 16)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->gpu_enabled = b; conf->key_count++; }
        return 1;
    } else if (MATCH("gpu", "appendlibpath", 17)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->gpu_append_lib_path = b; conf->key_count++; }
        return 1;

    /* [user] */
    } else if (MATCH("user", "default", 18)) {
        free(conf->user_default);
        conf->user_default = strdup(value);
        conf->key_count++;
        return 1;

    /* [boot] */
    } else if (MATCH("boot", "command", 19)) {
        free(conf->boot_command);
        conf->boot_command = strdup(value);
        conf->key_count++;
        return 1;
    } else if (MATCH("boot", "systemd", 20)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) {
            /* FreeBSD: systemd is always disabled */
            conf->boot_systemd = 0;
            printf("[wsl.conf] boot.systemd=%s ignored (FreeBSD forces false)\n", value);
            conf->key_count++;
        }
        return 1;
    } else if (MATCH("boot", "inittimeout", 21)) {
        int v;
        if (wsl_conf_parse_int(value, &v) == 0) { conf->boot_init_timeout = v; conf->key_count++; }
        return 1;
    } else if (MATCH("boot", "protectbinfmt", 22)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->boot_protect_binfmt = b; conf->key_count++; }
        return 1;

    /* [general] */
    } else if (MATCH("general", "guiapplications", 23)) {
        int b = wsl_conf_parse_bool(value);
        if (b >= 0) { conf->general_gui_applications = b; conf->key_count++; }
        return 1;
    }

    #undef MATCH
    return 0;  /* Unknown key */
}

/* Parse wsl.conf from an already-opened FILE*.
 * Returns 0 on success, -1 on read error. */
static inline int wsl_conf_parse_stream(struct wsl_conf *conf, FILE *fp)
{
    if (!conf || !fp) return -1;

    char line[4096];
    char current_section[128] = "";
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *p = wsl_conf_strip(line);

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#') continue;

        /* Section header [sectionname] */
        if (*p == '[') {
            char *close = strchr(p, ']');
            if (!close) {
                fprintf(stderr, "[wsl.conf] line %d: missing ']' in section header\n", line_num);
                continue;
            }
            size_t len = close - p - 1;
            if (len >= sizeof(current_section)) len = sizeof(current_section) - 1;
            memcpy(current_section, p + 1, len);
            current_section[len] = '\0';
            /* Validate section name starts with alpha */
            if (!isalpha((unsigned char)current_section[0])) {
                fprintf(stderr, "[wsl.conf] line %d: invalid section name '%s'\n", line_num, current_section);
                current_section[0] = '\0';
            }
            continue;
        }

        /* Key = value */
        if (current_section[0] == '\0') {
            fprintf(stderr, "[wsl.conf] line %d: key outside of section\n", line_num);
            continue;
        }

        /* Extract key and value from "key = value" line.
         * CAUTION: Must not write '\0' before the '=' position, or
         * wsl_conf_extract_value's strchr() won't find '='.
         * Solution: find '=' first, then extract key and value as
         * separate strdup'd substrings without modifying the buffer
         * before '='. */
        char *eq = strchr(p, '=');
        if (!eq) {
            fprintf(stderr, "[wsl.conf] line %d: missing '=' in key-value pair\n", line_num);
            continue;
        }

        /* Key: substring from p to eq, stripped of whitespace.
         * Use strndup to avoid modifying the line buffer. */
        size_t key_len = eq - p;
        char *raw_key = malloc(key_len + 1);
        if (!raw_key) continue;
        memcpy(raw_key, p, key_len);
        raw_key[key_len] = '\0';
        char *key = strdup(wsl_conf_strip(raw_key));
        free(raw_key);
        if (!key) continue;

        /* Value: extract from the original line (after '=') */
        char *value = wsl_conf_extract_value(p);
        if (!value) {
            fprintf(stderr, "[wsl.conf] line %d: cannot extract value\n", line_num);
            free(key);
            continue;
        }

        /* Apply to config (key_count is incremented inside wsl_conf_apply) */
        int applied = wsl_conf_apply(conf, current_section, key, value);
        (void)applied;

        free(value);
        free(key);
    }

    conf->parsed = 1;
    return 0;
}

/* Parse wsl.conf from a file path.
 * If the file does not exist, returns 0 (uses defaults).
 * Returns 0 on success (including file-not-found), -1 on read error. */
static inline int wsl_conf_parse_file(struct wsl_conf *conf, const char *path)
{
    if (!conf || !path) return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        /* File not found is OK — use defaults */
        if (errno == ENOENT) {
            printf("[wsl.conf] %s not found, using defaults\n", path);
            conf->parsed = 1;
            return 0;
        }
        perror("[wsl.conf] fopen");
        return -1;
    }

    printf("[wsl.conf] parsing %s\n", path);
    int rc = wsl_conf_parse_stream(conf, fp);
    fclose(fp);
    return rc;
}

/* Parse wsl.conf from a string buffer (for testing).
 * Returns 0 on success, -1 on error. */
static inline int wsl_conf_parse_string(struct wsl_conf *conf, const char *content)
{
    if (!conf || !content) return -1;
    FILE *fp = fmemopen((void *)content, strlen(content), "r");
    if (!fp) {
        fprintf(stderr, "[wsl.conf] fmemopen failed: %s\n", strerror(errno));
        return -1;
    }
    int rc = wsl_conf_parse_stream(conf, fp);
    fclose(fp);
    return rc;
}

/* Print a debug dump of the parsed configuration to stdout. */
static inline void wsl_conf_dump(const struct wsl_conf *conf)
{
    if (!conf) {
        printf("[wsl.conf] (null)\n");
        return;
    }
    printf("[wsl.conf] parsed=%d, keys=%d\n", conf->parsed, conf->key_count);
    printf("[wsl.conf] [automount]\n");
    printf("[wsl.conf]   enabled       = %s\n", conf->automount_enabled ? "true" : "false");
    printf("[wsl.conf]   root          = '%s'\n", conf->automount_root ? conf->automount_root : "(null)");
    printf("[wsl.conf]   options       = '%s'\n", conf->automount_options ? conf->automount_options : "(null)");
    printf("[wsl.conf]   mountFsTab    = %s\n", conf->automount_mountfstab ? "true" : "false");
    printf("[wsl.conf]   ldconfig      = %s\n", conf->automount_ldconfig ? "true" : "false");
    printf("[wsl.conf] [filesystem]\n");
    printf("[wsl.conf]   umask         = 0%03o\n", (unsigned)conf->filesystem_umask & 0777);
    printf("[wsl.conf] [interop]\n");
    printf("[wsl.conf]   enabled       = %s\n", conf->interop_enabled ? "true" : "false");
    printf("[wsl.conf]   appendWinPath = %s\n", conf->interop_append_windows_path ? "true" : "false");
    printf("[wsl.conf] [network]\n");
    printf("[wsl.conf]   generateHosts = %s\n", conf->network_generate_hosts ? "true" : "false");
    printf("[wsl.conf]   generateResolv= %s\n", conf->network_generate_resolvconf ? "true" : "false");
    printf("[wsl.conf]   hostname      = '%s'\n", conf->network_hostname ? conf->network_hostname : "(null)");
    printf("[wsl.conf] [time]\n");
    printf("[wsl.conf]   useWinTz      = %s\n", conf->time_use_windows_timezone ? "true" : "false");
    printf("[wsl.conf] [fileServer]\n");
    printf("[wsl.conf]   enabled       = %s\n", conf->fileserver_enabled ? "true" : "false");
    printf("[wsl.conf]   logFile       = '%s'\n", conf->fileserver_log_file ? conf->fileserver_log_file : "(null)");
    printf("[wsl.conf]   logLevel      = %d\n", conf->fileserver_log_level);
    printf("[wsl.conf]   logTruncate   = %s\n", conf->fileserver_log_truncate ? "true" : "false");
    printf("[wsl.conf] [gpu]\n");
    printf("[wsl.conf]   enabled       = %s\n", conf->gpu_enabled ? "true" : "false");
    printf("[wsl.conf]   appendLibPath = %s\n", conf->gpu_append_lib_path ? "true" : "false");
    printf("[wsl.conf] [user]\n");
    printf("[wsl.conf]   default       = '%s'\n", conf->user_default ? conf->user_default : "(null)");
    printf("[wsl.conf] [boot]\n");
    printf("[wsl.conf]   command       = '%s'\n", conf->boot_command ? conf->boot_command : "(null)");
    printf("[wsl.conf]   systemd       = %s (forced false for FreeBSD)\n", conf->boot_systemd ? "true" : "false");
    printf("[wsl.conf]   initTimeout   = %d\n", conf->boot_init_timeout);
    printf("[wsl.conf]   protectBinfmt = %s\n", conf->boot_protect_binfmt ? "true" : "false");
    printf("[wsl.conf] [general]\n");
    printf("[wsl.conf]   guiApps       = %s\n", conf->general_gui_applications ? "true" : "false");
}

#endif /* WSL_CONF_PARSER_H */
