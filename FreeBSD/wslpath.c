/* SPDX-License-Identifier: MIT */
/*
 * wslpath.c - Convert paths between Windows and POSIX formats.
 *
 * This is the FreeBSD C port of the Linux wslpath.cpp reference
 * (src/linux/init/wslpath.cpp). It converts paths between Windows
 * (e.g. C:\Users\foo) and POSIX (e.g. /mnt/c/Users/foo) formats.
 *
 * The WSL automount root is read from /etc/wsl.conf [automount] root=
 * (default: /mnt). UNC paths (\\server\share) map to
 * <mount_root>/wsl/server/share.
 *
 * Usage:
 *   wslpath [-w|-u|-m] [-a] PATH
 *     -u  Convert Windows path to POSIX path (default)
 *     -w  Convert POSIX path to Windows path
 *     -m  Convert to mixed format (Windows drive, forward slashes)
 *     -a  Return absolute path (default)
 *
 * Examples:
 *   wslpath -w /mnt/c/Users/foo   ->  C:\Users\foo
 *   wslpath -u 'C:\Users\foo'     ->  /mnt/c/Users/foo
 *   wslpath -m /mnt/c/Users/foo   ->  C:/Users/foo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <locale.h>

/* Path separators */
#define PATH_SEP '/'
#define PATH_SEP_NT '\\'
#define DRIVE_SEP ':'

/* Translation modes (matching wslpath.h) */
#define TRANSLATE_MODE_UNIX 'u'
#define TRANSLATE_MODE_WINDOWS 'w'
#define TRANSLATE_MODE_MIXED 'm'

/* Defaults */
#define DEFAULT_MOUNT_ROOT "/mnt"
#define WSL_CONF_PATH "/etc/wsl.conf"

/*
 * The subdirectory name under the automount root used for UNC paths.
 * \\server\share  ->  <mount_root>/wsl/server/share
 */
#define UNC_MOUNT_NAME "wsl"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* -----------------------------------------------------------------------
 * usage - Print usage information to stderr.
 * ----------------------------------------------------------------------- */
static void
usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-w|-u|-m] [-a] PATH\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Convert paths between Windows and POSIX formats.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u    Convert Windows path to POSIX path (default)\n");
    fprintf(stderr, "  -w    Convert POSIX path to Windows path\n");
    fprintf(stderr, "  -m    Convert to mixed format (Windows drive with forward slashes)\n");
    fprintf(stderr, "  -a    Return absolute path (default)\n");
    fprintf(stderr, "  --help  Show this help message\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s -w /mnt/c/Users/foo     ->  C:\\Users\\foo\n", prog);
    fprintf(stderr, "  %s -u 'C:\\Users\\foo'       ->  /mnt/c/Users/foo\n", prog);
    fprintf(stderr, "  %s -m /mnt/c/Users/foo     ->  C:/Users/foo\n", prog);
}

/* -----------------------------------------------------------------------
 * strip_trailing_slash - Remove trailing '/' characters from a path.
 * Keeps at least one character (the root "/" stays as "/").
 * ----------------------------------------------------------------------- */
static void
strip_trailing_slash(char *path)
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == PATH_SEP)
    {
        path[--len] = '\0';
    }
}

/* -----------------------------------------------------------------------
 * read_automount_root - Read the WSL automount root from /etc/wsl.conf.
 *
 * Parses [automount] root= value. If the file is missing or the key is
 * not set, the default "/mnt" is used. The result is stored in buf
 * (NUL-terminated, without a trailing slash).
 * ----------------------------------------------------------------------- */
static void
read_automount_root(char *buf, size_t buf_size)
{
    /* Start with the default */
    if (buf_size < 5)
    {
        if (buf_size > 0) buf[0] = '\0';
        return;
    }
    strncpy(buf, DEFAULT_MOUNT_ROOT, buf_size - 1);
    buf[buf_size - 1] = '\0';

    FILE *fp = fopen(WSL_CONF_PATH, "r");
    if (!fp)
    {
        return; /* File not found is OK — use default */
    }

    char line[512];
    int in_automount = 0;

    while (fgets(line, sizeof(line), fp))
    {
        /* Strip leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        /* Strip trailing whitespace/newline */
        char *end = p + strlen(p);
        while (end > p && (end[-1] == '\n' || end[-1] == '\r' ||
                           end[-1] == ' '  || end[-1] == '\t'))
        {
            *--end = '\0';
        }

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        /* Section header */
        if (*p == '[')
        {
            char *close = strchr(p, ']');
            if (close)
            {
                *close = '\0';
                in_automount = (strcasecmp(p + 1, "automount") == 0);
            }
            continue;
        }

        if (!in_automount) continue;

        /* Key = value */
        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = p;
        char *value = eq + 1;

        /* Strip whitespace from key */
        while (*key == ' ' || *key == '\t') key++;
        char *kend = key + strlen(key);
        while (kend > key && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = '\0';

        /* Strip whitespace from value */
        while (*value == ' ' || *value == '\t') value++;
        char *vend = value + strlen(value);
        while (vend > value && (vend[-1] == ' ' || vend[-1] == '\t' ||
                                vend[-1] == '\n' || vend[-1] == '\r'))
        {
            *--vend = '\0';
        }

        /* Remove surrounding double quotes from value */
        if (*value == '"')
        {
            char *cq = strchr(value + 1, '"');
            if (cq)
            {
                *cq = '\0';
                value++;
            }
        }

        if (strcasecmp(key, "root") == 0 && *value != '\0')
        {
            strncpy(buf, value, buf_size - 1);
            buf[buf_size - 1] = '\0';
        }
    }

    fclose(fp);

    /* Normalize: strip trailing slash */
    strip_trailing_slash(buf);
}

/* -----------------------------------------------------------------------
 * replace_sep - Replace all occurrences of 'from' with 'to' in a string.
 * ----------------------------------------------------------------------- */
static void
replace_sep(char *s, char from, char to)
{
    for (; *s; s++)
    {
        if (*s == from) *s = to;
    }
}

/* -----------------------------------------------------------------------
 * to_windows - Convert a POSIX path to Windows (or mixed) format.
 *
 * mount_root: The automount root without trailing slash (e.g. "/mnt").
 * input:      The POSIX path to convert.
 * output:     Buffer receiving the result.
 * out_size:   Size of output buffer.
 * mixed:      If true, use forward slashes (mixed mode); else backslashes.
 *
 * Returns 0 on success, -1 on error (errno set).
 * ----------------------------------------------------------------------- */
static int
to_windows(const char *mount_root, const char *input,
           char *output, size_t out_size, bool mixed)
{
    char win_sep = mixed ? PATH_SEP : PATH_SEP_NT;
    char abs_buf[PATH_MAX];
    const char *path = input;

    /* Make the path absolute if it is relative */
    if (path[0] != PATH_SEP)
    {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL)
        {
            return -1;
        }
        int n = snprintf(abs_buf, sizeof(abs_buf), "%s/%s", cwd, input);
        if (n < 0 || (size_t)n >= sizeof(abs_buf))
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        path = abs_buf;
    }

    size_t mlen = strlen(mount_root);

    /* Check if the path is under the automount root */
    if (mlen > 0 && strncmp(path, mount_root, mlen) == 0 &&
        path[mlen] == PATH_SEP)
    {
        const char *rest = path + mlen + 1; /* character after mount_root/ */

        /* Check for UNC: /mnt/wsl/server/share/... */
        size_t unc_len = strlen(UNC_MOUNT_NAME);
        if (strncmp(rest, UNC_MOUNT_NAME, unc_len) == 0 &&
            (rest[unc_len] == PATH_SEP || rest[unc_len] == '\0'))
        {
            const char *unc_rest = rest + unc_len;
            /* Skip the leading slash */
            if (*unc_rest == PATH_SEP) unc_rest++;

            /* Build: \\<unc_rest> (double backslash for UNC) */
            int n = snprintf(output, out_size, "%c%c%s",
                             PATH_SEP_NT, PATH_SEP_NT, unc_rest);
            if (n < 0 || (size_t)n >= out_size)
            {
                errno = ENAMETOOLONG;
                return -1;
            }
            /* Convert forward slashes in the UNC portion */
            replace_sep(output, PATH_SEP, win_sep);
            return 0;
        }

        /* Check for drive letter: /mnt/c/... or /mnt/c */
        if (isalpha((unsigned char)rest[0]) &&
            (rest[1] == PATH_SEP || rest[1] == '\0'))
        {
            char drive = (char)toupper((unsigned char)rest[0]);
            const char *remainder = (rest[1] == PATH_SEP) ? rest + 2 : "";

            if (*remainder == '\0')
            {
                /* Drive root: /mnt/c or /mnt/c/ -> C:\ */
                int n = snprintf(output, out_size, "%c%c%c",
                                 drive, DRIVE_SEP, win_sep);
                if (n < 0 || (size_t)n >= out_size)
                {
                    errno = ENAMETOOLONG;
                    return -1;
                }
            }
            else
            {
                /* C:\<remainder> */
                int n = snprintf(output, out_size, "%c%c%c%s",
                                 drive, DRIVE_SEP, win_sep, remainder);
                if (n < 0 || (size_t)n >= out_size)
                {
                    errno = ENAMETOOLONG;
                    return -1;
                }
                /* Convert remaining forward slashes */
                replace_sep(output + 3, PATH_SEP, win_sep);
            }
            return 0;
        }

        /*
         * Path is under the mount root but not a drive or UNC path.
         * Fall through to plain slash conversion below.
         */
    }

    /* Not under mount root (or unrecognised) — just convert slashes */
    int n = snprintf(output, out_size, "%s", path);
    if (n < 0 || (size_t)n >= out_size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    replace_sep(output, PATH_SEP, win_sep);
    return 0;
}

/* -----------------------------------------------------------------------
 * to_unix - Convert a Windows path to POSIX format.
 *
 * mount_root: The automount root without trailing slash (e.g. "/mnt").
 * input:      The Windows path to convert.
 * output:     Buffer receiving the result.
 * out_size:   Size of output buffer.
 *
 * Returns 0 on success, -1 on error (errno set).
 * ----------------------------------------------------------------------- */
static int
to_unix(const char *mount_root, const char *input,
        char *output, size_t out_size)
{
    /* Handle long path prefix: \\?\C:\... -> strip to C:\... */
    if (input[0] == PATH_SEP_NT && input[1] == PATH_SEP_NT &&
        input[2] == '?' && input[3] == PATH_SEP_NT)
    {
        input += 4;
    }

    /* Handle UNC paths: \\server\share\... -> <mount_root>/wsl/server/share/... */
    if (input[0] == PATH_SEP_NT && input[1] == PATH_SEP_NT)
    {
        const char *rest = input + 2;
        int n = snprintf(output, out_size, "%s/%s/%s",
                         mount_root, UNC_MOUNT_NAME, rest);
        if (n < 0 || (size_t)n >= out_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        replace_sep(output, PATH_SEP_NT, PATH_SEP);
        return 0;
    }

    /* Handle drive letter paths: C:\... or c:\... or C:/... */
    if (isalpha((unsigned char)input[0]) && input[1] == DRIVE_SEP)
    {
        char drive = (char)tolower((unsigned char)input[0]);
        const char *rest = input + 2;

        /* Skip the path separator after the colon (if any) */
        if (*rest == PATH_SEP_NT || *rest == PATH_SEP)
        {
            rest++;
        }

        int n;
        if (*rest == '\0')
        {
            /* /mnt/c */
            n = snprintf(output, out_size, "%s/%c", mount_root, drive);
        }
        else
        {
            /* /mnt/c/<rest> */
            n = snprintf(output, out_size, "%s/%c/%s",
                         mount_root, drive, rest);
        }
        if (n < 0 || (size_t)n >= out_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        replace_sep(output, PATH_SEP_NT, PATH_SEP);
        return 0;
    }

    /*
     * Not a recognised absolute Windows path.
     * Convert backslashes to forward slashes and return as-is.
     * This handles relative Windows paths (e.g. "foo\bar") gracefully.
     */
    int n = snprintf(output, out_size, "%s", input);
    if (n < 0 || (size_t)n >= out_size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    replace_sep(output, PATH_SEP_NT, PATH_SEP);
    return 0;
}

/* -----------------------------------------------------------------------
 * main - wslpath entry point.
 * ----------------------------------------------------------------------- */
int
main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");

    char mode = TRANSLATE_MODE_UNIX; /* default mode */
    bool absolute = true;            /* -a is the default */
    const char *path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0')
        {
            /* Parse single-character flags (may be combined: -aw) */
            for (int j = 1; argv[i][j]; j++)
            {
                switch (argv[i][j])
                {
                case 'u':
                    mode = TRANSLATE_MODE_UNIX;
                    break;
                case 'w':
                    mode = TRANSLATE_MODE_WINDOWS;
                    break;
                case 'm':
                    mode = TRANSLATE_MODE_MIXED;
                    break;
                case 'a':
                    absolute = true;
                    break;
                default:
                    fprintf(stderr, "%s: unknown option '-%c'\n",
                            argv[0], argv[i][j]);
                    usage(argv[0]);
                    return 1;
                }
            }
        }
        else
        {
            if (path == NULL)
            {
                path = argv[i];
            }
            else
            {
                fprintf(stderr, "%s: unexpected argument '%s'\n",
                        argv[0], argv[i]);
                usage(argv[0]);
                return 1;
            }
        }
    }

    if (path == NULL || path[0] == '\0')
    {
        fprintf(stderr, "%s: missing path argument\n", argv[0]);
        usage(argv[0]);
        return 1;
    }

    (void)absolute; /* -a is always on by default; no-op flag */

    /* Read the automount root from /etc/wsl.conf */
    char mount_root[PATH_MAX];
    read_automount_root(mount_root, sizeof(mount_root));

    /* Perform the translation */
    char output[PATH_MAX * 2];
    int rc;

    switch (mode)
    {
    case TRANSLATE_MODE_UNIX:
        rc = to_unix(mount_root, path, output, sizeof(output));
        break;
    case TRANSLATE_MODE_WINDOWS:
        rc = to_windows(mount_root, path, output, sizeof(output), false);
        break;
    case TRANSLATE_MODE_MIXED:
        rc = to_windows(mount_root, path, output, sizeof(output), true);
        break;
    default:
        fprintf(stderr, "%s: invalid mode\n", argv[0]);
        return 1;
    }

    if (rc < 0)
    {
        fprintf(stderr, "%s: %s: %s\n", argv[0], path, strerror(errno));
        return 1;
    }

    printf("%s\n", output);
    return 0;
}
