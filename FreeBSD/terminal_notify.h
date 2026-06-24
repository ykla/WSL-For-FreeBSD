/*
 * SPDX-License-Identifier: MIT
 *
 * terminal_notify.h - Terminal appearance notification module.
 *
 * Consolidates Phase 7 (font size detection) and Phase 8 (OSC 11
 * background color sniffing) into a reusable header-only module.
 *
 * Phase 7: Font size detection
 *   Tracks ws_xpixel/ws_ypixel from TIOCGWINSZ to compute cell pixel
 *   dimensions (font size). When cell dimensions change without rows/cols
 *   changing, it indicates a pure font size change (not a window resize).
 *
 * Phase 8: OSC 11 background color sniffer
 *   Non-intrusive byte stream parser that detects OSC 11 (set/query
 *   background color) and OSC 111 (reset background color) sequences.
 *   Parses rgb:R/G/B and #RRGGBB color formats. All bytes are still
 *   forwarded unchanged — the sniffer is read-only (tap, not intercept).
 *
 * Usage:
 *   #include "terminal_notify.h"
 *
 *   struct font_size_tracker fst;
 *   struct bg_color_tracker bct;
 *
 *   // Initialize after forkpty + TIOCGWINSZ
 *   font_size_tracker_init(&fst, ws.ws_row, ws.ws_col,
 *                          ws.ws_xpixel, ws.ws_ypixel);
 *   bg_color_tracker_init(&bct);
 *
 *   // In poll loop, after TIOCGWINSZ:
 *   // Phase 6 checks fst.tracked_rows/cols for window size notification,
 *   // then Phase 7 checks font size:
 *   font_size_check_change(&fst, cur_ws.ws_row, cur_ws.ws_col,
 *                          cur_ws.ws_xpixel, cur_ws.ws_ypixel);
 *
 *   // In PTY->stdout relay path:
 *   for (ssize_t i = 0; i < n; i++)
 *       bg_color_feed_byte(&bct, (unsigned char)buf[i]);
 *
 *   // After host-initiated TIOCSWINSZ resize:
 *   font_size_sync_after_resize(&fst, rows, cols,
 *                               sync_ws.ws_xpixel, sync_ws.ws_ypixel);
 */
#ifndef TERMINAL_NOTIFY_H
#define TERMINAL_NOTIFY_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ===================================================================
 * Phase 7: Font size detection
 * =================================================================== */

struct font_size_tracker {
    unsigned short tracked_rows;
    unsigned short tracked_cols;
    unsigned short tracked_xpixel;
    unsigned short tracked_ypixel;
};

/* Initialize the tracker with the initial TIOCGWINSZ values. */
static inline void font_size_tracker_init(struct font_size_tracker *t,
                                          unsigned short rows,
                                          unsigned short cols,
                                          unsigned short xpixel,
                                          unsigned short ypixel)
{
    t->tracked_rows = rows;
    t->tracked_cols = cols;
    t->tracked_xpixel = xpixel;
    t->tracked_ypixel = ypixel;
}

/* Check for font size change from a new TIOCGWINSZ reading.
 * Computes cell pixel dimensions (pixels / cells) and logs when they
 * change, indicating a font size adjustment.
 *
 * This function also updates ALL tracked values (rows, cols, xpixel,
 * ypixel) to the new values. The caller should read fst.tracked_rows
 * and fst.tracked_cols BEFORE calling this function if Phase 6 window
 * size change detection is needed.
 *
 * Returns 1 if font size changed (and logs), 0 otherwise. */
static inline int font_size_check_change(struct font_size_tracker *t,
                                         unsigned short rows,
                                         unsigned short cols,
                                         unsigned short xpixel,
                                         unsigned short ypixel)
{
    int changed = 0;

    if (xpixel != t->tracked_xpixel || ypixel != t->tracked_ypixel) {
        /* Compute cell dimensions only when all values are non-zero
         * (terminal emulators that don't report pixel sizes leave them 0). */
        if (xpixel > 0 && cols > 0 && ypixel > 0 && rows > 0 &&
            t->tracked_xpixel > 0 && t->tracked_cols > 0 &&
            t->tracked_ypixel > 0 && t->tracked_rows > 0) {
            unsigned cell_w_old = t->tracked_xpixel / t->tracked_cols;
            unsigned cell_h_old = t->tracked_ypixel / t->tracked_rows;
            unsigned cell_w_new = xpixel / cols;
            unsigned cell_h_new = ypixel / rows;
            if (cell_w_old != cell_w_new || cell_h_old != cell_h_new) {
                printf("[bridge] font size change detected: "
                       "cell %ux%u -> %ux%u (window %ux%u -> %ux%u)\n",
                       cell_w_old, cell_h_old,
                       cell_w_new, cell_h_new,
                       t->tracked_xpixel, t->tracked_ypixel,
                       xpixel, ypixel);
                changed = 1;
            }
        }
    }

    /* Update all tracked values */
    t->tracked_rows = rows;
    t->tracked_cols = cols;
    t->tracked_xpixel = xpixel;
    t->tracked_ypixel = ypixel;

    return changed;
}

/* Sync tracked values after a host-initiated TIOCSWINSZ resize.
 * TIOCSWINSZ may zero ws_xpixel/ws_ypixel, so the caller should re-read
 * the actual kernel state via TIOCGWINSZ and pass the results here.
 * This prevents the font size tracker from falsely detecting a change
 * caused by the host resize. */
static inline void font_size_sync_after_resize(struct font_size_tracker *t,
                                               unsigned short rows,
                                               unsigned short cols,
                                               unsigned short xpixel,
                                               unsigned short ypixel)
{
    t->tracked_rows = rows;
    t->tracked_cols = cols;
    t->tracked_xpixel = xpixel;
    t->tracked_ypixel = ypixel;
}

/* ===================================================================
 * Phase 8: OSC 11 background color sniffer
 * ===================================================================
 *
 * OSC 11 format:  ESC ] 11 ; <color> BEL   (or ESC ] 11 ; <color> ESC \)
 * OSC 11 query:   ESC ] 11 ; ? BEL
 * OSC 111 reset:  ESC ] 1 1 1 BEL
 *
 * Color formats parsed:
 *   rgb:RR/GG/BB   (X11 spec, e.g. "rgb:1e/1e/2e")
 *   #RRGGBB        (hex, e.g. "#1e1e2e")
 *   #RGB           (short hex, e.g. "#123") */

#define TN_SNIFF_IDLE       0
#define TN_SNIFF_ESC        1
#define TN_SNIFF_OSC        2  /* collecting OSC string */
#define TN_SNIFF_OSC_ESC    3  /* ESC seen inside OSC (possible ST) */

struct bg_color_tracker {
    /* Sniffer state machine */
    int sniffer_state;
    char osc_buf[256];
    size_t osc_buf_len;
    /* Tracked background color */
    int color_initialized;
    unsigned tracked_r, tracked_g, tracked_b;
};

/* Initialize the background color tracker. */
static inline void bg_color_tracker_init(struct bg_color_tracker *t)
{
    t->sniffer_state = TN_SNIFF_IDLE;
    t->osc_buf_len = 0;
    t->color_initialized = 0;
    t->tracked_r = 0;
    t->tracked_g = 0;
    t->tracked_b = 0;
}

/* Reset the sniffer state machine to IDLE without losing the tracked color.
 * Call this when entering drain mode (host disconnect) to discard any
 * half-parsed OSC sequence, so stale state doesn't persist. The tracked
 * color is preserved so that if the session resumes, color change detection
 * remains continuous. */
static inline void bg_color_tracker_reset_sniffer(struct bg_color_tracker *t)
{
    t->sniffer_state = TN_SNIFF_IDLE;
    t->osc_buf_len = 0;
}

/* Parse a color string into RGB components (0-255 each).
 * Supported formats: rgb:RR/GG/BB, #RRGGBB, #RGB.
 * Returns 1 on success, 0 on unrecognized format. */
static inline int tn_parse_color(const char *str,
                                 unsigned *r, unsigned *g, unsigned *b)
{
    if (!str || !r || !g || !b) return 0;

    /* Format: rgb:RR/GG/BB (X11 color spec) */
    if (strncmp(str, "rgb:", 4) == 0) {
        const char *p = str + 4;
        char *end;
        unsigned long val;

        val = strtoul(p, &end, 16);
        if (end == p || *end != '/') return 0;
        *r = (unsigned)(val & 0xFF);
        p = end + 1;

        val = strtoul(p, &end, 16);
        if (end == p || *end != '/') return 0;
        *g = (unsigned)(val & 0xFF);
        p = end + 1;

        val = strtoul(p, &end, 16);
        if (end == p) return 0;
        *b = (unsigned)(val & 0xFF);
        return 1;
    }

    /* Format: #RRGGBB or #RGB */
    if (str[0] == '#') {
        size_t len = strlen(str + 1);
        if (len == 6) {
            char rs[3] = {str[1], str[2], 0};
            char gs[3] = {str[3], str[4], 0};
            char bs[3] = {str[5], str[6], 0};
            *r = (unsigned)strtoul(rs, NULL, 16);
            *g = (unsigned)strtoul(gs, NULL, 16);
            *b = (unsigned)strtoul(bs, NULL, 16);
            return 1;
        } else if (len == 3) {
            char rs[3] = {str[1], str[1], 0};
            char gs[3] = {str[2], str[2], 0};
            char bs[3] = {str[3], str[3], 0};
            *r = (unsigned)strtoul(rs, NULL, 16);
            *g = (unsigned)strtoul(gs, NULL, 16);
            *b = (unsigned)strtoul(bs, NULL, 16);
            return 1;
        }
    }
    return 0;
}

/* Process a complete OSC string to detect background color changes.
 * Called internally when the sniffer detects a complete OSC sequence. */
static inline void tn_process_osc(struct bg_color_tracker *t,
                                  const char *osc_str)
{
    size_t len = strlen(osc_str);

    /* OSC 11 with no parameter (ESC]11 BEL) — per xterm spec, this is
     * equivalent to OSC 11;? (query background color). */
    if (len == 2 && osc_str[0] == '1' && osc_str[1] == '1') {
        printf("[bridge] OSC 11 background color query detected (no parameter)\n");
        return;
    }

    /* OSC 11;<color> — set background color */
    if (len >= 3 && osc_str[0] == '1' && osc_str[1] == '1' && osc_str[2] == ';') {
        const char *param = osc_str + 3;

        /* OSC 11;? — query (not a color set, just log) */
        if (param[0] == '?' && param[1] == '\0') {
            printf("[bridge] OSC 11 background color query detected\n");
            return;
        }

        unsigned r, g, b;
        if (tn_parse_color(param, &r, &g, &b)) {
            if (!t->color_initialized ||
                r != t->tracked_r || g != t->tracked_g || b != t->tracked_b) {
                if (t->color_initialized) {
                    printf("[bridge] background color changed: "
                           "#%02x%02x%02x -> #%02x%02x%02x\n",
                           t->tracked_r, t->tracked_g, t->tracked_b, r, g, b);
                } else {
                    printf("[bridge] background color set: #%02x%02x%02x\n",
                           r, g, b);
                }
                t->tracked_r = r;
                t->tracked_g = g;
                t->tracked_b = b;
                t->color_initialized = 1;
            }
        }
        return;
    }

    /* OSC 111 — reset background color */
    if (len >= 3 && osc_str[0] == '1' && osc_str[1] == '1' && osc_str[2] == '1' &&
        (len == 3 || osc_str[3] == ';')) {
        printf("[bridge] background color reset (OSC 111)\n");
        t->color_initialized = 0;
        return;
    }
}

/* Feed one byte to the background color sniffer.
 * The sniffer is a non-intrusive tap — it parses the byte stream but
 * does NOT modify, buffer, or delay the passthrough. The caller should
 * still forward the byte unchanged via send_all/write_all.
 *
 * Returns 1 if a complete OSC sequence was just processed (color may
 * have been updated/logged), 0 otherwise. */
static inline int bg_color_feed_byte(struct bg_color_tracker *t,
                                     unsigned char b)
{
    switch (t->sniffer_state) {
    case TN_SNIFF_IDLE:
        if (b == 0x1b) t->sniffer_state = TN_SNIFF_ESC;
        return 0;

    case TN_SNIFF_ESC:
        if (b == ']') {
            t->sniffer_state = TN_SNIFF_OSC;
            t->osc_buf_len = 0;
        } else if (b == 0x1b) {
            /* stay in ESC state (multiple ESCs) */
        } else {
            t->sniffer_state = TN_SNIFF_IDLE;
        }
        return 0;

    case TN_SNIFF_OSC:
        if (b == 0x07) {
            /* BEL terminator — OSC complete */
            t->osc_buf[t->osc_buf_len] = '\0';
            t->sniffer_state = TN_SNIFF_IDLE;
            tn_process_osc(t, t->osc_buf);
            return 1;
        } else if (b == 0x1b) {
            /* Possible ST terminator (ESC \) */
            t->sniffer_state = TN_SNIFF_OSC_ESC;
            return 0;
        } else {
            if (t->osc_buf_len < sizeof(t->osc_buf) - 1) {
                t->osc_buf[t->osc_buf_len++] = (char)b;
            } else {
                /* Buffer overflow — abandon this OSC */
                t->sniffer_state = TN_SNIFF_IDLE;
                t->osc_buf_len = 0;
            }
            return 0;
        }

    case TN_SNIFF_OSC_ESC:
        if (b == '\\') {
            /* ST terminator (ESC \) — OSC complete */
            t->osc_buf[t->osc_buf_len] = '\0';
            t->sniffer_state = TN_SNIFF_IDLE;
            tn_process_osc(t, t->osc_buf);
            return 1;
        } else {
            /* Malformed OSC — discard and reprocess this byte */
            t->sniffer_state = TN_SNIFF_IDLE;
            t->osc_buf_len = 0;
            if (b == 0x1b) t->sniffer_state = TN_SNIFF_ESC;
            return 0;
        }
    }
    return 0;
}

#endif /* TERMINAL_NOTIFY_H */
