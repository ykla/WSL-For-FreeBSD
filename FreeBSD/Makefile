# SPDX-License-Identifier: MIT
#
# FreeBSD production Makefile for WSL-For-FreeBSD.
#
# Builds the production hvinit and hvbridge binaries for FreeBSD using
# the native lib9p (9P2000.L file server) and AF_HYPERV (hvsocket)
# transport. This Makefile is intended to be run on FreeBSD; it is not
# compiled by the Linux test harness (see test/Makefile for that).
#
# Build:  make
# Clean:  make clean
#
# Dependencies (FreeBSD base or pkg):
#   - lib9p   : /usr/src/contrib/lib9p (base) or pkg install lib9p
#   - libutil : forkpty() for hvbridge (base)
#   - libevent: used internally by lib9p transport (base)
#
# The -D__FreeBSD__=1 flag selects the lib9p production branch in
# plan9_server.h (AF_HYPERV + l9p_backend_fs_init) instead of the
# Linux TCP test stub.

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O2 -g -std=gnu11 -D__FreeBSD__=1
LDFLAGS ?= -lutil -levent -l9p

# Production binaries
BINS = hvinit hvbridge

# Source files
HVINIT_SRCS = hvinit.c
HVBRIDGE_SRCS = hvbridge.c

# Headers that trigger rebuild.
# Includes all headers transitively included by hvinit.c and hvbridge.c:
#   hvinit.c  -> gns_engine.h, dns_tunneling.h, config_parser.h,
#                wsl_conf_parser.h, timezone_handler.h, network_config.h,
#                drvfs_mount.h, binfmt_handler.h, plan9_server.h
#   hvbridge.c -> terminal_notify.h, interop_server.h, wsl_interop.h
#   wsl-interop.c is included by wsl_interop.h as a .c header.
HDRS = gns_engine.h plan9_server.h dns_tunneling.h port_tracker.h \
       drvfs_mount.h interop_server.h wsl_interop.h wsl_conf_parser.h \
       config_parser.h timezone_handler.h network_config.h binfmt_handler.h \
       terminal_notify.h wsl-interop.c

all: $(BINS)

hvinit: $(HVINIT_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(HVINIT_SRCS) $(LDFLAGS)

hvbridge: $(HVBRIDGE_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(HVBRIDGE_SRCS) $(LDFLAGS)

clean:
	rm -f $(BINS)

.PHONY: all clean
