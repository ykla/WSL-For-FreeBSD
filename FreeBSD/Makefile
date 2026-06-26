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
# Install: make install
# Clean:  make clean
#
# Installation targets:
#   make install         Install binaries and rc.d script
#   make install-bin     Install binaries only
#   make install-rc      Install rc.d script only
#   make install-tools   Install wslpath and wslinfo user tools
#
# Dependencies (FreeBSD base or pkg):
#   - lib9p   : /usr/src/contrib/lib9p (base) or pkg install lib9p
#   - libutil : forkpty() for hvbridge (base)
#   - libevent: used internally by lib9p transport (base)

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O2 -g -std=gnu11 -D__FreeBSD__=1
# lib9p headers: main header + backend/ + transport/ subdirs
CFLAGS  += -I/usr/local/include
LDFLAGS ?= -L/usr/local/lib -lutil -levent -l9p

# Installation paths
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec/wsl
RCDIR      ?= $(PREFIX)/etc/rc.d
MANDIR     ?= $(PREFIX)/share/man/man1

# Production binaries
BINS = hvinit hvbridge wslpath wslinfo

# Source files
HVINIT_SRCS = hvinit.c
HVBRIDGE_SRCS = hvbridge.c
WSLPATH_SRCS = wslpath.c
WSLINFO_SRCS = wslinfo.c

# Headers that trigger rebuild.
# Includes all headers transitively included by hvinit.c and hvbridge.c:
#   hvinit.c  -> gns_engine.h, dns_tunneling.h, config_parser.h,
#                wsl_conf_parser.h, timezone_handler.h, network_config.h,
#                drvfs_mount.h, binfmt_handler.h, plan9_server.h
#   hvbridge.c -> terminal_notify.h, interop_server.h, wsl_interop.h
#   wsl-interop.c is included by wsl_interop.h as a .c
# Headers that trigger rebuild.
HDRS = gns_engine.h plan9_server.h dns_tunneling.h port_tracker.h \
       drvfs_mount.h interop_server.h wsl_interop.h wsl_conf_parser.h \
       config_parser.h timezone_handler.h network_config.h binfmt_handler.h \
       terminal_notify.h wsl-interop.c logger.h

all: $(BINS)

hvinit: $(HVINIT_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(HVINIT_SRCS) $(LDFLAGS)

hvbridge: $(HVBRIDGE_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(HVBRIDGE_SRCS) $(LDFLAGS)

wslpath: $(WSLPATH_SRCS)
	$(CC) $(CFLAGS) -o $@ $(WSLPATH_SRCS)

wslinfo: $(WSLINFO_SRCS)
	$(CC) $(CFLAGS) -o $@ $(WSLINFO_SRCS)

clean:
	rm -f $(BINS)

# ---- Installation targets ----

# install-bin: Install the WSL init daemon binaries to libexec.
install-bin: hvinit hvbridge
	mkdir -p $(DESTDIR)$(LIBEXECDIR)
	install -m 755 hvinit $(DESTDIR)$(LIBEXECDIR)/hvinit
	install -m 755 hvbridge $(DESTDIR)$(LIBEXECDIR)/hvbridge

# install-tools: Install user-facing tools to bin.
install-tools: wslpath wslinfo
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 wslpath $(DESTDIR)$(BINDIR)/wslpath
	install -m 755 wslinfo $(DESTDIR)$(BINDIR)/wslinfo

# install-rc: Install the rc.d service script.
install-rc:
	mkdir -p $(DESTDIR)$(RCDIR)
	install -m 555 wsl_init $(DESTDIR)$(RCDIR)/wsl_init

# install: Install everything (binaries, tools, rc.d script).
install: install-bin install-tools install-rc
	@echo ""
	@echo "WSL-For-FreeBSD installed successfully."
	@echo ""
	@echo "To enable the WSL init daemon:"
	@echo "  sysrc wsl_init_enable=YES"
	@echo "  service wsl_init start"
	@echo ""

.PHONY: all clean install install-bin install-tools install-rc
