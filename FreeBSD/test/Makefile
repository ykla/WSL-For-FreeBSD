# SPDX-License-Identifier: MIT
#
# Makefile for WSL-For-FreeBSD Phase 9 local test harness.
#
# Usage:
#   make          # build all test binaries
#   make test     # build and run the full test
#   make clean    # remove binaries

CC      = cc
CFLAGS  = -Wall -Wextra -O2 -g -std=gnu11 -I..
LDFLAGS = -lutil

BINARIES = wsl_mock_host hvinit_tcp hvbridge_tcp wsl-interop wslpath wslinfo

GNS_HEADERS = ../gns_engine.h ../port_tracker.h ../binfmt_handler.h ../interop_server.h

all: $(BINARIES)

wsl_mock_host: wsl_mock_host.c wsl_protocol.h ../config_parser.h ../wsl_conf_parser.h \
               ../timezone_handler.h ../network_config.h ../drvfs_mount.h $(GNS_HEADERS) ../logger.h
	$(CC) $(CFLAGS) -o $@ wsl_mock_host.c $(LDFLAGS)

hvinit_tcp: hvinit_tcp.c wsl_protocol.h ../config_parser.h ../wsl_conf_parser.h \
            ../timezone_handler.h ../network_config.h ../drvfs_mount.h $(GNS_HEADERS) ../logger.h
	$(CC) $(CFLAGS) -o $@ hvinit_tcp.c

hvbridge_tcp: hvbridge_tcp.c wsl_protocol.h ../interop_server.h ../wsl_interop.h ../logger.h
	$(CC) $(CFLAGS) -o $@ hvbridge_tcp.c $(LDFLAGS)

wsl-interop: ../wsl-interop.c ../wsl_interop.h ../logger.h
	$(CC) $(CFLAGS) -o $@ ../wsl-interop.c

wslpath: ../wslpath.c ../logger.h
	$(CC) $(CFLAGS) -o $@ ../wslpath.c

wslinfo: ../wslinfo.c ../logger.h
	$(CC) $(CFLAGS) -o $@ ../wslinfo.c

test: all
	@./run_test.sh

clean:
	rm -f $(BINARIES) *.o

.PHONY: all test clean
