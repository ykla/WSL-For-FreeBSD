# SPDX-License-Identifier: MIT
#
# Makefile for WSL-For-FreeBSD Phase 0 local test harness.
#
# Usage:
#   make          # build all test binaries
#   make test     # build and run the full test
#   make clean    # remove binaries

CC      = cc
CFLAGS  = -Wall -Wextra -O2 -g -std=gnu11 -I..
LDFLAGS = -lutil

BINARIES = wsl_mock_host hvinit_tcp hvbridge_tcp

all: $(BINARIES)

wsl_mock_host: wsl_mock_host.c wsl_protocol.h ../config_parser.h ../wsl_conf_parser.h ../timezone_handler.h ../network_config.h ../drvfs_mount.h
	$(CC) $(CFLAGS) -o $@ wsl_mock_host.c $(LDFLAGS)

hvinit_tcp: hvinit_tcp.c wsl_protocol.h ../config_parser.h ../wsl_conf_parser.h ../timezone_handler.h ../network_config.h ../drvfs_mount.h ../gns_engine.h
	$(CC) $(CFLAGS) -o $@ hvinit_tcp.c

hvbridge_tcp: hvbridge_tcp.c wsl_protocol.h ../interop_server.h
	$(CC) $(CFLAGS) -o $@ hvbridge_tcp.c $(LDFLAGS)

test: all
	@./run_test.sh

clean:
	rm -f $(BINARIES) *.o

.PHONY: all test clean
