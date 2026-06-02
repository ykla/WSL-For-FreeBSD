# Build FreeBSD-side hvinit / hvbridge natively on FreeBSD.
#
# Usage:
#   make            # build both binaries into ./build/
#   make hvinit     # build only the init responder
#   make hvbridge   # build only the per-instance bridge
#   make clean
#
# Requires: FreeBSD 13+ with the hvs(4) driver (kldload hvs) and a base
# system that provides <libutil.h> (forkpty). The hvinit/hvbridge programs
# are the LX_INIT / HV-socket protocol stand-ins described in FreeBSD/.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=c11
LDFLAGS ?=
LDLIBS  ?= -lutil

BUILD   := build

.PHONY: all clean hvinit hvbridge

all: hvinit hvbridge

hvinit: $(BUILD)/hvinit

hvbridge: $(BUILD)/hvbridge

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/hvinit: hvinit.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

$(BUILD)/hvbridge: hvbridge.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BUILD)
