#!/bin/bash
# SPDX-License-Identifier: MIT
#
# run_test.sh - Orchestrate the Phase 9 test: start hvbridge + hvinit,
#               then run the mock host to validate all protocol fixes.
#
# Usage: ./run_test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Kill any lingering test processes from previous runs.
# Stale hvinit_tcp/hvbridge_tcp processes can hold resources and cause
# the test to hang on accept()/connect().
# Use binary name (not full path) since processes may be started as ./name.
pkill -9 -f 'hvinit_tcp' 2>/dev/null || true
pkill -9 -f 'hvbridge_tcp' 2>/dev/null || true
pkill -9 -f 'wsl_mock_host' 2>/dev/null || true
sleep 0.5

# Test-scoped etc directory for resolv.conf writes (avoids /etc permission issues)
export WSL_TEST_ROOT="${WSL_TEST_ROOT:-/tmp/wsl_test_etc}"
mkdir -p "$WSL_TEST_ROOT"
rm -f "$WSL_TEST_ROOT/resolv.conf"

# B (DNS Tunneling): tests bind 127.0.0.1:53 instead of 10.255.255.254:53
# because the latter requires special interface configuration. The guest's
# dns_tunneling.h honors WSL_DNS_TUNNEL_IP for exactly this reason.
export WSL_DNS_TUNNEL_IP="${WSL_DNS_TUNNEL_IP:-127.0.0.1}"

# B (DNS Tunneling): use port 5353 instead of 53 to avoid requiring root
# or CAP_NET_BIND_SERVICE on Linux. The guest's dns_tunneling.h honors
# WSL_DNS_TUNNEL_PORT for exactly this reason.
export WSL_DNS_TUNNEL_PORT="${WSL_DNS_TUNNEL_PORT:-5353}"

echo "============================================"
echo "  WSL-For-FreeBSD Phase 9 Test Runner"
echo "============================================"
echo ""
echo "[runner] WSL_TEST_ROOT=$WSL_TEST_ROOT"
echo ""

# Make sure binaries are built
if [ ! -x ./hvbridge_tcp ] || [ ! -x ./hvinit_tcp ] || [ ! -x ./wsl_mock_host ]; then
    echo "[runner] Building test binaries..."
    make
    echo ""
fi

# Cleanup function: kill any lingering processes
cleanup() {
    kill %2 2>/dev/null || true   # hvinit_tcp
    kill %1 2>/dev/null || true   # hvbridge_tcp
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Step 1: Start hvbridge_tcp (listens on port 60000)
echo "[runner] Starting hvbridge_tcp (guest bridge)..."
stdbuf -oL -eL ./hvbridge_tcp &
BRIDGE_PID=$!
echo "[runner]   pid=$BRIDGE_PID"

# Give hvbridge time to start listening
sleep 0.3

# Step 2: Start wsl_mock_host (listens on port 50000/50001) in background
# It will accept connections from hvinit, then connect to hvbridge.
echo "[runner] Starting wsl_mock_host (mock host)..."
stdbuf -oL -eL ./wsl_mock_host &
HOST_PID=$!
echo "[runner]   pid=$HOST_PID"

# Give mock host time to start listening on port 50000
sleep 0.3

# Step 3: Start hvinit_tcp (connects to port 50000)
echo "[runner] Starting hvinit_tcp (guest init)..."
stdbuf -oL -eL ./hvinit_tcp &
INIT_PID=$!
echo "[runner]   pid=$INIT_PID"

# Step 4: Wait for the mock host to finish (it runs the full test flow)
echo "[runner] Waiting for mock host to complete tests..."
wait $HOST_PID
HOST_EXIT=$?

echo ""
echo "[runner] Mock host exited with code $HOST_EXIT"

# Cleanup guest processes
echo "[runner] Cleaning up guest processes..."
kill $INIT_PID 2>/dev/null || true
kill $BRIDGE_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
if [ $HOST_EXIT -eq 0 ]; then
    echo "============================================"
    echo "  RESULT: ALL PHASE 9 TESTS PASSED"
    echo "============================================"
else
    echo "============================================"
    echo "  RESULT: SOME TESTS FAILED"
    echo "============================================"
fi

exit $HOST_EXIT
