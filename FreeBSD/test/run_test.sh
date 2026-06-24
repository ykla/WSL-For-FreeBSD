#!/bin/bash
# SPDX-License-Identifier: MIT
#
# run_test.sh - Orchestrate the Phase 0 test: start hvbridge + hvinit,
#               then run the mock host to validate all protocol fixes.
#
# Usage: ./run_test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  WSL-For-FreeBSD Phase 5 Test Runner"
echo "============================================"
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
./hvbridge_tcp &
BRIDGE_PID=$!
echo "[runner]   pid=$BRIDGE_PID"

# Give hvbridge time to start listening
sleep 0.3

# Step 2: Start wsl_mock_host (listens on port 50000) in background
# It will accept connections from hvinit, then connect to hvbridge.
echo "[runner] Starting wsl_mock_host (mock host)..."
./wsl_mock_host &
HOST_PID=$!
echo "[runner]   pid=$HOST_PID"

# Give mock host time to start listening on port 50000
sleep 0.3

# Step 3: Start hvinit_tcp (connects to port 50000)
echo "[runner] Starting hvinit_tcp (guest init)..."
./hvinit_tcp &
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
    echo "  RESULT: ALL PHASE 5 TESTS PASSED"
    echo "============================================"
else
    echo "============================================"
    echo "  RESULT: SOME TESTS FAILED"
    echo "============================================"
fi

exit $HOST_EXIT
