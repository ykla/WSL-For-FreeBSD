#!/bin/bash
# SPDX-License-Identifier: MIT
#
# run_test.sh - Orchestrate the Phase 9 test: start hvbridge + hvinit,
#               then run the mock host to validate all protocol fixes.
#
# Usage: ./run_test.sh [-v] [-t SECONDS]
#
# This script delegates to run_test.py which does not depend on shell job
# control (the original bash version used `wait $PID` which fails in
# non-interactive shells without job control).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Prefer python3, fall back to python
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "FATAL: python3 not found" >&2
    exit 1
fi

exec "$PY" "$SCRIPT_DIR/run_test.py" "$@"
