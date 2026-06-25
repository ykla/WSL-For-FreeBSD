#!/usr/bin/env python3
"""run_test.py - Orchestrate the WSL-For-FreeBSD test: start hvbridge + hvinit,
                 then run the mock host to validate all protocol fixes.

This replaces the bash run_test.sh with a portable orchestrator that does not
depend on shell job control (which is unavailable in some sandbox/CI shells).

Usage:
    ./run_test.py            # run all tests, 60s timeout
    ./run_test.py -v         # verbose: print all output in real time
    ./run_test.py -t 120     # custom timeout (seconds)
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

PORT_BRIDGE = 60000
PORT_HOST = 50000
PORT_GNS = 50001


def kill_lingering():
    subprocess.run(
        ["pkill", "-9", "-f", "hvinit_tcp|hvbridge_tcp|wsl_mock_host"],
        capture_output=True,
    )
    time.sleep(0.5)


def make_env():
    env = os.environ.copy()
    env["WSL_TEST_ROOT"] = env.get("WSL_TEST_ROOT", "/tmp/wsl_test_etc")
    env["WSL_DNS_TUNNEL_IP"] = env.get("WSL_DNS_TUNNEL_IP", "127.0.0.1")
    env["WSL_DNS_TUNNEL_PORT"] = env.get("WSL_DNS_TUNNEL_PORT", "5353")
    os.makedirs(env["WSL_TEST_ROOT"], exist_ok=True)
    resolv = os.path.join(env["WSL_TEST_ROOT"], "resolv.conf")
    try:
        os.remove(resolv)
    except FileNotFoundError:
        pass
    return env


def ensure_built():
    for bin_name in ("hvbridge_tcp", "hvinit_tcp", "wsl_mock_host"):
        if not os.path.isfile(bin_name) or not os.access(bin_name, os.X_OK):
            print("[runner] Building test binaries...")
            r = subprocess.run(["make"], capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout)
                print(r.stderr, file=sys.stderr)
                sys.exit(1)
            break


def start_proc(args, env, verbose=False, log_path=None):
    """Start a subprocess. If verbose, inherit stdout/stderr. Otherwise write
    combined output to log_path (a temporary file) to avoid pipe buffer
    deadlocks (a 64KB pipe buffer can fill up and block the subprocess)."""
    if verbose:
        return subprocess.Popen(
            args, env=env, stdin=subprocess.DEVNULL,
        )
    # Use a temp file for stdout to avoid pipe buffer deadlock.
    # The file is unlinked on close (delete=True via NamedTemporaryFile).
    if log_path is None:
        log_path = tempfile.NamedTemporaryFile(
            prefix="wsl_test_", suffix=".log", delete=False
        ).name
    log_fp = open(log_path, "w+b")
    proc = subprocess.Popen(
        args, env=env,
        stdout=log_fp, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    proc._log_fp = log_fp  # stash for cleanup
    proc._log_path = log_path
    return proc


def read_log(proc):
    """Read the temp log file contents."""
    if not hasattr(proc, "_log_fp"):
        return ""
    proc._log_fp.flush()
    try:
        with open(proc._log_path, "r", errors="replace") as f:
            return f.read()
    except (IOError, OSError):
        return ""


def drain(proc, timeout=2):
    """Wait for proc to exit, then return its log output."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    out = read_log(proc)
    try:
        if hasattr(proc, "_log_fp"):
            proc._log_fp.close()
            os.unlink(proc._log_path)
    except (IOError, OSError):
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print all subprocess output in real time")
    ap.add_argument("-t", "--timeout", type=int, default=60,
                    help="Timeout in seconds for the mock host (default: 60)")
    args = ap.parse_args()

    print("============================================")
    print("  WSL-For-FreeBSD Phase 9 Test Runner")
    print("============================================")
    print(f"[runner] WSL_TEST_ROOT=/tmp/wsl_test_etc")
    print()

    kill_lingering()
    ensure_built()
    env = make_env()

    # Start bridge
    print("[runner] Starting hvbridge_tcp (guest bridge)...")
    bridge = start_proc(["./hvbridge_tcp"], env, args.verbose)
    print(f"[runner]   pid={bridge.pid}")
    time.sleep(0.5)

    # Start mock host
    print("[runner] Starting wsl_mock_host (mock host)...")
    host = start_proc(["./wsl_mock_host"], env, args.verbose)
    print(f"[runner]   pid={host.pid}")
    time.sleep(0.5)

    # Start hvinit
    print("[runner] Starting hvinit_tcp (guest init)...")
    init = start_proc(["./hvinit_tcp"], env, args.verbose)
    print(f"[runner]   pid={init.pid}")

    # Wait for mock host to finish
    print("[runner] Waiting for mock host to complete tests...")
    try:
        host.wait(timeout=args.timeout)
        host_exit = host.returncode
    except subprocess.TimeoutExpired:
        print(f"[runner] TIMEOUT after {args.timeout}s — killing mock host")
        host.kill()
        host.wait()
        host_exit = -1

    # Cleanup guest processes
    for p in (init, bridge):
        p.kill()

    host_text = read_log(host)
    init_out = drain(init)
    bridge_out = drain(bridge)

    # Close host log
    try:
        if hasattr(host, "_log_fp"):
            host._log_fp.close()
            os.unlink(host._log_path)
    except (IOError, OSError):
        pass

    if not args.verbose:
        print()
        print("=== HOST OUTPUT ===")
        print(host_text)
        print()
        print("=== BRIDGE OUTPUT (first 30 lines) ===")
        for line in bridge_out.splitlines()[:30]:
            print(line)
        print()
        print("=== INIT OUTPUT (first 30 lines) ===")
        for line in init_out.splitlines()[:30]:
            print(line)

    pass_count = len(re.findall(r"\[PASS\]", host_text))
    fail_count = len(re.findall(r"\[FAIL\]", host_text))

    print()
    print("============================================")
    print(f"  RESULT: {pass_count} PASS, {fail_count} FAIL")
    print(f"  host exit code: {host_exit}")
    print("============================================")

    # Exit 0 only if host exited cleanly AND no failures
    sys.exit(0 if host_exit == 0 and fail_count == 0 else 1)


if __name__ == "__main__":
    main()
