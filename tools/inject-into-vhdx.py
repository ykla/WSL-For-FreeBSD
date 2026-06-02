#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mount the FreeBSD VHDX, inject hvs_load into loader.conf, and optionally
copy hvinit/hvbridge binaries into the image."""

import subprocess
import sys
import os
from pathlib import Path

VHDX = Path(r"C:\Users\ykla\vhdx\FreeBSD15.1-ForWSL.vhdx")


def run_ps(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True,
    )


def find_freebsd_partition() -> str | None:
    """Find the drive letter of the mounted FreeBSD UFS partition."""
    r = run_ps(
        'Get-Volume | Where-Object { $_.FileSystemType -eq "Unknown" -or $_.FileSystem -eq "UFS" } '
        '| Select-Object -ExpandProperty DriveLetter'
    )
    letters = r.stdout.strip().splitlines()
    if letters and letters[0]:
        return letters[0].strip() + ":"
    # Fallback: list all volumes and look for FreeBSD
    r2 = run_ps("Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystemType -AutoSize")
    print("Volumes:\n" + r2.stdout)
    return None


def main() -> int:
    # 1. Mount VHDX
    print(f"[1] Mounting {VHDX} ...")
    r = run_ps(f"Mount-VHD -Path '{VHDX}'")
    if r.returncode != 0:
        # Maybe already mounted
        print(f"  Mount-VHD returned {r.returncode}")
        print(f"  stderr: {r.stderr.strip()}")
        # Try without -ReadOnly
        r = run_ps(f"Mount-VHD -Path '{VHDX}'")
        if r.returncode != 0:
            print("  Failed to mount. Is Hyper-V enabled?")
            return 1

    # 2. Find the FreeBSD partition
    print("[2] Looking for FreeBSD partition ...")
    drive = find_freebsd_partition()
    if not drive:
        print("  Could not auto-detect FreeBSD partition drive letter.")
        print("  Please enter the drive letter (e.g. 'E'): ", end="")
        drive = input().strip().upper() + ":"
        if not os.path.isdir(drive + "\\"):
            print(f"  {drive} is not a valid path.")
            return 2

    print(f"  FreeBSD partition found at {drive}")

    # 3. Inject hvs_load="YES" into /boot/loader.conf
    loader_conf = Path(drive) / "boot" / "loader.conf"
    print(f"[3] Patching {loader_conf} ...")

    if loader_conf.exists():
        content = loader_conf.read_text(encoding="utf-8", errors="replace")
    else:
        content = ""

    if 'hvs_load="YES"' in content:
        print("  hvs_load already present, skipping")
    else:
        content += '\nhvs_load="YES"\n'
        loader_conf.parent.mkdir(parents=True, exist_ok=True)
        loader_conf.write_text(content, encoding="utf-8", newline="\n")
        print("  added hvs_load=\"YES\"")

    # 4. Copy hvinit/hvbridge if available
    hvinit_src = Path("FreeBSD/build/hvinit")
    hvbridge_src = Path("FreeBSD/build/hvbridge")

    if hvinit_src.exists():
        sbin_dir = Path(drive) / "sbin"
        sbin_dir.mkdir(parents=True, exist_ok=True)
        dest = sbin_dir / "init"
        # Backup original init
        if dest.exists() and not (sbin_dir / "init.orig").exists():
            import shutil
            shutil.copy2(dest, sbin_dir / "init.orig")
            print(f"  backed up original init -> init.orig")
        import shutil
        shutil.copy2(hvinit_src, dest)
        print(f"  copied hvinit -> {dest}")
    else:
        print(f"[4] {hvinit_src} not found, skipping hvinit injection")
        print("    To compile: run 'make -C FreeBSD' on a FreeBSD host, then re-run this script.")

    if hvbridge_src.exists():
        libexec_dir = Path(drive) / "usr" / "libexec"
        libexec_dir.mkdir(parents=True, exist_ok=True)
        dest = libexec_dir / "hvbridge"
        import shutil
        shutil.copy2(hvbridge_src, dest)
        print(f"  copied hvbridge -> {dest}")
    else:
        print(f"[4] {hvbridge_src} not found, skipping hvbridge injection")

    # 5. Dismount
    print("[5] Dismounting VHDX ...")
    r = run_ps(f"Dismount-VHD -Path '{VHDX}'")
    if r.returncode != 0:
        print(f"  Dismount-VHD returned {r.returncode}")
        print(f"  stderr: {r.stderr.strip()}")
    else:
        print("  done")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
