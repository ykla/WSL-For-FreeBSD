#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download an official FreeBSD VM image and stage it where the WSL-For-FreeBSD
Windows host expects to find it.

Why this script exists
----------------------
The project is a fork of WSL2 that runs FreeBSD inside a Hyper-V utility VM.
The root CMakeLists builds only the Windows host (wslservice, wsl.exe, ...);
the FreeBSD-side hvinit / hvbridge C programs in FreeBSD/ are intentionally
not built on Windows -- they have to be compiled natively on FreeBSD against
the hvs(4) driver and libutil.

This script follows the "use an existing image, bypass compilation" path:

  1. Download a stock FreeBSD 14.3 amd64 VHD from download.freebsd.org
     (or honour --vhd / --url if you already have one).
  2. Verify the SHA256 against the upstream CHECKSUM.SHA256 file.
  3. Convert / copy the VHD to VHDX format and place it at the path that
     src/windows/service/exe/WslCoreVm.cpp hard-codes:
         C:\\dev\\vhdx\\FreeBSD14.3-ForWSL.vhdx
     (override with --output / WSFB_VHDX_PATH).
  4. Print a short summary of next steps.

Image conversion tries, in order:
  - qemu-img convert -f vhd -O vhdx  (preferred; portable via QEMU for Windows)
  - PowerShell Convert-VHD           (requires Hyper-V feature)
  - raw byte copy with .vhd -> .vhdx rename (HCS may refuse; we warn)

Caveat: without the hvinit / hvbridge helpers from FreeBSD/ compiled and
injected into the image, the WSL host's LX_INIT handshake will time out
and you will get a FreeBSD kernel panic / hang at boot. Run FreeBSD/Makefile
on a FreeBSD host and copy /sbin/init, /usr/libexec/hvbridge into the
rootfs to get the console-mode handshake described in the project README.

Usage
-----
    python tools/setup-freebsd-vhdx.py
    python tools/setup-freebsd-vhdx.py --output D:\\vm\\FreeBSD.vhdx
    python tools/setup-freebsd-vhdx.py --vhd  C:\\already\\have.vhd
    python tools/setup-freebsd-vhdx.py --url  https://...custom.vhd.xz
    python tools/setup-freebsd-vhdx.py --skip-verify
    python tools/setup-freebsd-vhdx.py --prefer qemu|convert|copy

Environment variables (overridden by flags)
------------------------------------------
    WSFB_VHDX_PATH       default output path
    WSFB_CACHE_DIR       where the .vhd.xz and intermediate .vhd are kept
"""

from __future__ import annotations

import argparse
import hashlib
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults -- FreeBSD 14.3-RELEASE amd64 VM image
# ---------------------------------------------------------------------------

DEFAULT_RELEASE = "15.1-RC2"
DEFAULT_ARCH = "amd64"
DEFAULT_BASE_URL = (
    "https://download.freebsd.org/releases/VM-IMAGES"
    f"/{DEFAULT_RELEASE}/{DEFAULT_ARCH}/Latest"
)
DEFAULT_VHD_NAME = f"FreeBSD-{DEFAULT_RELEASE}-{DEFAULT_ARCH}-ufs.vhd.xz"
DEFAULT_CHECKSUM_NAME = "CHECKSUM.SHA256"
DEFAULT_OUTPUT = Path(r"C:\dev\vhdx\FreeBSD14.3-ForWSL.vhdx")
DEFAULT_CACHE = Path(os.environ.get("WSFB_CACHE_DIR", tempfile.gettempdir())) / "wslfb-freebsd-image"

CHUNK = 1024 * 1024  # 1 MiB


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def _c(code: str, msg: str) -> str:
    return f"\x1b[{code}m{msg}\x1b[0m" if _supports_color() else msg


def info(msg: str) -> None:
    print(_c("36", f"[info] ") + msg)


def warn(msg: str) -> None:
    print(_c("33", "[warn] ") + msg, file=sys.stderr)


def err(msg: str) -> None:
    print(_c("31", "[err ] ") + msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

def http_download(url: str, dest: Path, *, resume: bool = True) -> None:
    """Stream ``url`` to ``dest`` with optional range resume."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "wslfb-setup-freebsd-vhdx/1.0"}
    mode = "wb"
    pos = 0
    if resume and dest.exists():
        pos = dest.stat().st_size
        headers["Range"] = f"bytes={pos}-"
        mode = "ab"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            # If server ignored Range, start over
            if pos > 0 and resp.status != 206:
                pos = 0
                mode = "wb"
            total = resp.headers.get("Content-Length")
            total = int(total) + pos if total else None
            with open(dest, mode) as f:
                done = pos
                t0 = time.monotonic()
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = done * 100 // total
                        sys.stdout.write(
                            f"\r  ... {done/1_048_576:8.1f} MiB / {total/1_048_576:8.1f} MiB  {pct:3d}%"
                        )
                        sys.stdout.flush()
                if total:
                    sys.stdout.write("\n")
                dt = time.monotonic() - t0
                if dt > 0:
                    info(f"  downloaded {done/1_048_576:.1f} MiB in {dt:.1f}s "
                         f"({done/1_048_576/dt:.1f} MiB/s)")
    except urllib.error.HTTPError as e:
        if e.code == 416 and pos > 0:
            # Already fully downloaded
            return
        raise


def sha256_of(path: Path, *, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fetch_checksum(base_url: str, checksum_name: str) -> dict[str, str]:
    """Parse a FreeBSD CHECKSUM.SHA256 / FreeBSD-style manifest.

    The ``Latest/CHECKSUM.SHA256`` files use BSD-style lines:
        ``SHA256 (FreeBSD-15.1-RC2-amd64-ufs.vhd.xz) = <hex>``

    Older ``CHECKSUM.SHA256-FreeBSD-<rel>-<arch>`` files use a
    ``<hex>  <filename>`` GNU coreutils layout.  Both are handled here.
    """
    url = f"{base_url.rstrip('/')}/{checksum_name}"
    info(f"fetching checksum manifest: {url}")
    with urllib.request.urlopen(url, timeout=60) as resp:
        text = resp.read().decode("ascii", errors="replace")
    out: dict[str, str] = {}
    bsd_re = re.compile(r"^SHA256\s+\(([^)]+)\)\s*=\s*([0-9a-fA-F]{64})\s*$")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = bsd_re.match(line)
        if m:
            out[m.group(1)] = m.group(2)
            continue
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            out[parts[-1]] = parts[0]
    return out


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def find_tool(name: str) -> str | None:
    return shutil.which(name)


def convert_with_qemu(src: Path, dst: Path) -> bool:
    qemu = find_tool("qemu-img")
    if not qemu:
        return False
    info(f"converting via qemu-img: {qemu}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    rc = subprocess.run(
        [qemu, "convert", "-f", "vhd", "-O", "vhdx", str(src), str(dst)],
        check=False,
    )
    return rc.returncode == 0


def convert_with_powershell(src: Path, dst: Path) -> bool:
    if os.name != "nt":
        return False
    info("trying PowerShell Convert-VHD (Hyper-V)")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    ps = (
        f"Convert-VHD -Path '{src}' -DestinationPath '{dst}' -VHDType Dynamic"
    )
    rc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
        check=False,
        capture_output=True,
        text=True,
    )
    if rc.returncode != 0:
        warn("Convert-VHD failed; stderr was:\n" + (rc.stderr or "").strip())
    return rc.returncode == 0


def copy_as_vhdx(src: Path, dst: Path) -> bool:
    """Last-resort: byte-copy the .vhd to a .vhdx path. HCS may refuse it."""
    warn("falling back to raw byte copy with .vhdx extension; HCS may reject this")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return True


def convert(src: Path, dst: Path, prefer: list[str]) -> str:
    tried: list[str] = []
    for backend in prefer:
        tried.append(backend)
        if backend == "qemu" and convert_with_qemu(src, dst):
            return "qemu"
        if backend == "convert" and convert_with_powershell(src, dst):
            return "convert"
        if backend == "copy" and copy_as_vhdx(src, dst):
            return "copy"
    raise RuntimeError(f"all conversion backends failed: {tried}")


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------

def decompress_xz(src_xz: Path, dst: Path) -> None:
    info(f"decompressing {src_xz.name} -> {dst.name}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        info(f"  {dst} already exists, skipping decompression")
        return
    with lzma.open(src_xz, "rb") as fin, open(dst, "wb") as fout:
        copied = 0
        t0 = time.monotonic()
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            fout.write(chunk)
            copied += len(chunk)
        dt = time.monotonic() - t0
        info(f"  decompressed {copied/1_048_576:.1f} MiB in {dt:.1f}s")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Stage a FreeBSD VHDX for WSL-For-FreeBSD.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--release", default=DEFAULT_RELEASE,
                   help="FreeBSD release tag, e.g. 14.3-RELEASE")
    p.add_argument("--arch", default=DEFAULT_ARCH, help="amd64 or arm64")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL,
                   help="Upstream VM-IMAGES base URL")
    p.add_argument("--vhd-name", default=DEFAULT_VHD_NAME,
                   help="Basename of the compressed VHD on the mirror")
    p.add_argument("--checksum-name", default=DEFAULT_CHECKSUM_NAME,
                   help="Basename of the CHECKSUM.SHA256 file")
    p.add_argument("--output", type=Path,
                   default=Path(os.environ.get("WSFB_VHDX_PATH", str(DEFAULT_OUTPUT))),
                   help="Destination VHDX path")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE,
                   help="Where to keep the downloaded .vhd.xz and intermediate .vhd")
    p.add_argument("--vhd", type=Path, default=None,
                   help="Skip download; use a local .vhd (or .vhd.xz) file")
    p.add_argument("--url", default=None,
                   help="Override the full download URL (implies --vhd-name derived)")
    p.add_argument("--skip-verify", action="store_true",
                   help="Skip SHA256 verification")
    p.add_argument("--prefer", default="qemu,convert,copy",
                   help="Comma-separated conversion backends, in order of preference")
    p.add_argument("--keep-cache", action="store_true",
                   help="Do not delete the cached .vhd after staging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cache = args.cache_dir.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    prefer = [b.strip() for b in args.prefer.split(",") if b.strip()]

    # Resolve source file
    if args.vhd:
        src = args.vhd.resolve()
        if not src.exists():
            err(f"--vhd file not found: {src}")
            return 2
        info(f"using local source: {src}")
    else:
        if args.url:
            url = args.url
            vhd_name = Path(url.split("?", 1)[0]).name
        else:
            vhd_name = args.vhd_name
            url = f"{args.base_url.rstrip('/')}/{vhd_name}"
        compressed = cache / vhd_name
        info(f"download URL: {url}")
        http_download(url, compressed)

        if not args.skip_verify:
            sums = fetch_checksum(args.base_url, args.checksum_name)
            if vhd_name not in sums:
                warn(f"no entry for {vhd_name} in {args.checksum_name}; "
                     "this is normal for older release layouts but means we "
                     "cannot verify. Pass --skip-verify to silence.")
            else:
                expected = sums[vhd_name]
                actual = sha256_of(compressed)
                if actual.lower() != expected.lower():
                    err(f"sha256 mismatch for {compressed}\n"
                        f"  expected: {expected}\n"
                        f"  actual:   {actual}")
                    return 3
                info(f"sha256 ok: {actual}")
        else:
            warn("--skip-verify set, not checking checksum")

        # Decompress to .vhd
        assert vhd_name.endswith(".xz"), "expected .xz download"
        vhd_path = cache / vhd_name[:-3]
        decompress_xz(compressed, vhd_path)
        src = vhd_path

    # Convert / copy to VHDX
    dst = args.output.resolve()
    if dst.exists():
        warn(f"destination {dst} already exists; it will be overwritten")
        try:
            dst.unlink()
        except OSError as e:
            err(f"cannot remove existing {dst}: {e}")
            return 4
    backend = convert(src, dst, prefer)
    info(f"staged VHDX at {dst} via backend={backend}")

    if not args.keep_cache and src.exists() and src.parent == cache:
        try:
            src.unlink()
        except OSError:
            pass

    # Final summary
    size_gib = dst.stat().st_size / 1024 ** 3
    info(f"done -- FreeBSD VHDX is {size_gib:.2f} GiB at {dst}")
    info("next steps:")
    info("  1. (optional, on a FreeBSD host) make -C FreeBSD && inject the")
    info("     resulting build/hvinit, build/hvbridge into the image's /sbin")
    info("     and /usr/libexec respectively, and add 'hvs_load=\"YES\"' to")
    info("     /boot/loader.conf inside the image.")
    info("  2. Build the Windows host from the repo root with CMake + VS, then")
    info("     run the resulting wslservice with this VHDX attached.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("interrupted")
        sys.exit(130)
