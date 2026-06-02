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

  1. Download a stock FreeBSD amd64 VHD from download.freebsd.org
     using multi-threaded (16 threads) range requests for speed.
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
    python tools/setup-freebsd-vhdx.py --threads 8

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
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults -- FreeBSD 15.1-RC2 amd64 VM image
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
DEFAULT_THREADS = 32

CHUNK = 1024 * 1024  # 1 MiB
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def _c(code: str, msg: str) -> str:
    return f"\x1b[{code}m{msg}\x1b[0m" if _supports_color() else msg


def info(msg: str) -> None:
    print(_c("36", "[info] ") + msg)


def warn(msg: str) -> None:
    print(_c("33", "[warn] ") + msg, file=sys.stderr)


def err(msg: str) -> None:
    print(_c("31", "[err ] ") + msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """Thread-safe progress bar for multi-threaded downloads."""

    def __init__(self, total: int, width: int = 40) -> None:
        self.total = total
        self.done = 0
        self.width = width
        self.lock = threading.Lock()
        self.t0 = time.monotonic()

    def update(self, nbytes: int) -> None:
        with self.lock:
            self.done += nbytes
            self._render()

    def _render(self) -> None:
        if self.total <= 0:
            return
        pct = self.done / self.total
        filled = int(self.width * pct)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.monotonic() - self.t0
        speed = self.done / elapsed / 1_048_576 if elapsed > 0 else 0
        sys.stdout.write(
            f"\r  [{bar}] {pct:6.1%}  "
            f"{self.done/1_048_576:8.1f}/{self.total/1_048_576:.1f} MiB  "
            f"{speed:6.1f} MiB/s"
        )
        sys.stdout.flush()

    def finish(self) -> None:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Multi-threaded download
# ---------------------------------------------------------------------------

def _get_content_length(url: str) -> int:
    """HEAD request to get Content-Length; -1 if unknown."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return int(resp.headers.get("Content-Length", -1))


def _download_range(
    url: str,
    start: int,
    end: int,
    dest_dir: Path,
    chunk_size: int,
    bar: ProgressBar,
    thread_id: int,
    errors: list[str],
) -> None:
    """Download byte range [start, end] into a per-thread temp file with resume."""
    tmp = dest_dir / f".part.{thread_id:03d}"
    headers = {
        "User-Agent": UA,
        "Range": f"bytes={start}-{end}",
    }

    # Resume: if part file exists, continue from where we left off
    pos = 0
    if tmp.exists():
        pos = tmp.stat().st_size
        if pos > 0 and (start + pos) <= end:
            # Adjust range to skip already-downloaded bytes
            headers["Range"] = f"bytes={start + pos}-{end}"
            bar.update(pos)  # count existing bytes toward progress
        else:
            # Part file is corrupt or too large, restart
            pos = 0
            tmp.unlink()

    req = urllib.request.Request(url, headers=headers)
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                mode = "ab" if pos > 0 else "wb"
                with open(tmp, mode) as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        bar.update(len(chunk))
            return  # success
        except Exception as e:
            if attempt < max_retries:
                time.sleep(attempt * 2)
                continue
            errors.append(f"thread {thread_id} (range {start}-{end}): {e}")


def _splice_parts(dest: Path, dest_dir: Path, num_threads: int) -> None:
    """Concatenate per-thread temp files in order into dest."""
    info("splicing downloaded parts ...")
    with open(dest, "wb") as out:
        for i in range(num_threads):
            tmp = dest_dir / f".part.{i:03d}"
            if not tmp.exists():
                raise FileNotFoundError(f"missing part {i}: {tmp}")
            with open(tmp, "rb") as inp:
                while True:
                    chunk = inp.read(4 * CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
            tmp.unlink()


def http_download_mt(
    url: str,
    dest: Path,
    *,
    num_threads: int = DEFAULT_THREADS,
    chunk_size: int = 4 * CHUNK,  # 4 MiB per read
    cache: Path | None = None,
) -> None:
    """Download ``url`` to ``dest`` using ``num_threads`` parallel range requests."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if cache is None:
        cache = dest.parent

    # Get total size
    total = _get_content_length(url)
    if total <= 0:
        # Fallback: single-threaded
        info("server does not report Content-Length, falling back to single-thread")
        http_download_st(url, dest)
        return

    # Check if server supports Range (try a small range request)
    try:
        test_req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Range": "bytes=0-0",
        })
        with urllib.request.urlopen(test_req, timeout=30) as resp:
            if resp.status != 206:
                info("server does not support Range, falling back to single-thread")
                http_download_st(url, dest)
                return
    except Exception:
        http_download_st(url, dest)
        return

    info(f"downloading with {num_threads} threads, total size {total/1_048_576:.1f} MiB")

    # Split into ranges
    part_size = total // num_threads
    ranges: list[tuple[int, int]] = []
    for i in range(num_threads):
        start = i * part_size
        end = (i + 1) * part_size - 1 if i < num_threads - 1 else total - 1
        ranges.append((start, end))

    bar = ProgressBar(total)
    errors: list[str] = []
    threads: list[threading.Thread] = []

    for idx, (start, end) in enumerate(ranges):
        t = threading.Thread(
            target=_download_range,
            args=(url, start, end, cache, chunk_size, bar, idx, errors),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    bar.finish()

    if errors:
        # Clean up partial files
        for i in range(num_threads):
            (cache / f".part.{i:03d}").unlink(missing_ok=True)
        for e in errors:
            err(e)
        raise RuntimeError(f"{len(errors)} thread(s) failed during download")

    # Splice parts into final file
    _splice_parts(dest, cache, num_threads)

    elapsed = time.monotonic() - bar.t0
    speed = total / elapsed / 1_048_576 if elapsed > 0 else 0
    info(f"  downloaded {total/1_048_576:.1f} MiB in {elapsed:.1f}s ({speed:.1f} MiB/s)")


def http_download_st(url: str, dest: Path, *, max_retries: int = 5) -> None:
    """Single-threaded fallback with resume and retries."""
    dest.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, max_retries + 1):
        headers = {"User-Agent": UA}
        mode = "wb"
        pos = 0
        if dest.exists():
            pos = dest.stat().st_size
            if pos > 0:
                headers["Range"] = f"bytes={pos}-"
                mode = "ab"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
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
                return
        except urllib.error.HTTPError as e:
            if e.code == 416 and pos > 0:
                return
            if e.code in (429, 503) and attempt < max_retries:
                wait = attempt * 10
                warn(f"HTTP {e.code} on attempt {attempt}/{max_retries}, "
                     f"retrying in {wait}s ...")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, OSError) as e:
            if attempt < max_retries:
                wait = attempt * 5
                warn(f"network error on attempt {attempt}/{max_retries}: {e}, "
                     f"retrying in {wait}s ...")
                time.sleep(wait)
                continue
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
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
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
        [qemu, "convert", "-f", "vpc", "-O", "vhdx", str(src), str(dst)],
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
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                   help="Number of parallel download threads")
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

        if compressed.exists() and compressed.stat().st_size > 0:
            info(f"cached file found: {compressed} ({compressed.stat().st_size/1_048_576:.1f} MiB)")
        else:
            info(f"download URL: {url}")
            http_download_mt(url, compressed, num_threads=args.threads, cache=cache)

        if not args.skip_verify:
            sums = fetch_checksum(args.base_url, args.checksum_name)
            if vhd_name not in sums:
                warn(f"no entry for {vhd_name} in {args.checksum_name}; "
                     "this is normal for older release layouts but means we "
                     "cannot verify. Pass --skip-verify to silence.")
            else:
                expected = sums[vhd_name]
                info("verifying SHA256 (this may take a moment) ...")
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
