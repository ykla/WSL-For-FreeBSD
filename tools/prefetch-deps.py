#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-download FetchContent dependencies (GSL, nlohmann_json) with proxy support,
then place them where CMake expects them."""

import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PROXY = "http://127.0.0.1:7890"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

DEPS = [
    {
        "name": "gsl",
        "url": "https://github.com/microsoft/GSL/archive/refs/tags/v4.0.0.tar.gz",
        "sha256": "f0e32cb10654fea91ad56bde89170d78cfbf4363ee0b01d8f097de2ba49f6ce9",
        "dir": "GSL-4.0.0",
    },
    {
        "name": "nlohmannjson",
        "url": "https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz",
        "sha256": "d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d",
        "dir": "json",
    },
]

BUILD_DIR = Path(r"build\_deps\x64")


def setup_proxy():
    proxy_handler = urllib.request.ProxyHandler({
        "http": PROXY,
        "https": PROXY,
    })
    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)


def download(url: str, dest: Path) -> None:
    print(f"  downloading {url} -> {dest.name} ...")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)


def verify(path: Path, expected: str) -> bool:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                    break
            h.update(chunk)
    actual = h.hexdigest()
    if actual.lower() != expected.lower():
        print(f"  SHA256 mismatch: expected {expected}, got {actual}")
        return False
    print(f"  SHA256 ok: {actual[:16]}...")
    return True


def main() -> int:
    setup_proxy()
    tmp = Path(tempfile.mkdtemp(prefix="wslfb-deps-"))

    for dep in DEPS:
        print(f"\n[{dep['name']}]")
        src_dir = BUILD_DIR / f"{dep['name']}-src"
        stamp_dir = BUILD_DIR / f"{dep['name']}-stamp"

        if src_dir.exists() and (stamp_dir / "gsl-populate-done" if dep["name"] == "gsl" else stamp_dir / "nlohmannjson-populate-done").exists():
            print(f"  already present, skipping")
            continue

        # Download
        archive = tmp / dep["url"].split("/")[-1]
        if not archive.exists():
            download(dep["url"], archive)
        if not verify(archive, dep["sha256"]):
            archive.unlink()
            return 1

        # Extract
        src_dir.parent.mkdir(parents=True, exist_ok=True)
        print(f"  extracting to {src_dir} ...")
        if archive.suffix == ".xz":
            import lzma
            with lzma.open(archive, "rb") as f_in:
                # Write to .tar first
                tar_path = archive.with_suffix(".tar")
                with open(tar_path, "wb") as f_out:
                    shutil_copyfileobj(f_in, f_out)
                archive = tar_path

        import tarfile
        with tarfile.open(archive) as tf:
            tf.extractall(src_dir.parent)

        # Find the extracted directory
        if not src_dir.exists():
            # It might be under a subdirectory
            extracted = BUILD_DIR / dep["dir"]
            if not extracted.exists():
                # Look for it
                for item in src_dir.parent.iterdir():
                    if item.is_dir() and item.name.startswith(dep.get("dir", dep["name"][:3]).split("-")[0]):
                        extracted = item
                        break
            if extracted.exists() and extracted != src_dir:
                # Rename
                if src_dir.exists():
                    import shutil
                    shutil.rmtree(src_dir)
                extracted.rename(src_dir)

        print(f"  done: {src_dir}")

    print("\nAll dependencies ready. Re-run cmake configure.")
    return 0


def shutil_copyfileobj(fsrc, fdst, length=1024*1024):
    while True:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
