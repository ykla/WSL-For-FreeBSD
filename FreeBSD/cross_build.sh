#!/bin/bash
# SPDX-License-Identifier: MIT
#
# cross_build.sh - Cross-compile WSL-For-FreeBSD from Linux to FreeBSD 15.1
#
# Uses clang/LLVM (native cross-compiler) + FreeBSD 15.1 base.txz sysroot.
# Downloads FreeBSD src.txz to get lib9p (contrib/lib9p), then cross-compiles
# lib9p and the 4 WSL binaries: hvinit, hvbridge, wslpath, wslinfo.
#
# FreeBSD 15.1-RELEASE: released 2026-06-16, EOL 2027-03.
# Base.txz URL verified: https://download.freebsd.org/releases/amd64/amd64/15.1-RELEASE/base.txz
# Src.txz URL verified:  https://download.freebsd.org/releases/amd64/amd64/15.1-RELEASE/src.txz
# lib9p source: contrib/lib9p (BSD-2-clause), built via lib/lib9p/Makefile
# lib9p deps: libsbuf (base), optionally casper/cap_pwd/cap_grp (disabled via -DWITH_CASPER=0)
# lib9p does NOT depend on libevent (verified from lib/lib9p/Makefile)
#
# Output: build/output/wsl-freebsd-15.1-amd64.tar.gz  (deployment tarball)
#
# Requirements on Linux host:
#   - clang (version 11+, tested with 21.1.8)
#   - lld (LLVM linker, tested with lld-22)
#   - wget or curl
#   - git
#   - tar, gzip
#
# Usage:
#   ./cross_build.sh            # Full build: download sysroot, build lib9p, build WSL
#   ./cross_build.sh sysroot    # Only download+extract FreeBSD sysroot
#   ./cross_build.sh lib9p      # Only cross-compile lib9p
#   ./cross_build.sh wsl        # Only cross-compile WSL binaries
#   ./cross_build.sh package    # Only create deployment tarball
#   ./cross_build.sh wslfile    # Create .wsl file (tar.gz rootfs + WSL config)
#   ./cross_build.sh clean      # Clean build artifacts

set -euo pipefail

# ===== Configuration =====
FREEBSD_REL="15.1-RELEASE"
FREEBSD_ARCH="amd64"
TARGET_TRIPLE="x86_64-unknown-freebsd15.1"

BASE_TXZ_URL="https://download.freebsd.org/releases/${FREEBSD_ARCH}/${FREEBSD_ARCH}/${FREEBSD_REL}/base.txz"
SRC_TXZ_URL="https://download.freebsd.org/releases/${FREEBSD_ARCH}/${FREEBSD_ARCH}/${FREEBSD_REL}/src.txz"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
SYSROOT="${BUILD_DIR}/sysroot"
LIB9P_SRC="${BUILD_DIR}/freebsd-src"
OUTPUT_DIR="${BUILD_DIR}/output"

# clang
export CC="${CC:-clang}"
CROSS_FLAGS="--target=${TARGET_TRIPLE} --sysroot=${SYSROOT} -fuse-ld=lld"
CFLAGS_BASE="-Wall -Wextra -O2 -g -std=gnu11 -D__FreeBSD__=1"

PKG_NAME="wsl-freebsd-${FREEBSD_REL}-${FREEBSD_ARCH}"

# ===== Utility functions =====
log()  { echo -e "\033[1;32m[BUILD]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*"; exit 1; }

check_tools() {
    log "Checking build tools..."
    command -v clang >/dev/null || err "clang not found. Install: apt install clang"
    # Check lld availability
    if ! clang -fuse-ld=lld -print-search-dirs >/dev/null 2>&1; then
        warn "lld not found via clang -fuse-ld=lld, trying ld.lld..."
        if command -v ld.lld >/dev/null 2>&1; then
            log "ld.lld found"
        elif command -v ld.lld-22 >/dev/null 2>&1; then
            log "ld.lld-22 found, creating symlink..."
            sudo ln -sf /usr/bin/ld.lld-22 /usr/local/bin/ld.lld 2>/dev/null || true
        else
            warn "lld not found, will try without -fuse-ld=lld"
        fi
    fi
    command -v wget >/dev/null || command -v curl >/dev/null || err "wget or curl required"
    command -v git >/dev/null || err "git required"
    log "clang: $(clang --version | head -1)"
}

download() {
    local url="$1" dest="$2"
    if [ -f "$dest" ]; then
        log "Already downloaded: $dest"
        return 0
    fi
    log "Downloading: $url"
    if command -v wget >/dev/null; then
        wget -q --show-progress -O "$dest" "$url"
    else
        curl -L -o "$dest" "$url"
    fi
}

# ===== Step 1: Download FreeBSD sysroot =====
step_sysroot() {
    mkdir -p "$BUILD_DIR"

    local txz="${BUILD_DIR}/base.txz"
    download "$BASE_TXZ_URL" "$txz"

    if [ -d "$SYSROOT" ] && [ -f "${SYSROOT}/usr/lib/libc.so" ]; then
        log "Sysroot already extracted at $SYSROOT"
        return 0
    fi

    log "Extracting sysroot to $SYSROOT..."
    rm -rf "$SYSROOT"
    mkdir -p "$SYSROOT"
    tar -xf "$txz" -C "$SYSROOT"

    # Verify sysroot is usable
    for f in usr/lib/libc.so usr/lib/libutil.so usr/lib/libsbuf.so usr/lib/crt1.o; do
        if [ ! -f "${SYSROOT}/$f" ]; then
            warn "Missing from sysroot: $f"
        fi
    done

    log "Sysroot ready: $SYSROOT"
}

# ===== Step 2: Extract lib9p source from FreeBSD src.txz =====
step_lib9p_source() {
    if [ -d "$LIB9P_SRC" ] && [ -f "${LIB9P_SRC}/contrib/lib9p/lib9p.h" ]; then
        log "lib9p source already extracted at $LIB9P_SRC"
        return 0
    fi

    # Download src.txz if not already present
    local src_txz="${BUILD_DIR}/src.txz"
    download "$SRC_TXZ_URL" "$src_txz"

    log "Extracting lib9p source from src.txz..."
    rm -rf "$LIB9P_SRC"
    mkdir -p "$LIB9P_SRC"

    # Extract only the needed directories: contrib/lib9p, lib/lib9p, sys/sys, include
    # We use tar --strip-components=1 to flatten
    tar -xf "$src_txz" -C "$LIB9P_SRC" \
        --wildcards \
        'usr/src/contrib/lib9p/*' \
        'usr/src/lib/lib9p/*' \
        'usr/src/sys/sys/*' \
        'usr/src/include/*' \
        2>/dev/null || true

    # Reorganize: move everything from usr/src/ to root of LIB9P_SRC
    if [ -d "${LIB9P_SRC}/usr/src" ]; then
        mv "${LIB9P_SRC}/usr/src/contrib" "${LIB9P_SRC}/contrib" 2>/dev/null || true
        mv "${LIB9P_SRC}/usr/src/lib" "${LIB9P_SRC}/lib" 2>/dev/null || true
        mv "${LIB9P_SRC}/usr/src/sys" "${LIB9P_SRC}/sys" 2>/dev/null || true
        mv "${LIB9P_SRC}/usr/src/include" "${LIB9P_SRC}/include" 2>/dev/null || true
        rm -rf "${LIB9P_SRC}/usr"
    fi

    if [ ! -f "${LIB9P_SRC}/contrib/lib9p/lib9p.h" ]; then
        warn "lib9p source extraction may have failed, trying git clone..."
        rm -rf "$LIB9P_SRC"
        git clone --depth 1 --branch releng/15.1 \
            https://git.FreeBSD.org/src.git "$LIB9P_SRC" 2>/dev/null || {
            warn "git clone failed, trying main branch..."
            git clone --depth 1 https://git.FreeBSD.org/src.git "$LIB9P_SRC" 2>/dev/null || {
                err "Cannot obtain lib9p source. Please install FreeBSD src manually."
            }
        }
    fi

    log "lib9p source ready: ${LIB9P_SRC}/contrib/lib9p"
}

# ===== Step 3: Cross-compile lib9p =====
step_lib9p() {
    local lib9p_so="${OUTPUT_DIR}/lib9p.so"
    if [ -f "$lib9p_so" ]; then
        log "lib9p already built: $lib9p_so"
        return 0
    fi

    step_lib9p_source

    local lib9p_contrib="${LIB9P_SRC}/contrib/lib9p"
    if [ ! -d "$lib9p_contrib" ]; then
        err "lib9p source not found at $lib9p_contrib"
    fi

    log "Cross-compiling lib9p to FreeBSD..."

    mkdir -p "$OUTPUT_DIR"
    mkdir -p "${OUTPUT_DIR}/include/lib9p"
    mkdir -p "${OUTPUT_DIR}/include/backend"
    mkdir -p "${OUTPUT_DIR}/include/transport"

    # ---- Copy public headers ----
    cp "${lib9p_contrib}/lib9p.h" "${OUTPUT_DIR}/include/lib9p/"
    cp "${lib9p_contrib}/fid.h" "${OUTPUT_DIR}/include/lib9p/"
    cp "${lib9p_contrib}/backend/fs.h" "${OUTPUT_DIR}/include/backend/"
    cp "${lib9p_contrib}/transport/socket.h" "${OUTPUT_DIR}/include/transport/"

    # ---- Copy internal headers (needed for compilation) ----
    for h in fcall.h threadpool.h hashtable.h l9p.h l9p_connection.h \
             l9p_debug.h l9p_errno.h l9p_fid.h l9p_proto.h \
             l9p_backend.h l9p_transport.h; do
        if [ -f "${lib9p_contrib}/$h" ]; then
            cp "${lib9p_contrib}/$h" "${OUTPUT_DIR}/include/lib9p/"
        fi
    done

    # ---- Copy sys/sys headers needed by lib9p ----
    # lib9p needs sys/queue.h, sys/sbuf.h, sys/uio.h, etc.
    # These are in the sysroot already, but we also need them for compilation
    # The sysroot provides them at ${SYSROOT}/usr/include/

    # ---- lib9p source files (from lib/lib9p/Makefile + GNUmakefile) ----
    local lib9p_srcs=(
        connection.c
        genacl.c
        hashtable.c
        log.c
        pack.c
        request.c
        rfuncs.c
        threadpool.c
        utils.c
        backend/fs.c
        transport/socket.c
        sbuf/sbuf.c
    )

    local objs=()
    local include_flags="-I${lib9p_contrib} -I${OUTPUT_DIR}/include -I${OUTPUT_DIR}/include/lib9p"

    # Also add sysroot include path for sys/sbuf.h etc.
    include_flags="${include_flags} -I${SYSROOT}/usr/include"

    for src in "${lib9p_srcs[@]}"; do
        local src_path="${lib9p_contrib}/${src}"
        if [ ! -f "$src_path" ]; then
            warn "Missing source file: $src_path, skipping"
            continue
        fi
        local obj="${OUTPUT_DIR}/$(basename "${src%.c}.o")"
        objs+=("$obj")
        log "  CC $src"
        $CC $CROSS_FLAGS $CFLAGS_BASE \
            $include_flags \
            -DWITH_CASPER=0 \
            -c "$src_path" -o "$obj" || {
            warn "Failed to compile $src, trying without extra flags..."
            $CC $CROSS_FLAGS $CFLAGS_BASE \
                $include_flags \
                -DWITH_CASPER=0 \
                -Wno-everything \
                -c "$src_path" -o "$obj" || {
                err "Failed to compile $src"
            }
        }
    done

    if [ ${#objs[@]} -eq 0 ]; then
        err "No object files built for lib9p"
    fi

    log "  LD lib9p.so"
    $CC $CROSS_FLAGS -shared -o "$lib9p_so" "${objs[@]}" \
        -L"${SYSROOT}/usr/lib" -lsbuf 2>/dev/null || {
        # Try without external libsbuf (sbuf is compiled in)
        warn "Linking with -lsbuf failed, trying without (sbuf compiled in)..."
        $CC $CROSS_FLAGS -shared -o "$lib9p_so" "${objs[@]}"
    }

    # Also create static lib
    log "  AR lib9p.a"
    llvm-ar rcs "${OUTPUT_DIR}/lib9p.a" "${objs[@]}" 2>/dev/null || \
        ar rcs "${OUTPUT_DIR}/lib9p.a" "${objs[@]}"

    log "lib9p built: $(file "$lib9p_so" 2>/dev/null || echo 'unknown')"
}

# ===== Step 4: Cross-compile WSL binaries =====
step_wsl() {
    log "Cross-compiling WSL binaries..."
    mkdir -p "$OUTPUT_DIR"

    local lib9p_so="${OUTPUT_DIR}/lib9p.so"
    local lib9p_include="${OUTPUT_DIR}/include"

    # Include paths: source dir + lib9p headers + sysroot
    local inc="-I${SCRIPT_DIR} -I${SYSROOT}/usr/include"
    if [ -d "$lib9p_include" ]; then
        inc="$inc -I${lib9p_include} -I${lib9p_include}/lib9p"
    fi

    # Library paths: our built lib9p + sysroot libs
    local libpath="-L${OUTPUT_DIR} -L${SYSROOT}/usr/lib"
    # lib9p deps: libsbuf (base). libutil for forkpty in hvbridge.
    # lib9p does NOT need libevent (verified from lib/lib9p/Makefile).
    local ldflags="$libpath -l9p -lsbuf -lutil"

    cd "$SCRIPT_DIR"

    # ---- hvinit ----
    log "  CC hvinit"
    $CC $CROSS_FLAGS $CFLAGS_BASE $inc \
        -o "${OUTPUT_DIR}/hvinit" \
        hvinit.c $ldflags || {
        warn "hvinit build failed, trying with -Wno-everything..."
        $CC $CROSS_FLAGS $CFLAGS_BASE $inc -Wno-everything \
            -o "${OUTPUT_DIR}/hvinit" \
            hvinit.c $ldflags || err "Failed to build hvinit"
    }

    # ---- hvbridge ----
    log "  CC hvbridge"
    $CC $CROSS_FLAGS $CFLAGS_BASE $inc \
        -o "${OUTPUT_DIR}/hvbridge" \
        hvbridge.c $ldflags || {
        warn "hvbridge build failed, trying with -Wno-everything..."
        $CC $CROSS_FLAGS $CFLAGS_BASE $inc -Wno-everything \
            -o "${OUTPUT_DIR}/hvbridge" \
            hvbridge.c $ldflags || err "Failed to build hvbridge"
    }

    # ---- wslpath (no lib9p needed) ----
    log "  CC wslpath"
    $CC $CROSS_FLAGS $CFLAGS_BASE $inc \
        -o "${OUTPUT_DIR}/wslpath" \
        wslpath.c || err "Failed to build wslpath"

    # ---- wslinfo (no lib9p needed) ----
    log "  CC wslinfo"
    $CC $CROSS_FLAGS $CFLAGS_BASE $inc \
        -o "${OUTPUT_DIR}/wslinfo" \
        wslinfo.c || err "Failed to build wslinfo"

    cd "$SCRIPT_DIR"

    log "WSL binaries built:"
    for bin in hvinit hvbridge wslpath wslinfo; do
        if [ -f "${OUTPUT_DIR}/$bin" ]; then
            echo -n "  $bin: "
            file "${OUTPUT_DIR}/$bin" 2>/dev/null || echo "OK"
        else
            err "Failed to build $bin"
        fi
    done
}

# ===== Step 5: Create deployment tarball =====
step_package() {
    log "Creating deployment package..."
    mkdir -p "${BUILD_DIR}/pkg"

    local pkg="${BUILD_DIR}/pkg"
    mkdir -p "${pkg}/usr/local/libexec/wsl"
    mkdir -p "${pkg}/usr/local/bin"
    mkdir -p "${pkg}/usr/local/etc/rc.d"
    mkdir -p "${pkg}/usr/local/lib"
    mkdir -p "${pkg}/etc"

    # Copy binaries
    install -m 755 "${OUTPUT_DIR}/hvinit"   "${pkg}/usr/local/libexec/wsl/"
    install -m 755 "${OUTPUT_DIR}/hvbridge" "${pkg}/usr/local/libexec/wsl/"
    install -m 755 "${OUTPUT_DIR}/wslpath"  "${pkg}/usr/local/bin/"
    install -m 755 "${OUTPUT_DIR}/wslinfo"  "${pkg}/usr/local/bin/"

    # Copy lib9p
    if [ -f "${OUTPUT_DIR}/lib9p.so" ]; then
        install -m 644 "${OUTPUT_DIR}/lib9p.so" "${pkg}/usr/local/lib/"
    fi

    # Copy rc.d script
    if [ -f "${SCRIPT_DIR}/wsl_init" ]; then
        install -m 555 "${SCRIPT_DIR}/wsl_init" "${pkg}/usr/local/etc/rc.d/wsl_init"
    fi

    # Create install script
    cat > "${pkg}/install.sh" <<'INSTEOF'
#!/bin/sh
# Install WSL-For-FreeBSD into a FreeBSD system.
# Run as root: sh install.sh
set -e
echo "Installing WSL-For-FreeBSD..."
cp -a usr/local/libexec/wsl/* /usr/local/libexec/wsl/ 2>/dev/null || {
    mkdir -p /usr/local/libexec/wsl
    cp -a usr/local/libexec/wsl/* /usr/local/libexec/wsl/
}
cp -a usr/local/bin/* /usr/local/bin/
cp -a usr/local/etc/rc.d/* /usr/local/etc/rc.d/ 2>/dev/null || true
cp -a usr/local/lib/* /usr/local/lib/ 2>/dev/null || true
if [ -f /usr/local/lib/lib9p.so ]; then
    ldconfig /usr/local/lib
fi
echo "Done. Enable: sysrc wsl_init_enable=YES && service wsl_init start"
INSTEOF
    chmod 755 "${pkg}/install.sh"

    # Create README
    cat > "${pkg}/README.txt" <<'README'
WSL-For-FreeBSD 15.1-RELEASE (amd64)
====================================

This package contains FreeBSD binaries for the WSL2 protocol implementation.

Files:
  hvinit    - WSL init daemon (runs as PID 1 in Hyper-V VM)
  hvbridge  - Terminal session bridge (forkpty + PTY relay)
  wslpath   - Windows <-> POSIX path converter
  wslinfo   - WSL environment info query tool
  lib9p.so  - 9P2000.L file server library
  wsl_init  - FreeBSD rc.d service script

Installation (on FreeBSD 15.1+):
  # sh install.sh

Requirements:
  - FreeBSD 15.1-RELEASE or later (amd64)
  - Hyper-V Generation 2 VM
  - hv_sock kernel module (kldload hv_sock)

Quick start:
  sysrc wsl_init_enable=YES
  service wsl_init start

Build info:
  Cross-compiled from Linux using clang --target=x86_64-unknown-freebsd15.1
  with FreeBSD 15.1-RELEASE sysroot.
README

    # Create tarball
    local tarball="${BUILD_DIR}/${PKG_NAME}.tar.gz"
    log "Creating tarball: $tarball"
    tar -czf "$tarball" -C "${BUILD_DIR}/pkg" .

    log "Package created: $tarball ($(du -h "$tarball" | cut -f1))"
    log ""
    log "Contents:"
    tar -tzf "$tarball" | head -20

    echo ""
    echo "============================================"
    echo " Build complete!"
    echo "============================================"
    echo " Tarball: $tarball"
    echo ""
    echo " To deploy on FreeBSD:"
    echo "   tar -xzf ${PKG_NAME}.tar.gz -C /tmp/wsl && cd /tmp/wsl"
    echo "   sh install.sh"
    echo "============================================"
}

# ===== Step 6: Create .wsl file =====
step_wslfile() {
    log "Creating .wsl distribution file..."

    local pkg="${BUILD_DIR}/wsl-pkg"
    rm -rf "$pkg"
    mkdir -p "$pkg"

    # ---- Step 6a: Extract FreeBSD rootfs from base.txz ----
    local base_txz="${BUILD_DIR}/base.txz"
    if [ ! -f "$base_txz" ]; then
        download "$BASE_TXZ_URL" "$base_txz"
    fi

    log "Extracting FreeBSD rootfs..."
    tar -xf "$base_txz" -C "$pkg"

    # ---- Step 6b: Install WSL binaries into rootfs ----
    mkdir -p "$pkg/usr/local/libexec/wsl"
    mkdir -p "$pkg/usr/local/bin"
    mkdir -p "$pkg/usr/local/etc/rc.d"
    mkdir -p "$pkg/usr/local/lib"

    if [ -f "${OUTPUT_DIR}/hvinit" ]; then
        install -m 755 "${OUTPUT_DIR}/hvinit"   "$pkg/usr/local/libexec/wsl/"
        install -m 755 "${OUTPUT_DIR}/hvbridge" "$pkg/usr/local/libexec/wsl/"
        install -m 755 "${OUTPUT_DIR}/wslpath"  "$pkg/usr/local/bin/"
        install -m 755 "${OUTPUT_DIR}/wslinfo"  "$pkg/usr/local/bin/"
    else
        warn "WSL binaries not built yet, running build first..."
        step_wsl
        install -m 755 "${OUTPUT_DIR}/hvinit"   "$pkg/usr/local/libexec/wsl/"
        install -m 755 "${OUTPUT_DIR}/hvbridge" "$pkg/usr/local/libexec/wsl/"
        install -m 755 "${OUTPUT_DIR}/wslpath"  "$pkg/usr/local/bin/"
        install -m 755 "${OUTPUT_DIR}/wslinfo"  "$pkg/usr/local/bin/"
    fi

    if [ -f "${OUTPUT_DIR}/lib9p.so" ]; then
        install -m 644 "${OUTPUT_DIR}/lib9p.so" "$pkg/usr/local/lib/"
    fi

    if [ -f "${SCRIPT_DIR}/wsl_init" ]; then
        install -m 555 "${SCRIPT_DIR}/wsl_init" "$pkg/usr/local/etc/rc.d/wsl_init"
    fi

    # ---- Step 6c: Create WSL configuration files ----
    # /etc/wsl-distribution.conf - tells WSL how to configure this distro
    cat > "$pkg/etc/wsl-distribution.conf" <<'EOF'
# WSL Distribution Configuration for FreeBSD
# This file controls how WSL sets up the FreeBSD distribution.

[oobe]
command = /usr/local/libexec/wsl/hvinit
defaultUid = 0
defaultName = FreeBSD-15.1

[shortcut]
enabled = true

[windowsterminal]
enabled = true
EOF

    # /etc/wsl.conf - WSL per-distro settings
    cat > "$pkg/etc/wsl.conf" <<'EOF'
# WSL Configuration for FreeBSD
# See: https://learn.microsoft.com/en-us/windows/wsl/wsl-config

[automount]
enabled = true
root = /mnt
mountFsTab = true

[network]
generateHosts = true
generateResolvConf = true

[interop]
enabled = true
appendWindowsPath = true
EOF

    # ---- Step 6d: Create /etc/resolv.conf symlink placeholder ----
    # FreeBSD uses /etc/resolv.conf for DNS
    if [ ! -f "$pkg/etc/resolv.conf" ]; then
        echo "nameserver 8.8.8.8" > "$pkg/etc/resolv.conf"
    fi

    # ---- Step 6e: Create ldconfig entry for lib9p ----
    mkdir -p "$pkg/usr/local/etc/ldconfig.d"
    echo "/usr/local/lib" > "$pkg/usr/local/etc/ldconfig.d/wsl.conf"

    # ---- Step 6f: Package as .wsl file (tar.gz with .wsl extension) ----
    local wslfile="${BUILD_DIR}/${PKG_NAME}.wsl"
    log "Creating .wsl file: $wslfile"
    tar -czf "$wslfile" -C "$pkg" .

    log ".wsl file created: $wslfile ($(du -h "$wslfile" | cut -f1))"
    log ""
    log "To install on Windows:"
    log "  wsl --install --from-file ${PKG_NAME}.wsl"
    log ""
    log "Or import existing:"
    log "  wsl --import FreeBSD-15.1 C:\\wsl\\freebsd ${PKG_NAME}.wsl"
    log ""
    log "Note: This .wsl file contains a FreeBSD rootfs with WSL binaries."
    log "It requires a FreeBSD-compatible kernel to boot (Hyper-V Gen2 VM)."
}

# ===== Clean =====
step_clean() {
    log "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    log "Clean."
}

# ===== Check existing build =====
check_existing() {
    local missing=0
    for bin in hvinit hvbridge wslpath wslinfo; do
        if [ ! -f "${OUTPUT_DIR}/$bin" ]; then
            missing=1
        fi
    done
    if [ ! -f "${OUTPUT_DIR}/lib9p.so" ]; then
        missing=1
    fi
    return $missing
}

# ===== Main =====
main() {
    local action="${1:-all}"

    echo ""
    echo "============================================"
    echo " WSL-For-FreeBSD Cross-Compilation Builder"
    echo " Target: ${TARGET_TRIPLE}"
    echo " Sysroot: ${FREEBSD_REL}"
    echo "============================================"
    echo ""

    check_tools

    case "$action" in
        all)
            if check_existing; then
                log "Existing build found, skipping to package..."
                step_package
                return 0
            fi
            step_sysroot
            step_lib9p
            step_wsl
            step_package
            ;;
        sysroot)
            step_sysroot
            ;;
        lib9p)
            step_sysroot
            step_lib9p
            ;;
        wsl)
            step_sysroot
            step_lib9p
            step_wsl
            ;;
        package)
            step_package
            ;;
        wslfile)
            step_sysroot
            step_lib9p
            step_wsl
            step_wslfile
            ;;
        clean)
            step_clean
            ;;
        *)
            echo "Usage: $0 [all|sysroot|lib9p|wsl|package|wslfile|clean]"
            exit 1
            ;;
    esac
}

main "$@"