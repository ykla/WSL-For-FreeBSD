#!/bin/sh
#
# SPDX-License-Identifier: MIT
#
# build_lib9p.sh - Build and install lib9p from FreeBSD src.
#
# FreeBSD 14.0+ includes lib9p source in /usr/src/contrib/lib9p, but it
# may not be built/installed by default. This script builds lib9p and
# installs the library and headers.
#
# Usage:
#   ./build_lib9p.sh          # Build lib9p from src
#   ./build_lib9p.sh check    # Check if lib9p is already available
#
# Requirements:
#   - FreeBSD src component installed (/usr/src/contrib/lib9p)
#   - Build tools: make, cc
#

set -e

log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

# Check if running on FreeBSD
if [ "$(uname -s)" != "FreeBSD" ]; then
    log_error "This script must be run on FreeBSD"
    exit 1
fi

# Check FreeBSD version
major=$(uname -r | cut -d. -f1)
log_info "FreeBSD version: $(uname -r) (major=$major)"

if [ "$major" -lt 14 ]; then
    log_error "FreeBSD $major does not have lib9p in base"
    log_error "Install from pkg: pkg install lib9p"
    exit 1
fi

# Check if lib9p src exists
if [ ! -d "/usr/src/contrib/lib9p" ]; then
    log_error "FreeBSD src not found at /usr/src/contrib/lib9p"
    log_error "Install src component:"
    log_error "  freebsd-update fetch --components src"
    log_error "  Or download src: git clone https://git.FreeBSD.org/src.git /usr/src"
    exit 1
fi

log_info "lib9p source found at /usr/src/contrib/lib9p"

# Check if already built
check_lib9p() {
    if [ -f "/usr/local/lib/lib9p.so" ] || [ -f "/usr/lib/lib9p.so" ]; then
        log_info "lib9p library already installed"
        if [ -f "/usr/local/include/lib9p.h" ] || [ -f "/usr/include/lib9p.h" ]; then
            log_info "lib9p headers already installed"
            return 0
        fi
    fi
    return 1
}

# Build lib9p
build_lib9p() {
    log_info "Building lib9p from FreeBSD src..."

    # Navigate to lib9p source directory
    cd /usr/src/contrib/lib9p

    # Check for Makefile patterns
    if [ -f "Makefile.lib9p" ]; then
        log_info "Using Makefile.lib9p"
        make -f Makefile.lib9p
        make -f Makefile.lib9p install
    elif [ -f "Makefile" ]; then
        log_info "Using Makefile"
        make
        make install
    else
        # Try building manually
        log_info "No Makefile found, building manually..."

        # Find all C source files
        SRCS=$(find . -name "*.c" -type f | grep -v test)

        # Compile to object files
        for src in $SRCS; do
            obj=$(basename "${src%.c}.o")
            cc -c -O2 -I. -I/usr/src/sys "$src" -o "$obj"
        done

        # Link into shared library
        OBJS=$(find . -name "*.o" -type f)
        cc -shared -o lib9p.so $OBJS -levent

        # Install manually
        install -m 644 lib9p.so /usr/local/lib/
        install -m 644 lib9p.h /usr/local/include/

        # Create symlink
        ln -sf lib9p.so /usr/local/lib/lib9p.so.0

        log_info "lib9p built and installed manually"
    fi

    log_info "lib9p build complete"
}

# Install headers if missing
install_headers() {
    if [ ! -f "/usr/local/include/lib9p.h" ]; then
        log_info "Installing lib9p headers..."

        LIB9P_SRC="/usr/src/contrib/lib9p"

        # Copy main header
        if [ -f "${LIB9P_SRC}/lib9p.h" ]; then
            install -m 644 "${LIB9P_SRC}/lib9p.h" /usr/local/include/
        fi

        # Copy additional headers (backend, transport, etc.)
        for hdr in l9p.h l9p_backend.h l9p_transport.h l9p_connection.h; do
            if [ -f "${LIB9P_SRC}/${hdr}" ]; then
                install -m 644 "${LIB9P_SRC}/${hdr}" /usr/local/include/
            fi
        done

        # Install subdirectory headers (backend/, transport/)
        # These are required for plan9_server.h includes:
        #   <backend/fs.h>, <transport/socket.h>
        if [ -d "${LIB9P_SRC}/backend" ]; then
            mkdir -p /usr/local/include/backend
            for hdr in fs.h bio.h l9p_backend.h; do
                if [ -f "${LIB9P_SRC}/backend/${hdr}" ]; then
                    install -m 644 "${LIB9P_SRC}/backend/${hdr}" /usr/local/include/backend/
                fi
            done
        fi

        if [ -d "${LIB9P_SRC}/transport" ]; then
            mkdir -p /usr/local/include/transport
            for hdr in socket.h l9p_transport.h; do
                if [ -f "${LIB9P_SRC}/transport/${hdr}" ]; then
                    install -m 644 "${LIB9P_SRC}/transport/${hdr}" /usr/local/include/transport/
                fi
            done
        fi

        # Copy lib9p internal headers (required by backend/transport)
        for hdr in l9p.h l9p_proto.h l9p_debug.h l9p_errno.h l9p_fid.h; do
            if [ -f "${LIB9P_SRC}/${hdr}" ]; then
                install -m 644 "${LIB9P_SRC}/${hdr}" /usr/local/include/
            fi
        done

        log_info "Headers installed to /usr/local/include/ (including backend/ and transport/)"
    fi
}

# Update library cache
update_ldconfig() {
    log_info "Updating ldconfig cache..."
    ldconfig || true
}

# Main
action="${1:-build}"

case "$action" in
    check)
        if check_lib9p; then
            log_info "lib9p is available"
            exit 0
        else
            log_info "lib9p is NOT available"
            exit 1
        fi
        ;;
    build)
        if check_lib9p; then
            log_info "lib9p already available, skipping build"
        else
            build_lib9p
            install_headers
            update_ldconfig
        fi
        ;;
    *)
        log_error "Unknown action: $action"
        log_info "Usage: $0 [check|build]"
        exit 1
        ;;
esac

log_info "Done"