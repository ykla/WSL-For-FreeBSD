#!/bin/sh
#
# SPDX-License-Identifier: MIT
#
# build_freebsd.sh - Automated build script for WSL-For-FreeBSD on FreeBSD.
#
# This script must be run on a FreeBSD system (native build, not cross-compile).
# It installs dependencies, builds all binaries, and optionally installs them.
#
# Usage:
#   ./build_freebsd.sh          # Build only
#   ./build_freebsd.sh install  # Build and install to /usr/local
#   ./build_freebsd.sh package  # Build and create tarball package
#
# Requirements:
#   - FreeBSD 14.0+ (for lib9p in base)
#   - Root/sudo access for install/package modes
#

set -e  # Exit on error

# Configuration
PREFIX="${PREFIX:-/usr/local}"
LIBEXECDIR="${LIBEXECDIR:-${PREFIX}/libexec/wsl}"
BINDIR="${BINDIR:-${PREFIX}/bin}"
RCDIR="${RCDIR:-${PREFIX}/etc/rc.d}"

# Build artifacts
BINS="hvinit hvbridge wslpath wslinfo"

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1"
}

# Check if running on FreeBSD
check_freebsd() {
    if [ "$(uname -s)" != "FreeBSD" ]; then
        log_error "This script must be run on FreeBSD (native build required)"
        log_error "Current system: $(uname -s)"
        exit 1
    fi
    log_info "Running on FreeBSD $(uname -r)"
}

# Check FreeBSD version (lib9p requires 14.0+)
check_version() {
    major=$(uname -r | cut -d. -f1)
    if [ "$major" -lt 14 ]; then
        log_warn "FreeBSD $major detected; lib9p requires FreeBSD 14.0+"
        log_warn "lib9p is in base on 14.0+, or install from pkg on older versions"
    fi
}

# Install build dependencies
install_deps() {
    log_info "Installing build dependencies..."

    # lib9p: in FreeBSD 14.0+ base, or from pkg
    if [ "$major" -ge 14 ]; then
        log_info "lib9p available in base (/usr/src/contrib/lib9p)"
        # Ensure lib9p headers are available
        if [ ! -f "/usr/include/lib9p.h" ]; then
            log_warn "lib9p headers not in /usr/include; may need to build from src"
        fi
    else
        # Install lib9p from pkg
        pkg install -y lib9p || {
            log_error "Failed to install lib9p from pkg"
            exit 1
        }
    fi

    # libutil (for forkpty) - base library
    # libevent (for lib9p transport) - base library

    # Build tools
    pkg install -y gcc gmake || {
        log_warn "gcc/gmake install failed, using base cc/make"
    }

    log_info "Dependencies installed"
}

# Build lib9p from FreeBSD src (if not in base)
build_lib9p_from_src() {
    if [ -f "/usr/lib/lib9p.so" ]; then
        log_info "lib9p already available"
        return 0
    fi

    log_info "Building lib9p from FreeBSD src..."

    if [ ! -d "/usr/src/contrib/lib9p" ]; then
        log_error "FreeBSD src not found at /usr/src"
        log_error "Install src component: freebsd-update fetch --components src"
        exit 1
    fi

    cd /usr/src/contrib/lib9p
    make -f Makefile.lib9p || {
        # Try alternate Makefile pattern
        if [ -f "Makefile" ]; then
            make
        else
            log_error "No Makefile found in /usr/src/contrib/lib9p"
            exit 1
        fi
    }
    make install

    log_info "lib9p built and installed from src"
}

# Build WSL binaries
build_bins() {
    log_info "Building WSL binaries..."

    cd "$(dirname "$0")"

    # Use FreeBSD Makefile
    if [ -f "Makefile" ]; then
        log_info "Using production Makefile"
        make clean || true
        make CC="${CC:-cc}" CFLAGS="-Wall -Wextra -O2 -g -std=gnu11 -D__FreeBSD__=1" \
             LDFLAGS="-lutil -levent -l9p"
    else
        log_error "Makefile not found"
        exit 1
    fi

    # Verify binaries were built
    for bin in $BINS; do
        if [ ! -f "$bin" ]; then
            log_error "Failed to build $bin"
            exit 1
        fi
        log_info "Built: $bin ($(file "$bin" | cut -d: -f2))"
    done

    log_info "All binaries built successfully"
}

# Install binaries to system paths
install_bins() {
    log_info "Installing WSL binaries to ${PREFIX}..."

    # Create directories
    mkdir -p "${LIBEXECDIR}"
    mkdir -p "${BINDIR}"
    mkdir -p "${RCDIR}"

    # Install init daemon binaries
    install -m 755 hvinit "${LIBEXECDIR}/hvinit"
    install -m 755 hvbridge "${LIBEXECDIR}/hvbridge"
    log_info "Installed: hvinit, hvbridge -> ${LIBEXECDIR}"

    # Install user tools
    install -m 755 wslpath "${BINDIR}/wslpath"
    install -m 755 wslinfo "${BINDIR}/wslinfo"
    log_info "Installed: wslpath, wslinfo -> ${BINDIR}"

    # Install rc.d script
    if [ -f "wsl_init" ]; then
        install -m 555 wsl_init "${RCDIR}/wsl_init"
        log_info "Installed: wsl_init -> ${RCDIR}"
    else
        log_warn "wsl_init rc.d script not found"
    fi

    log_info "Installation complete"
    log_info ""
    log_info "To enable WSL init daemon:"
    log_info "  sysrc wsl_init_enable=YES"
    log_info "  service wsl_init start"
}

# Create distributable tarball package
create_package() {
    log_info "Creating distribution package..."

    PKG_NAME="wsl-freebsd-$(date +%Y%m%d)-$(uname -m)"
    PKG_DIR="/tmp/${PKG_NAME}"

    mkdir -p "${PKG_DIR}/bin"
    mkdir -p "${PKG_DIR}/libexec/wsl"
    mkdir -p "${PKG_DIR}/etc/rc.d"

    # Copy binaries
    install -m 755 hvinit "${PKG_DIR}/libexec/wsl/"
    install -m 755 hvbridge "${PKG_DIR}/libexec/wsl/"
    install -m 755 wslpath "${PKG_DIR}/bin/"
    install -m 755 wslinfo "${PKG_DIR}/bin/"

    # Copy rc.d script
    install -m 555 wsl_init "${PKG_DIR}/etc/rc.d/"

    # Create install script
    cat > "${PKG_DIR}/install.sh" <<'INSTALL_EOF'
#!/bin/sh
# Install script for WSL-For-FreeBSD
PREFIX="${PREFIX:-/usr/local}"

echo "Installing WSL-For-FreeBSD to ${PREFIX}..."

mkdir -p "${PREFIX}/libexec/wsl"
mkdir -p "${PREFIX}/bin"
mkdir -p "${PREFIX}/etc/rc.d"

install -m 755 libexec/wsl/hvinit "${PREFIX}/libexec/wsl/"
install -m 755 libexec/wsl/hvbridge "${PREFIX}/libexec/wsl/"
install -m 755 bin/wslpath "${PREFIX}/bin/"
install -m 755 bin/wslinfo "${PREFIX}/bin/"
install -m 555 etc/rc.d/wsl_init "${PREFIX}/etc/rc.d/"

echo ""
echo "Installation complete."
echo "To enable: sysrc wsl_init_enable=YES"
echo "To start:   service wsl_init start"
INSTALL_EOF
    chmod 755 "${PKG_DIR}/install.sh"

    # Create README
    cat > "${PKG_DIR}/README.txt" <<'README_EOF'
WSL-For-FreeBSD - WSL2 protocol implementation for FreeBSD guests

This package contains:
  - hvinit: WSL init daemon (runs as PID 1 in WSL VM)
  - hvbridge: Terminal session bridge process
  - wslpath: Path conversion tool (Windows <-> POSIX)
  - wslinfo: WSL environment info query tool
  - wsl_init: FreeBSD rc.d startup script

Installation:
  ./install.sh

Or manual install:
  cp libexec/wsl/* /usr/local/libexec/wsl/
  cp bin/* /usr/local/bin/
  cp etc/rc.d/wsl_init /usr/local/etc/rc.d/

Requirements:
  - FreeBSD 14.0+ (for lib9p and hv_sock kernel module)
  - Hyper-V Generation 2 VM (for hvsocket support)

Usage:
  sysrc wsl_init_enable=YES
  service wsl_init start

For more information, see:
  https://github.com/your-repo/WSL-For-FreeBSD
README_EOF

    # Create tarball
    tar -czf "/tmp/${PKG_NAME}.tar.gz" -C "/tmp" "${PKG_NAME}"

    log_info "Package created: /tmp/${PKG_NAME}.tar.gz"
    log_info "Package contents:"
    tar -tzf "/tmp/${PKG_NAME}.tar.gz"

    # Cleanup
    rm -rf "${PKG_DIR}"
}

# Main entry point
main() {
    action="${1:-build}"

    log_info "WSL-For-FreeBSD Build Script"
    log_info "Action: $action"
    log_info ""

    check_freebsd
    check_version

    case "$action" in
        build)
            install_deps
            build_lib9p_from_src
            build_bins
            log_info "Build complete. Binaries: $BINS"
            ;;
        install)
            install_deps
            build_lib9p_from_src
            build_bins
            install_bins
            ;;
        package)
            install_deps
            build_lib9p_from_src
            build_bins
            create_package
            ;;
        deps)
            install_deps
            build_lib9p_from_src
            ;;
        *)
            log_error "Unknown action: $action"
            log_info "Usage: $0 [build|install|package|deps]"
            exit 1
            ;;
    esac
}

main "$@"