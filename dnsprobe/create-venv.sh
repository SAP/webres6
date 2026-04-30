#!/usr/bin/env bash
#
# Creates a Python virtualenv in .venv and builds + installs the
# libunbound Python bindings (pyunbound) from source into it.
#
# Build recipe follows Dockerfile in this directory.
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
# SPDX-License-Identifier: Apache-2.0
#
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VENV_DIR="$SCRIPT_DIR/.venv"
BUILD_DIR="$VENV_DIR/unbound_build"   # libunbound installed here
MAX_TARGET_NX=25                         # same as Dockerfile; works around CDN issues

OS="$(uname -s)"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

info()  { echo "==> $*"; }
error() { echo "ERROR: $*" >&2; exit 1; }

# ── dependency check ─────────────────────────────────────────────────────────

check_deps() {
    info "Checking build dependencies..."
    local missing=()

    for cmd in curl tar python3 swig; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [ "$OS" = "Darwin" ]; then
        command -v gcc   &>/dev/null || missing+=("Xcode CLI tools (xcode-select --install)")
        brew --prefix openssl &>/dev/null 2>&1 || missing+=("openssl  (brew install openssl)")
    else
        command -v gcc        &>/dev/null || missing+=("build-essential")
        command -v pkg-config &>/dev/null || missing+=("pkg-config")
        python3-config --includes &>/dev/null 2>&1 || \
            dpkg -s python3-dev &>/dev/null 2>&1 || missing+=("python3-dev")
        pkg-config --exists libssl  2>/dev/null   || missing+=("libssl-dev")
        pkg-config --exists expat   2>/dev/null   || \
            [ -f /usr/include/expat.h ]            || missing+=("libexpat1-dev")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing dependencies:"
        printf '  %s\n' "${missing[@]}"
        if [ "$OS" = "Darwin" ]; then
            echo "Install with:  brew install openssl swig"
        else
            echo "Install with:  sudo apt-get install build-essential pkg-config python3-dev libssl-dev libexpat1-dev swig"
        fi
        error "Please install missing dependencies and retry."
    fi
}

# ── build unbound from source ─────────────────────────────────────────────────

build_unbound() {
    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" RETURN

    info "Downloading latest unbound source..."
    curl -fsSL https://nlnetlabs.nl/downloads/unbound/unbound-latest.tar.gz \
        -o "$tmpdir/unbound.tar.gz"
    tar -xzf "$tmpdir/unbound.tar.gz" -C "$tmpdir"

    local srcdir
    srcdir=$(find "$tmpdir" -maxdepth 1 -type d -name 'unbound-[0-9]*' | sort -V | tail -1)
    [ -n "$srcdir" ] || error "Could not find unbound source directory in tarball"

    info "Patching MAX_TARGET_NX → $MAX_TARGET_NX (CDN workaround, same as Dockerfile)..."
    sed -i.bak "s/#define MAX_TARGET_NX[[:space:]].*/#define MAX_TARGET_NX		${MAX_TARGET_NX}/" \
        "$srcdir/iterator/iterator.h"
    grep -q "MAX_TARGET_NX.*${MAX_TARGET_NX}" "$srcdir/iterator/iterator.h" \
        || error "MAX_TARGET_NX patch failed — check iterator/iterator.h"
    rm "$srcdir/iterator/iterator.h.bak"

    info "Configuring (prefix: $BUILD_DIR, PYTHON: $VENV_DIR/bin/python3)..."
    mkdir -p "$BUILD_DIR"

    local configure_args=(
        "--prefix=$BUILD_DIR"
        "--with-pyunbound"
        "PYTHON=$VENV_DIR/bin/python3"
    )

    if [ "$OS" = "Darwin" ]; then
        # On macOS, LDLIBRARY is 'Python.framework/…/Python' so configure never derives
        # -lpythonX.Y automatically — we must supply LDFLAGS + LIBS explicitly.
        # expat.h lives in the Xcode SDK, not in the Homebrew prefix.
        local python_libdir python_ldversion
        python_libdir=$("$VENV_DIR/bin/python3" -c \
            "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
        python_ldversion=$("$VENV_DIR/bin/python3" -c \
            "import sysconfig; print(sysconfig.get_config_var('LDVERSION'))")
        configure_args+=(
            "--with-ssl=$(brew --prefix openssl)"
            "--with-libexpat=$(xcrun --show-sdk-path)/usr"
            "LDFLAGS=-L$python_libdir"
            "LIBS=-lpython$python_ldversion"
        )
    else
        configure_args+=(
            "--with-ssl"
            "--with-libexpat=/usr"
        )
    fi

    cd "$srcdir"
    ./configure "${configure_args[@]}"

    info "Building unbound ($JOBS parallel jobs)..."
    make -j"$JOBS"

    info "Installing (libunbound → $BUILD_DIR/lib, pyunbound → venv site-packages)..."
    make install
}

# ── patch activate script with library path ───────────────────────────────────

patch_activate() {
    local activate="$VENV_DIR/bin/activate"
    if grep -q "unbound_build" "$activate" 2>/dev/null; then
        return  # already patched
    fi

    info "Adding $BUILD_DIR/lib to library search path in activate script..."
    if [ "$OS" = "Darwin" ]; then
        cat >> "$activate" <<EOF

# Added by create-venv.sh: make libunbound.dylib findable
export DYLD_LIBRARY_PATH="$BUILD_DIR/lib\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH}"
EOF
    else
        cat >> "$activate" <<EOF

# Added by create-venv.sh: make libunbound.so findable
export LD_LIBRARY_PATH="$BUILD_DIR/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
EOF
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

info "Setting up dnsprobe virtualenv in $VENV_DIR..."

# 1. Create venv
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip

# 2. Python dependencies (Flask + Gunicorn)
info "Installing Python dependencies (Flask, Gunicorn)..."
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
pip install --quiet 'gunicorn[gthread]'

# 3. Build pyunbound if not already available
if python3 -c "import unbound" 2>/dev/null; then
    info "pyunbound already importable — skipping build."
else
    check_deps
    build_unbound
fi

# 4. Ensure the activate script exports the library path
patch_activate

# 5. Verify (re-source activate so LD_LIBRARY_PATH is set for this check)
source "$VENV_DIR/bin/activate"
python3 -c "import unbound; print('pyunbound OK:', unbound.__file__)" \
    || error "import unbound failed — see messages above."

info "Done. Run with:"
info "  source .venv/bin/activate"
info "  ./dnsprobe.py --port 6453"
