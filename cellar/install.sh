#!/usr/bin/env bash
# install.sh — sets up the project: checks Python 3.13+, installs uv
# and just if missing, then runs `just setup`.
#
# Usage: ./install.sh

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }

check_python() {
    if ! command -v python3 &>/dev/null; then
        error "python3 not found. Install Python 3.13+ and re-run this script."
        exit 1
    fi

    local version major minor
    version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major=${version%%.*}
    minor=${version##*.}

    if (( major < 3 )) || { (( major == 3 )) && (( minor < 13 )); }; then
        error "Python 3.13+ required, found Python $version"
        exit 1
    fi
    success "Python $version detected"
}

install_uv() {
    if command -v uv &>/dev/null; then
        success "uv already installed"
        return
    fi
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    command -v uv &>/dev/null || { error "uv install failed — restart your shell and try again."; exit 1; }
    success "uv installed"
}

install_just() {
    if command -v just &>/dev/null; then
        success "just already installed"
        return
    fi
    info "Installing just..."
    mkdir -p "$HOME/.local/bin"
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
        | bash -s -- --to "$HOME/.local/bin"
    export PATH="$HOME/.local/bin:$PATH"
    success "just installed"
}

main() {
    echo "=== password-vault install ==="
    check_python
    install_uv
    install_just
    just setup
    success "Install complete!"
    echo ""
    echo "Next steps:"
    echo "  just run -- --help    # see available commands"
    echo "  just run -- init      # create your first vault"
}

main "$@"