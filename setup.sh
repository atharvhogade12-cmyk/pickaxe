#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
#  ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
#  ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
#  Pickaxe OSINT — Automated Setup Script
#  Supports: Termux (Android) | Debian/Ubuntu | Arch | RHEL/CentOS
# =============================================================================
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; }
section() { echo -e "\n${WHITE}════════════════════════════════════════${NC}"; \
            echo -e "${WHITE}  $*${NC}"; \
            echo -e "${WHITE}════════════════════════════════════════${NC}"; }

# ── Detect environment ────────────────────────────────────────────────────────
detect_env() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

ENV=$(detect_env)

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN} ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗${NC}"
echo -e "${CYAN} ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝${NC}"
echo -e "${CYAN} ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗  ${NC}"
echo -e "${CYAN} ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝  ${NC}"
echo -e "${CYAN} ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗${NC}"
echo -e "${CYAN} ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝${NC}"
echo -e "${WHITE}        Hybrid OSINT Setup Script — v2.0.0${NC}"
echo -e "        Detected environment: ${YELLOW}${ENV}${NC}"
echo ""

# ── Package installs ──────────────────────────────────────────────────────────
section "Step 1/4 — Installing system dependencies"

install_termux() {
    info "Updating package index (pkg)…"
    pkg update -y && pkg upgrade -y

    info "Installing: nmap whois dnsutils ruby python…"
    pkg install -y nmap whois dnsutils ruby python

    info "Installing WhatWeb via RubyGems…"
    gem install whatweb --no-document || warn "WhatWeb gem install failed — try manually: gem install whatweb"
}

install_debian() {
    info "Updating apt package index…"
    sudo apt-get update -y

    info "Installing: nmap whois dnsutils whatweb python3 python3-pip…"
    sudo apt-get install -y nmap whois dnsutils whatweb python3 python3-pip
}

install_arch() {
    info "Syncing pacman repos…"
    sudo pacman -Sy --noconfirm

    info "Installing: nmap whois bind whatweb python python-pip…"
    sudo pacman -S --noconfirm nmap whois bind whatweb python python-pip || {
        warn "whatweb not in official repos — installing via gem…"
        sudo pacman -S --noconfirm ruby
        gem install whatweb --no-document
    }
}

install_rhel() {
    PM="yum"
    command -v dnf &>/dev/null && PM="dnf"

    info "Updating $PM repos…"
    sudo $PM update -y

    info "Installing: nmap whois bind-utils python3 python3-pip…"
    sudo $PM install -y nmap whois bind-utils python3 python3-pip

    info "Installing WhatWeb via RubyGems…"
    sudo $PM install -y ruby
    gem install whatweb --no-document || warn "WhatWeb gem install failed"
}

case "$ENV" in
    termux)  install_termux  ;;
    debian)  install_debian  ;;
    arch)    install_arch    ;;
    rhel)    install_rhel    ;;
    *)
        warn "Unknown environment. Please install manually:"
        echo "  nmap, whois, dnsutils/bind-utils, whatweb, python3, pip"
        ;;
esac

success "System dependencies installed."

# ── Python packages ───────────────────────────────────────────────────────────
section "Step 2/4 — Installing Python packages"

if [ -f "requirements.txt" ]; then
    info "Installing from requirements.txt…"
    pip install -r requirements.txt --quiet || pip3 install -r requirements.txt --quiet
    success "Python packages installed."
else
    warn "requirements.txt not found — installing rich directly…"
    pip install "rich>=13.7.0" --quiet || pip3 install "rich>=13.7.0" --quiet
    success "rich installed."
fi

# ── Permissions ───────────────────────────────────────────────────────────────
section "Step 3/4 — Setting file permissions"

if [ -f "hybrid_osint.py" ]; then
    chmod +x hybrid_osint.py
    success "hybrid_osint.py marked as executable."
else
    warn "hybrid_osint.py not found in current directory."
fi

# ── Verification ──────────────────────────────────────────────────────────────
section "Step 4/4 — Verifying installed tools"

ALL_OK=true
TOOLS=("nmap" "whois" "dig" "whatweb" "ping" "python3")

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        success "$tool — found ($(command -v "$tool"))"
    else
        error  "$tool — NOT FOUND"
        ALL_OK=false
    fi
done

echo ""
if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✔  Setup complete! All tools installed.  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Run the tool:"
    echo -e "  ${CYAN}python hybrid_osint.py --check${NC}"
    echo -e "  ${CYAN}python hybrid_osint.py example.com${NC}"
else
    echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ⚠  Setup finished with missing tools above.    ║${NC}"
    echo -e "${YELLOW}║     Install them manually and re-run --check.   ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
fi
echo ""
