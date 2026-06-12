#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
#  ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
#  ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
#  ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
#  ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
#  ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
#
#  Pickaxe OSINT — Zero-Touch Dependency Installer v2.1
#  ONE command installs EVERYTHING. No manual steps.
#  Supports: Termux (Android) | Debian/Ubuntu | Kali | Arch | RHEL/Fedora
# =============================================================================
#
#  Usage:
#    bash setup.sh            — full auto install
#    bash setup.sh --check    — verify only, no install
#    bash setup.sh --repair   — re-install missing tools only
#
# =============================================================================

# ── Safety — but DON'T use -e so we can handle errors ourselves ───────────────
set -uo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m';  BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}  ➜${NC}  $*"; }
success() { echo -e "${GREEN}  ✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC}  $*"; }
err()     { echo -e "${RED}  ✘${NC}  $*"; }
section() {
    echo ""
    echo -e "${BOLD}${WHITE}┌─────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${WHITE}│  $*$(printf '%*s' $((43 - ${#*})) '')│${NC}"
    echo -e "${BOLD}${WHITE}└─────────────────────────────────────────────┘${NC}"
}

# ── Track overall failures ────────────────────────────────────────────────────
FAILED_TOOLS=()

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo ""
    echo -e "${CYAN} ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗${NC}"
    echo -e "${CYAN} ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝${NC}"
    echo -e "${CYAN} ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗  ${NC}"
    echo -e "${CYAN} ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝  ${NC}"
    echo -e "${CYAN} ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗${NC}"
    echo -e "${CYAN} ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Pickaxe OSINT — Zero-Touch Installer v2.1${NC}"
    echo -e "  ${CYAN}Zero manual steps. Sit back and watch.${NC}"
    echo ""
}

# ── Environment detection ─────────────────────────────────────────────────────
detect_env() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif grep -qi "kali" /etc/os-release 2>/dev/null; then
        echo "kali"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v dnf &>/dev/null; then
        echo "fedora"
    elif command -v yum &>/dev/null; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

ENV=$(detect_env)

# ── Helper: run a command, return 0 on success 1 on fail ─────────────────────
try_run() {
    if "$@" > /tmp/pickaxe_install.log 2>&1; then
        return 0
    else
        warn "Command failed: $*"
        warn "Log: $(tail -3 /tmp/pickaxe_install.log 2>/dev/null)"
        return 1
    fi
}

# ── Check if a binary exists in PATH ─────────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# ── Sudo wrapper — skips sudo in Termux (root context) ───────────────────────
maybe_sudo() {
    if [ "$ENV" = "termux" ] || [ "$(id -u)" = "0" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# =============================================================================
#  ENVIRONMENT-SPECIFIC INSTALLERS
# =============================================================================

# ─── Termux ───────────────────────────────────────────────────────────────────
setup_termux() {
    section "Termux — Updating package index"
    info "Running: pkg update && pkg upgrade …"
    pkg update -y && pkg upgrade -y
    success "Package index updated."

    section "Termux — Installing system tools"
    PKGS=(nmap whois dnsutils python ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if pkg install -y "$pkg_name" > /tmp/pickaxe_install.log 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed to install ${pkg_name}:"
            tail -5 /tmp/pickaxe_install.log
            FAILED_TOOLS+=("$pkg_name")
        fi
    done
}

# ─── Debian / Ubuntu / Kali ───────────────────────────────────────────────────
setup_debian() {
    section "Debian/Ubuntu — Updating APT index"
    info "Running: apt-get update …"
    maybe_sudo apt-get update -y > /tmp/pickaxe_install.log 2>&1 \
        && success "APT index refreshed." \
        || warn "apt-get update returned errors (continuing anyway)."

    section "Debian/Ubuntu — Installing system tools"
    PKGS=(nmap whois dnsutils python3 python3-pip ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo apt-get install -y "$pkg_name" > /tmp/pickaxe_install.log 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            tail -3 /tmp/pickaxe_install.log
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    # whatweb — try apt first, fallback to gem
    section "Installing WhatWeb"
    info "Trying: apt-get install whatweb …"
    if maybe_sudo apt-get install -y whatweb > /tmp/pickaxe_install.log 2>&1; then
        success "WhatWeb installed via apt."
    else
        warn "Not in apt repos — falling back to RubyGem…"
        install_whatweb_gem
    fi
}

# ─── Arch Linux ───────────────────────────────────────────────────────────────
setup_arch() {
    section "Arch — Syncing pacman repos"
    maybe_sudo pacman -Sy --noconfirm > /tmp/pickaxe_install.log 2>&1 \
        && success "pacman synced." \
        || warn "pacman sync issues (continuing)."

    section "Arch — Installing system tools"
    PKGS=(nmap whois bind python python-pip ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo pacman -S --noconfirm "$pkg_name" > /tmp/pickaxe_install.log 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Installing WhatWeb"
    if maybe_sudo pacman -S --noconfirm whatweb > /tmp/pickaxe_install.log 2>&1; then
        success "WhatWeb installed via pacman."
    else
        warn "Not in official repos — falling back to gem…"
        install_whatweb_gem
    fi
}

# ─── RHEL / CentOS / Fedora ───────────────────────────────────────────────────
setup_rhel() {
    PM="yum"; has dnf && PM="dnf"

    section "RHEL/Fedora — Updating ${PM} repos"
    maybe_sudo $PM makecache -y > /tmp/pickaxe_install.log 2>&1 \
        && success "Repo cache updated." \
        || warn "Cache update issues (continuing)."

    section "RHEL/Fedora — Installing system tools"
    PKGS=(nmap whois bind-utils python3 python3-pip ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo $PM install -y "$pkg_name" > /tmp/pickaxe_install.log 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Installing WhatWeb"
    install_whatweb_gem
}

# ─── Unknown OS ───────────────────────────────────────────────────────────────
setup_unknown() {
    err "Could not detect your package manager."
    echo ""
    echo -e "  Supported: ${YELLOW}Termux, apt (Debian/Ubuntu/Kali), pacman (Arch), dnf/yum (RHEL/Fedora)${NC}"
    echo -e "  Please open an issue at the project repo with your OS details."
    exit 1
}

# =============================================================================
#  WHATWEB VIA GEM (universal fallback)
# =============================================================================
install_whatweb_gem() {
    if ! has ruby; then
        err "Ruby not found — WhatWeb gem install skipped."
        FAILED_TOOLS+=("whatweb")
        return 1
    fi

    info "Installing WhatWeb gem (this may take ~60s)…"
    if gem install whatweb --no-document > /tmp/pickaxe_install.log 2>&1; then
        success "WhatWeb installed via gem."
    else
        # On some systems gem needs sudo
        if maybe_sudo gem install whatweb --no-document > /tmp/pickaxe_install.log 2>&1; then
            success "WhatWeb installed via gem (sudo)."
        else
            err "WhatWeb gem install failed:"
            tail -5 /tmp/pickaxe_install.log
            FAILED_TOOLS+=("whatweb")
        fi
    fi
}

# =============================================================================
#  PIP / PYTHON BOOTSTRAPPER
# =============================================================================
bootstrap_pip() {
    section "Python — Bootstrapping pip"

    PY=""
    for candidate in python3 python python3.12 python3.11 python3.10; do
        if has "$candidate"; then
            PY="$candidate"
            break
        fi
    done

    if [ -z "$PY" ]; then
        err "Python not found in PATH after install — cannot continue."
        FAILED_TOOLS+=("python")
        return 1
    fi

    success "Python: $($PY --version 2>&1)"

    # Check if pip already works
    if $PY -m pip --version &>/dev/null; then
        success "pip is available."
        return 0
    fi

    # Try ensurepip
    info "pip not found — bootstrapping via ensurepip…"
    if $PY -m ensurepip --upgrade > /tmp/pickaxe_install.log 2>&1; then
        success "pip bootstrapped via ensurepip."
        return 0
    fi

    # Try get-pip.py
    warn "ensurepip failed — fetching get-pip.py …"
    if has curl; then
        curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
            && $PY /tmp/get-pip.py --quiet \
            && success "pip installed via get-pip.py." \
            && return 0
    elif has wget; then
        wget -qO /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py \
            && $PY /tmp/get-pip.py --quiet \
            && success "pip installed via get-pip.py." \
            && return 0
    fi

    err "Could not install pip. Python packages will not be installed."
    FAILED_TOOLS+=("pip")
}

# =============================================================================
#  PYTHON PACKAGES
# =============================================================================
install_python_packages() {
    section "Python — Installing packages from requirements.txt"

    PY=""
    for candidate in python3 python python3.12 python3.11 python3.10; do
        if has "$candidate"; then PY="$candidate"; break; fi
    done

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REQ="${SCRIPT_DIR}/requirements.txt"

    if [ ! -f "$REQ" ]; then
        warn "requirements.txt not found at ${REQ}"
        info "Installing 'rich' directly…"
        $PY -m pip install "rich>=13.7.0" --quiet \
            && success "rich installed." \
            || { err "rich install failed."; FAILED_TOOLS+=("rich"); }
        return
    fi

    info "Installing from: ${REQ}"
    if $PY -m pip install -r "$REQ" --quiet; then
        success "All Python packages installed."
    else
        warn "pip install failed — retrying with --user flag…"
        if $PY -m pip install -r "$REQ" --quiet --user; then
            success "Python packages installed (--user mode)."
        else
            err "pip install failed. Check internet and try again."
            FAILED_TOOLS+=("python-packages")
        fi
    fi
}

# =============================================================================
#  FILE PERMISSIONS
# =============================================================================
set_permissions() {
    section "Setting file permissions"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    TARGET="${SCRIPT_DIR}/hybrid_osint.py"
    if [ -f "$TARGET" ]; then
        chmod +x "$TARGET"
        success "hybrid_osint.py → executable (+x)"
    else
        warn "hybrid_osint.py not found at ${SCRIPT_DIR} — skipping chmod."
    fi
}

# =============================================================================
#  FINAL VERIFICATION TABLE
# =============================================================================
verify_all() {
    section "Verification — Checking all tools"

    declare -A TOOL_MAP=(
        ["nmap"]="nmap"
        ["whois"]="whois"
        ["dig"]="dig"
        ["whatweb"]="whatweb"
        ["ping"]="ping"
        ["python"]="python3 python"
        ["pip"]="pip3 pip"
        ["ruby"]="ruby"
        ["gem"]="gem"
    )

    ALL_OK=true
    printf "\n  %-12s  %s\n" "Tool" "Status"
    printf "  %-12s  %s\n" "────────────" "──────────────────────────────"

    for label in nmap whois dig whatweb ping python pip ruby gem; do
        CANDIDATES="${TOOL_MAP[$label]}"
        FOUND=""
        for c in $CANDIDATES; do
            if has "$c"; then
                VER=$(command -v "$c")
                FOUND="$c  ($VER)"
                break
            fi
        done

        if [ -n "$FOUND" ]; then
            printf "  ${GREEN}✔${NC}  %-10s  ${GREEN}%s${NC}\n" "$label" "$FOUND"
        else
            printf "  ${RED}✘${NC}  %-10s  ${RED}NOT FOUND${NC}\n" "$label"
            ALL_OK=false
        fi
    done
    echo ""

    return $( [ "$ALL_OK" = true ] && echo 0 || echo 1 )
}

# =============================================================================
#  FINAL SUMMARY BANNER
# =============================================================================
print_summary() {
    echo ""
    if [ ${#FAILED_TOOLS[@]} -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                                                      ║${NC}"
        echo -e "${GREEN}║   ✔  PICKAXE IS READY — ALL DEPENDENCIES INSTALLED  ║${NC}"
        echo -e "${GREEN}║                                                      ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${BOLD}Next steps:${NC}"
        echo -e "  ${CYAN}python hybrid_osint.py --check${NC}         # verify env"
        echo -e "  ${CYAN}python hybrid_osint.py example.com${NC}     # run a scan"
        echo -e "  ${CYAN}python hybrid_osint.py --help${NC}          # usage guide"
    else
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║   ⚠  SETUP FINISHED — Some tools had issues         ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        err  "Failed to install: ${FAILED_TOOLS[*]}"
        echo ""
        echo -e "  ${BOLD}Troubleshooting:${NC}"
        echo -e "  • Check your internet connection."
        echo -e "  • On Debian/Kali, try:  ${CYAN}sudo apt-get install -f${NC}"
        echo -e "  • On Termux, try:       ${CYAN}pkg install ruby && gem install whatweb${NC}"
        echo -e "  • Run again:            ${CYAN}bash setup.sh --repair${NC}"
        echo -e "  • Pickaxe will skip missing tools automatically at runtime."
    fi
    echo ""
}

# =============================================================================
#  MAIN ENTRY POINT
# =============================================================================
main() {
    print_banner

    MODE="${1:-install}"

    # ── Check-only mode ───────────────────────────────────────────────────────
    if [ "$MODE" = "--check" ]; then
        info "Running in CHECK mode — no packages will be installed."
        verify_all && echo -e "\n  ${GREEN}All tools found!${NC}" \
                   || echo -e "\n  ${YELLOW}Some tools are missing. Run: bash setup.sh${NC}"
        exit 0
    fi

    # ── Environment banner ────────────────────────────────────────────────────
    echo -e "  ${BOLD}Detected environment:${NC} ${YELLOW}${ENV}${NC}"
    echo ""

    # ── Step 1 — OS packages ──────────────────────────────────────────────────
    case "$ENV" in
        termux)          setup_termux  ;;
        debian | kali)   setup_debian  ;;
        arch)            setup_arch    ;;
        rhel | fedora)   setup_rhel    ;;
        *)               setup_unknown ;;
    esac

    # ── WhatWeb on Termux needs gem (handled separately) ─────────────────────
    if [ "$ENV" = "termux" ] && ! has whatweb; then
        section "Termux — Installing WhatWeb via gem"
        install_whatweb_gem
    fi

    # ── Step 2 — Bootstrap pip ────────────────────────────────────────────────
    bootstrap_pip

    # ── Step 3 — Python packages ──────────────────────────────────────────────
    install_python_packages

    # ── Step 4 — Permissions ─────────────────────────────────────────────────
    set_permissions

    # ── Step 5 — Verify ───────────────────────────────────────────────────────
    verify_all || true   # don't exit on verify failure — summary handles it

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary
}

main "${1:-}"
