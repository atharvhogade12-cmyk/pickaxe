#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
#  ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
#  ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
#  ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
#  ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
#  ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
#
#  Pickaxe OSINT — Zero-Touch Dependency Installer v3.0
#  ONE command installs EVERYTHING. No manual steps.
#  Supports: Termux | Debian/Ubuntu | Kali | Arch | RHEL/Fedora | macOS | Alpine | openSUSE
#
#  FIXES in v3.0:
#   - Uses $TMPDIR instead of /tmp (critical for Termux)
#   - gem PATH exported and persisted to shell rc after install
#   - --repair mode properly implemented
#   - section() box width calculation fixed (${#msg} not ${#*})
#   - WhatWeb gem bin dir always added to PATH post-install
# =============================================================================
#
#  Usage:
#    bash setup.sh            — full auto install
#    bash setup.sh --check    — verify only, no install
#    bash setup.sh --repair   — re-install only missing tools
#
# =============================================================================

# ── Safety — DON'T use -e so we handle errors ourselves ──────────────────────
set -uo pipefail

# log goes here, idk why /tmp breaks on termux but it does
PICKAXE_LOG="${TMPDIR:-/tmp}/pickaxe_install.log"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m';  BOLD='\033[1m';  NC='\033[0m'

info()    { echo -e "${CYAN}  ➜${NC}  $*"; }
success() { echo -e "${GREEN}  ✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC}  $*"; }
err()     { echo -e "${RED}  ✘${NC}  $*"; }

section() {
    local msg="$*"
    local len=${#msg}
    local pad=$(( 43 - len ))
    [ $pad -lt 0 ] && pad=0
    echo ""
    echo -e "${BOLD}${WHITE}┌─────────────────────────────────────────────┐${NC}"
    printf "${BOLD}${WHITE}│  %s%*s│${NC}\n" "$msg" "$pad" ""
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
    echo -e "  ${BOLD}${WHITE}Pickaxe OSINT — Zero-Touch Installer v3.0${NC}"
    echo -e "  ${CYAN}Zero manual steps. Sit back and watch.${NC}"
    echo ""
}

# ── Environment detection ─────────────────────────────────────────────────────
detect_env() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif [ "$(uname -s)" = "Darwin" ]; then
        echo "macos"
    elif grep -qi "alpine" /etc/os-release 2>/dev/null || command -v apk &>/dev/null; then
        echo "alpine"
    elif grep -qi "opensuse\|suse" /etc/os-release 2>/dev/null || command -v zypper &>/dev/null; then
        echo "opensuse"
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

# ── Check if a binary exists in PATH ─────────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# ── Sudo wrapper — skips sudo in Termux (root not needed) ────────────────────
maybe_sudo() {
    if [ "$ENV" = "termux" ] || [ "$(id -u)" = "0" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ── Helper: run command, log output, return exit code ────────────────────────
# FIX: Uses $PICKAXE_LOG (= $TMPDIR-based) instead of hardcoded /tmp
try_run() {
    if "$@" > "$PICKAXE_LOG" 2>&1; then
        return 0
    else
        warn "Command failed: $*"
        warn "Last log lines: $(tail -3 "$PICKAXE_LOG" 2>/dev/null)"
        return 1
    fi
}

# =============================================================================
#  GEM PATH STUFF
# =============================================================================
# gem installs to some random dir that's not in PATH by default
# this tries to find it and add it, idk why gem doesn't just do this itself
fix_gem_path() {
    local gem_bin_dir=""

    # ask gem where it put its stuff
    if has gem; then
        local gemdir
        gemdir=$(gem environment gemdir 2>/dev/null)
        if [ -n "$gemdir" ] && [ -d "${gemdir}/bin" ]; then
            gem_bin_dir="${gemdir}/bin"
        fi
    fi

    # termux puts ruby gems somewhere completely different
    if [ -z "$gem_bin_dir" ] && [ "$ENV" = "termux" ]; then
        local prefix="${PREFIX:-/data/data/com.termux/files/usr}"
        # Look for ruby gem installations under the prefix
        for candidate in \
            "${prefix}/lib/ruby/gems"/*/*/bin \
            "${HOME}/.gem/ruby"/*/bin
        do
            if [ -d "$candidate" ] && ls "$candidate/whatweb" &>/dev/null 2>&1; then
                gem_bin_dir="$candidate"
                break
            fi
        done
        # Fallback: just grab any ruby gem bin dir
        if [ -z "$gem_bin_dir" ]; then
            for candidate in "${HOME}/.gem/ruby"/*/bin "${prefix}/lib/ruby/gems"/*/gems/*/bin; do
                if [ -d "$candidate" ]; then
                    gem_bin_dir="$candidate"
                    break
                fi
            done
        fi
    fi

    # brute force it, just check common gem dirs
    if [ -z "$gem_bin_dir" ]; then
        for candidate in "${HOME}/.gem/ruby"/*/bin; do
            if [ -d "$candidate" ]; then
                gem_bin_dir="$candidate"
                break
            fi
        done
    fi

    if [ -n "$gem_bin_dir" ]; then
        # Export for current session
        export PATH="${gem_bin_dir}:${PATH}"
        success "Gem bin dir added to PATH: ${gem_bin_dir}"

        # Persist to shell rc file for future sessions
        local rc_file=""
        if [ "$ENV" = "termux" ]; then
            rc_file="${HOME}/.bashrc"
        else
            for candidate in "${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.profile"; do
                if [ -f "$candidate" ]; then
                    rc_file="$candidate"
                    break
                fi
            done
        fi

        if [ -n "$rc_file" ] && [ -f "$rc_file" ]; then
            if ! grep -q "gem_bin_dir\|${gem_bin_dir}" "$rc_file" 2>/dev/null; then
                echo "" >> "$rc_file"
                echo "# Added by Pickaxe setup.sh — gem bin directory" >> "$rc_file"
                echo "export PATH=\"${gem_bin_dir}:\$PATH\"" >> "$rc_file"
                info "Persisted gem PATH to: ${rc_file}"
                info "Run: source ${rc_file}  (or open a new terminal)"
            else
                info "Gem PATH already in ${rc_file}"
            fi
        fi
    else
        warn "Could not locate gem bin directory — WhatWeb may not be in PATH"
        warn "Run manually: gem environment gemdir"
    fi
}

# =============================================================================
#  WHATWEB
# =============================================================================
# whatweb isn't always in apt so we fall back to installing via gem
# ruby needs to already be there for this to work obviously
install_whatweb_gem() {
    if ! has ruby; then
        err "Ruby not found — WhatWeb gem install skipped."
        FAILED_TOOLS+=("whatweb")
        return 1
    fi

    info "Installing WhatWeb gem (this may take ~60s)…"
    if gem install whatweb --no-document > "$PICKAXE_LOG" 2>&1; then
        success "WhatWeb installed via gem."
        fix_gem_path  # FIX: immediately export gem PATH
    elif maybe_sudo gem install whatweb --no-document > "$PICKAXE_LOG" 2>&1; then
        success "WhatWeb installed via gem (sudo)."
        fix_gem_path
    else
        err "WhatWeb gem install failed:"
        tail -5 "$PICKAXE_LOG"
        FAILED_TOOLS+=("whatweb")
        return 1
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
    local PKGS=(nmap whois dnsutils python ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if pkg install -y "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed to install ${pkg_name}:"
            tail -5 "$PICKAXE_LOG"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done
}

# ─── Debian / Ubuntu / Kali ───────────────────────────────────────────────────
setup_debian() {
    section "Debian/Ubuntu — Updating APT index"
    maybe_sudo apt-get update -y > "$PICKAXE_LOG" 2>&1 \
        && success "APT index refreshed." \
        || warn "apt-get update returned errors (continuing)."

    section "Debian/Ubuntu — Installing system tools"
    local PKGS=(nmap whois dnsutils python3 python3-pip ruby curl wget)
    info "Packages: ${PKGS[*]}"
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo apt-get install -y "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            tail -3 "$PICKAXE_LOG"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Installing WhatWeb"
    info "Trying: apt-get install whatweb …"
    if maybe_sudo apt-get install -y whatweb > "$PICKAXE_LOG" 2>&1; then
        success "WhatWeb installed via apt."
    else
        warn "Not in apt repos — falling back to RubyGem…"
        install_whatweb_gem
    fi
}

# ─── Arch Linux ───────────────────────────────────────────────────────────────
setup_arch() {
    section "Arch — Syncing pacman repos"
    maybe_sudo pacman -Sy --noconfirm > "$PICKAXE_LOG" 2>&1 \
        && success "pacman synced." \
        || warn "pacman sync issues (continuing)."

    section "Arch — Installing system tools"
    local PKGS=(nmap whois bind python python-pip ruby curl wget)
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo pacman -S --noconfirm "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Installing WhatWeb"
    if maybe_sudo pacman -S --noconfirm whatweb > "$PICKAXE_LOG" 2>&1; then
        success "WhatWeb installed via pacman."
    else
        warn "Not in official repos — falling back to gem…"
        install_whatweb_gem
    fi
}

# ─── RHEL / CentOS / Fedora ───────────────────────────────────────────────────
setup_rhel() {
    local PM="yum"; has dnf && PM="dnf"

    section "RHEL/Fedora — Updating ${PM} repos"
    maybe_sudo $PM makecache -y > "$PICKAXE_LOG" 2>&1 \
        && success "Repo cache updated." \
        || warn "Cache update issues (continuing)."

    section "RHEL/Fedora — Installing system tools"
    local PKGS=(nmap whois bind-utils python3 python3-pip ruby curl wget)
    for pkg_name in "${PKGS[@]}"; do
        info "Installing ${pkg_name}…"
        if maybe_sudo $PM install -y "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Installing WhatWeb"
    install_whatweb_gem
}

# ─── macOS / Homebrew ─────────────────────────────────────────────────────────
setup_macos() {
    # install homebrew if missing — it's the standard package manager on mac
    if ! has brew; then
        warn "Homebrew not found — installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # M1/M2 macs install brew to /opt/homebrew
        if [ -f "/opt/homebrew/bin/brew" ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "${HOME}/.zprofile"
        fi
    fi

    section "macOS — Installing tools via Homebrew"
    local PKGS=(nmap whois bind ruby curl wget)
    for pkg_name in "${PKGS[@]}"; do
        info "brew install ${pkg_name}..."
        if brew install "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            warn "${pkg_name}: brew said it may already be installed"
        fi
    done

    if ! has python3; then
        info "installing python3 via brew..."
        brew install python3 > "$PICKAXE_LOG" 2>&1 && success "python3 installed."
    fi

    section "macOS — Installing WhatWeb"
    install_whatweb_gem
}

# ─── Alpine Linux ─────────────────────────────────────────────────────────────
setup_alpine() {
    section "Alpine — Updating apk"
    maybe_sudo apk update > "$PICKAXE_LOG" 2>&1 \
        && success "apk index updated." \
        || warn "apk update had issues (continuing)."

    section "Alpine — Installing system tools"
    local PKGS=(nmap whois bind-tools python3 py3-pip ruby curl wget)
    for pkg_name in "${PKGS[@]}"; do
        info "apk add ${pkg_name}..."
        if maybe_sudo apk add --no-cache "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "Alpine — Installing WhatWeb"
    install_whatweb_gem
}

# ─── openSUSE / SUSE ──────────────────────────────────────────────────────────
setup_opensuse() {
    section "openSUSE — Refreshing zypper repos"
    maybe_sudo zypper refresh > "$PICKAXE_LOG" 2>&1 \
        && success "repos refreshed." \
        || warn "zypper refresh had issues (continuing)."

    section "openSUSE — Installing system tools"
    local PKGS=(nmap whois bind-utils python3 python3-pip ruby curl wget)
    for pkg_name in "${PKGS[@]}"; do
        info "zypper install ${pkg_name}..."
        if maybe_sudo zypper install -y "$pkg_name" > "$PICKAXE_LOG" 2>&1; then
            success "${pkg_name} installed."
        else
            err "Failed: ${pkg_name}"
            FAILED_TOOLS+=("$pkg_name")
        fi
    done

    section "openSUSE — Installing WhatWeb"
    install_whatweb_gem
}

# ─── Unknown OS ───────────────────────────────────────────────────────────────
setup_unknown() {
    warn "couldn't detect your OS/package manager — skipping OS package install"
    warn "you may need to manually install: nmap whois dig ruby curl wget python3"
    info "supported package managers: apt, pacman, dnf/yum, zypper, apk, brew, pkg (Termux)"
    # don't exit — python package install will still run below
}

# =============================================================================
#  PIP / PYTHON BOOTSTRAPPER
# =============================================================================
bootstrap_pip() {
    section "Python pip check"

    local PY=""
    # find whatever python we have, try newest first
    for candidate in python3 python python3.12 python3.11 python3.10 python3.9; do
        if has "$candidate"; then
            PY="$candidate"
            break
        fi
    done

    if [ -z "$PY" ]; then
        err "Python not found in PATH — cannot continue."
        FAILED_TOOLS+=("python")
        return 1
    fi

    success "Python: $($PY --version 2>&1)"

    if $PY -m pip --version &>/dev/null; then
        success "pip is available."
        return 0
    fi

    info "pip not found — bootstrapping via ensurepip…"
    if $PY -m ensurepip --upgrade > "$PICKAXE_LOG" 2>&1; then
        success "pip bootstrapped via ensurepip."
        return 0
    fi

    warn "ensurepip also broke, downloading get-pip.py the old fashioned way..."
    local GETPIP="${TMPDIR:-/tmp}/get-pip.py"
    if has curl; then
        curl -sSL https://bootstrap.pypa.io/get-pip.py -o "$GETPIP" \
            && $PY "$GETPIP" --quiet \
            && success "pip installed via get-pip.py." \
            && return 0
    elif has wget; then
        wget -qO "$GETPIP" https://bootstrap.pypa.io/get-pip.py \
            && $PY "$GETPIP" --quiet \
            && success "pip installed via get-pip.py." \
            && return 0
    fi

    err "Could not install pip. Python packages will not be installed."
    FAILED_TOOLS+=("pip")
}

# python packages install
# kali/debian block pip with "externally-managed-environment" since 2023
# try apt first, then --break-system-packages, then --user as fallback
# no venv needed with any of these
install_python_packages() {
    section "Python packages"

    local PY=""
    for candidate in python3 python python3.12 python3.11 python3.10 python3.9; do
        if has "$candidate"; then PY="$candidate"; break; fi
    done

    if [ -z "$PY" ]; then
        err "Python not found — skipping package install."
        return 1
    fi

    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local REQ="${SCRIPT_DIR}/requirements.txt"

    # ── Collect packages to install ──────────────────────────────────────────
    local PKGS=()
    if [ -f "$REQ" ]; then
        info "Reading packages from: ${REQ}"
        while IFS= read -r line; do
            # Skip blank lines and comment lines (POSIX-safe case match)
            case "$line" in
                ""|\#*) continue ;;
            esac
            PKGS+=("$line")
        done < "$REQ"
    else
        warn "requirements.txt not found — installing 'rich' directly"
        PKGS=("rich>=13.7.0")
    fi

    info "Packages to install: ${PKGS[*]}"
    echo ""

    # try OS package manager first — cleanest, avoids pip + PEP 668 entirely
    case "$ENV" in
        debian | kali)
            info "trying apt for python packages..."
            local APT_ALL_OK=true
            for pkg in "${PKGS[@]}"; do
                local base_name
                base_name=$(echo "$pkg" | sed 's/[><=!].*//' | tr '[:upper:]' '[:lower:]')
                local apt_pkg=""
                case "$base_name" in
                    rich)       apt_pkg="python3-rich"      ;;
                    requests)   apt_pkg="python3-requests"  ;;
                    colorama)   apt_pkg="python3-colorama"  ;;
                    dnspython)  apt_pkg="python3-dnspython" ;;
                    *)          apt_pkg=""                  ;;
                esac
                if [ -n "$apt_pkg" ]; then
                    info "apt: ${apt_pkg}..."
                    if maybe_sudo apt-get install -y "$apt_pkg" > "$PICKAXE_LOG" 2>&1; then
                        success "${apt_pkg} installed."
                    else
                        APT_ALL_OK=false
                    fi
                else
                    APT_ALL_OK=false
                fi
            done
            if [ "$APT_ALL_OK" = true ]; then
                success "all packages installed via apt"
                return 0
            fi
            ;;
        alpine)
            info "trying apk for python packages..."
            # alpine has py3-rich in the community repo
            if maybe_sudo apk add --no-cache py3-rich > "$PICKAXE_LOG" 2>&1; then
                success "rich installed via apk"
                return 0
            fi
            ;;
        macos)
            # brew python doesn't have the PEP 668 venv restriction
            info "pip install (brew python, no venv needed)..."
            if $PY -m pip install --quiet "${PKGS[@]}" > "$PICKAXE_LOG" 2>&1; then
                success "packages installed"
                return 0
            fi
            ;;
    esac


    # kali/debian: use --break-system-packages to bypass the venv requirement
    info "trying pip install --break-system-packages..."
    if $PY -m pip install --break-system-packages --quiet "${PKGS[@]}" \
        > "$PICKAXE_LOG" 2>&1; then
        success "packages installed (--break-system-packages)"
        return 0
    fi

    # last resort: per-user install, always works
    warn "trying --user install..."
    if $PY -m pip install --user --quiet "${PKGS[@]}" > "$PICKAXE_LOG" 2>&1; then
        success "packages installed (~/.local)"
        local LOCAL_BIN="${HOME}/.local/bin"
        if [ -d "$LOCAL_BIN" ] && [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
            export PATH="${LOCAL_BIN}:${PATH}"
        fi
        return 0
    fi

    # all three methods failed, print hints
    err "could not install packages, try one of these manually:"
    echo ""
    echo -e "  ${CYAN}sudo apt install python3-rich${NC}"
    echo -e "  ${CYAN}pip install rich --break-system-packages${NC}"
    echo -e "  ${CYAN}pip install rich --user${NC}"
    echo ""
    FAILED_TOOLS+=("python-packages")
}

# =============================================================================
#  FILE PERMISSIONS
# =============================================================================
set_permissions() {
    section "Setting file permissions"
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local TARGET="${SCRIPT_DIR}/hybrid_osint.py"
    if [ -f "$TARGET" ]; then
        chmod +x "$TARGET"
        success "hybrid_osint.py → executable (+x)"
    else
        warn "hybrid_osint.py not found at ${SCRIPT_DIR} — skipping chmod."
    fi
}

# =============================================================================
#  REPAIR MODE
# =============================================================================
# run with --repair to only install what's missing
# useful when one thing broke and you don't wanna reinstall everything
repair_missing() {
    section "REPAIR MODE — Checking for missing tools"

    local needs_work=false

    # Check nmap
    if ! has nmap; then
        warn "nmap is missing — installing…"
        needs_work=true
        case "$ENV" in
            termux)         pkg install -y nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
            debian | kali)  maybe_sudo apt-get install -y nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
            arch)           maybe_sudo pacman -S --noconfirm nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
            rhel | fedora)  local PM="yum"; has dnf && PM="dnf"; maybe_sudo $PM install -y nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
            macos)          brew install nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || warn "brew: nmap may already be installed" ;;
            alpine)         maybe_sudo apk add --no-cache nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
            opensuse)       maybe_sudo zypper install -y nmap > "$PICKAXE_LOG" 2>&1 && success "nmap installed." || { err "nmap failed."; FAILED_TOOLS+=("nmap"); } ;;
        esac
    else
        success "nmap already installed: $(command -v nmap)"
    fi

    # Check whois
    if ! has whois; then
        warn "whois is missing — installing…"
        needs_work=true
        case "$ENV" in
            termux)         pkg install -y whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
            debian | kali)  maybe_sudo apt-get install -y whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
            arch)           maybe_sudo pacman -S --noconfirm whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
            rhel | fedora)  local PM="yum"; has dnf && PM="dnf"; maybe_sudo $PM install -y whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
            macos)          brew install whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || warn "brew: whois may already be installed" ;;
            alpine)         maybe_sudo apk add --no-cache whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
            opensuse)       maybe_sudo zypper install -y whois > "$PICKAXE_LOG" 2>&1 && success "whois installed." || { err "whois failed."; FAILED_TOOLS+=("whois"); } ;;
        esac
    else
        success "whois already installed: $(command -v whois)"
    fi

    # Check dig (dnsutils)
    if ! has dig; then
        warn "dig is missing — installing dnsutils…"
        needs_work=true
        case "$ENV" in
            termux)         pkg install -y dnsutils > "$PICKAXE_LOG" 2>&1 && success "dnsutils installed." || { err "dnsutils failed."; FAILED_TOOLS+=("dig"); } ;;
            debian | kali)  maybe_sudo apt-get install -y dnsutils > "$PICKAXE_LOG" 2>&1 && success "dnsutils installed." || { err "dnsutils failed."; FAILED_TOOLS+=("dig"); } ;;
            arch)           maybe_sudo pacman -S --noconfirm bind > "$PICKAXE_LOG" 2>&1 && success "bind installed." || { err "bind failed."; FAILED_TOOLS+=("dig"); } ;;
            rhel | fedora)  local PM="yum"; has dnf && PM="dnf"; maybe_sudo $PM install -y bind-utils > "$PICKAXE_LOG" 2>&1 && success "bind-utils installed." || { err "bind-utils failed."; FAILED_TOOLS+=("dig"); } ;;
            macos)          brew install bind > "$PICKAXE_LOG" 2>&1 && success "bind/dig installed." || warn "brew: bind may already be installed" ;;
            alpine)         maybe_sudo apk add --no-cache bind-tools > "$PICKAXE_LOG" 2>&1 && success "bind-tools installed." || { err "bind-tools failed."; FAILED_TOOLS+=("dig"); } ;;
            opensuse)       maybe_sudo zypper install -y bind-utils > "$PICKAXE_LOG" 2>&1 && success "bind-utils installed." || { err "bind-utils failed."; FAILED_TOOLS+=("dig"); } ;;
        esac
    else
        success "dig already installed: $(command -v dig)"
    fi

    # Check whatweb
    if ! has whatweb; then
        warn "whatweb is missing — installing…"
        needs_work=true
        case "$ENV" in
            debian | kali)
                if maybe_sudo apt-get install -y whatweb > "$PICKAXE_LOG" 2>&1; then
                    success "whatweb installed via apt."
                else
                    install_whatweb_gem
                fi ;;
            arch)
                if maybe_sudo pacman -S --noconfirm whatweb > "$PICKAXE_LOG" 2>&1; then
                    success "whatweb installed via pacman."
                else
                    install_whatweb_gem
                fi ;;
            *)  install_whatweb_gem ;;
        esac
    else
        success "whatweb already installed: $(command -v whatweb)"
    fi

    # Check ping
    if ! has ping; then
        warn "ping is missing — installing…"
        needs_work=true
        case "$ENV" in
            termux)         pkg install -y iputils > "$PICKAXE_LOG" 2>&1 && success "iputils installed." || { err "iputils failed."; FAILED_TOOLS+=("ping"); } ;;
            debian | kali)  maybe_sudo apt-get install -y iputils-ping > "$PICKAXE_LOG" 2>&1 && success "iputils-ping installed." || { err "iputils-ping failed."; FAILED_TOOLS+=("ping"); } ;;
            arch)           maybe_sudo pacman -S --noconfirm iputils > "$PICKAXE_LOG" 2>&1 && success "iputils installed." || { err "iputils failed."; FAILED_TOOLS+=("ping"); } ;;
            rhel | fedora)  local PM="yum"; has dnf && PM="dnf"; maybe_sudo $PM install -y iputils > "$PICKAXE_LOG" 2>&1 && success "iputils installed." || { err "iputils failed."; FAILED_TOOLS+=("ping"); } ;;
            macos)          success "ping is built-in on macOS" ;;
            alpine)         maybe_sudo apk add --no-cache iputils > "$PICKAXE_LOG" 2>&1 && success "iputils installed." || { err "iputils failed."; FAILED_TOOLS+=("ping"); } ;;
            opensuse)       maybe_sudo zypper install -y iputils > "$PICKAXE_LOG" 2>&1 && success "iputils installed." || { err "iputils failed."; FAILED_TOOLS+=("ping"); } ;;
        esac
    else
        success "ping already installed: $(command -v ping)"
    fi

    # Check Python packages
    local PY=""
    for candidate in python3 python; do has "$candidate" && PY="$candidate" && break; done
    if [ -n "$PY" ]; then
        if ! $PY -c "import rich" 2>/dev/null; then
            warn "Python 'rich' package missing — installing…"
            needs_work=true
            # try OS package manager first
            case "$ENV" in
                debian | kali) maybe_sudo apt-get install -y python3-rich > "$PICKAXE_LOG" 2>&1 && success "rich installed via apt." && continue 2>/dev/null ;;
                alpine)        maybe_sudo apk add --no-cache py3-rich > "$PICKAXE_LOG" 2>&1 && success "rich installed via apk." && continue 2>/dev/null ;;
            esac
            $PY -m pip install rich --break-system-packages --quiet 2>/dev/null \
                || $PY -m pip install rich --user --quiet \
                && success "rich installed." \
                || { err "rich install failed."; FAILED_TOOLS+=("rich"); }
        else
            success "Python 'rich' package already installed."
        fi
    fi

    if [ "$needs_work" = false ]; then
        echo ""
        echo -e "  ${GREEN}All tools are already installed! Nothing to repair.${NC}"
    fi
}

# =============================================================================
#  FINAL VERIFICATION TABLE
# =============================================================================
verify_all() {
    section "Verification — Checking all tools"

    local ALL_OK=true
    printf "\n  %-12s  %s\n" "Tool" "Status"
    printf "  %-12s  %s\n" "────────────" "──────────────────────────────────"

    for label in nmap whois dig whatweb ping python pip ruby gem; do
        local candidates=""
        case "$label" in
            python) candidates="python3 python" ;;
            pip)    candidates="pip3 pip"       ;;
            *)      candidates="$label"         ;;
        esac

        local FOUND=""
        for c in $candidates; do
            if has "$c"; then
                FOUND="$c  ($(command -v "$c"))"
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

    [ "$ALL_OK" = true ]
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
        echo -e "  ${CYAN}python hybrid_osint.py --check${NC}              # verify env"
        echo -e "  ${CYAN}python hybrid_osint.py example.com${NC}          # full scan"
        echo -e "  ${CYAN}python hybrid_osint.py --profile quick t.com${NC} # fast scan"
        echo -e "  ${CYAN}python hybrid_osint.py --help${NC}               # usage guide"
    else
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║   ⚠  SETUP FINISHED — Some tools had issues         ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        err  "Failed to install: ${FAILED_TOOLS[*]}"
        echo ""
        echo -e "  ${BOLD}Troubleshooting:${NC}"
        echo -e "  • Check your internet connection."
        echo -e "  • Debian/Kali:  ${CYAN}sudo apt-get install -f${NC}"
        echo -e "  • Termux:       ${CYAN}pkg install ruby && gem install whatweb --no-document${NC}"
        echo -e "  • macOS:        ${CYAN}brew install nmap whois bind && pip install rich${NC}"
        echo -e "  • Alpine:       ${CYAN}apk add nmap whois bind-tools py3-rich${NC}"
        echo -e "  • openSUSE:     ${CYAN}zypper install nmap whois bind-utils python3-pip${NC}"
        echo -e "  • Run repair:   ${CYAN}bash setup.sh --repair${NC}"
        echo -e "  • Pickaxe auto-skips missing tools at runtime."
    fi
    echo ""
    echo -e "  ${BOLD}Gem PATH note (Termux/Linux):${NC}"
    echo -e "  If WhatWeb is not found after install, run:"
    echo -e "  ${CYAN}source ~/.bashrc${NC}  (or open a new terminal)"
    echo ""
}

# =============================================================================
#  MAIN ENTRY POINT
# =============================================================================
main() {
    print_banner

    local MODE="${1:-install}"

    # ── Check-only mode ───────────────────────────────────────────────────────
    if [ "$MODE" = "--check" ]; then
        info "CHECK mode — no packages will be installed."
        if verify_all; then
            echo -e "\n  ${GREEN}All tools found! Pickaxe is ready.${NC}"
            exit 0
        else
            echo -e "\n  ${YELLOW}Some tools are missing. Run: bash setup.sh${NC}"
            exit 1
        fi
    fi

    # ── Repair mode — only install what's missing ─────────────────────────────
    # FIX: --repair was previously undocumented/non-functional
    if [ "$MODE" = "--repair" ]; then
        info "REPAIR mode — installing only missing tools."
        echo -e "  ${BOLD}Detected environment:${NC} ${YELLOW}${ENV}${NC}"
        echo ""
        repair_missing
        fix_gem_path
        bootstrap_pip
        install_python_packages
        verify_all || true
        print_summary
        exit 0
    fi

    # ── Environment banner ────────────────────────────────────────────────────
    echo -e "  ${BOLD}Detected environment:${NC} ${YELLOW}${ENV}${NC}"
    echo ""

    # ── Step 1 — OS packages ──────────────────────────────────────────────────
    case "$ENV" in
        termux)        setup_termux   ;;
        debian | kali) setup_debian   ;;
        arch)          setup_arch     ;;
        rhel | fedora) setup_rhel     ;;
        macos)         setup_macos    ;;
        alpine)        setup_alpine   ;;
        opensuse)      setup_opensuse ;;
        *)             setup_unknown  ;;
    esac

    # ── WhatWeb on Termux needs gem (not in pkg repos) ────────────────────────
    if [ "$ENV" = "termux" ] && ! has whatweb; then
        section "Termux — Installing WhatWeb via gem"
        install_whatweb_gem
    fi

    # FIX: Always run fix_gem_path after setup so WhatWeb is in PATH
    fix_gem_path

    # ── Step 2 — Bootstrap pip ────────────────────────────────────────────────
    bootstrap_pip

    # ── Step 3 — Python packages ──────────────────────────────────────────────
    install_python_packages

    # ── Step 4 — File permissions ─────────────────────────────────────────────
    set_permissions

    # ── Step 5 — Verify ───────────────────────────────────────────────────────
    verify_all || true  # don't exit on verify failure — summary handles it

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary
}

main "${1:-}"
