#!/usr/bin/env python3
# =============================================================================
#  ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
#  ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
#  ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
#  ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
#  ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
#  ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
#
#  Hybrid OSINT & Website Reconnaissance Utility
#  Version : 3.0.0
#  Author  : Pickaxe Project
#  License : MIT
#  Target  : Termux (Android) | Linux
#
#  v3.0 Changes:
#   - Python 3.9 compatibility fix (from __future__ import annotations)
#   - Termux: nmap uses -sT (no root needed), gem PATH auto-fixed
#   - asyncio.gather uses return_exceptions=True (no crash on partial fail)
#   - Fixed --skip / --profile / --timeout CLI parser
#   - Fixed ping platform flags, CVE parser, dig regex
#   - NEW: SSL/TLS inspector, HTTP security headers, subdomain enum
#   - NEW: GeoIP lookup (ip-api.com, no key), phishing risk scoring
#   - NEW: --output (JSON/TXT), --profile presets, --timeout
# =============================================================================

from __future__ import annotations  # Enables Python 3.9 compat for all type hints

import asyncio
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl as ssl_lib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────────────────────────────────────
#  VERSION
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "3.0.0"

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL THEME & CONSOLE
# ─────────────────────────────────────────────────────────────────────────────

CUSTOM_THEME = Theme({
    "banner":       "bold bright_cyan",
    "header":       "bold bright_white",           # hex bg removed — breaks non-truecolor terminals
    "success":      "bold bright_green",
    "warning":      "bold yellow",
    "error":        "bold bright_red",
    "info":         "bold bright_blue",
    "muted":        "dim white",
    "field":        "bold cyan",
    "value":        "bright_white",
    "section":      "bold magenta",
    "cve":          "bold bright_red",              # hex bg removed — breaks non-truecolor terminals
    "port_open":    "bold green",
    "port_closed":  "dim red",
    "dns_record":   "bright_yellow",
    "cms":          "bold bright_magenta",
    "highlight":    "bold bright_cyan",             # hex bg removed — breaks non-truecolor terminals
    "phish_low":    "bold bright_green",
    "phish_sus":    "bold yellow",
    "phish_likely": "bold orange1",
    "phish_high":   "bold bright_red",
    "ssl_good":     "bold bright_green",
    "ssl_warn":     "bold yellow",
    "ssl_bad":      "bold bright_red",
    "hdr_good":     "bold bright_green",
    "hdr_miss":     "bold yellow",
    "geo_info":     "bold bright_cyan",
    "sub_found":    "bold bright_green",
})

console = Console(theme=CUSTOM_THEME, highlight=False)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS — PHISHING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".cc", ".icu", ".loan", ".work", ".party", ".date", ".racing",
    ".download", ".accountant", ".trade", ".science", ".stream", ".faith",
    ".gdn", ".win", ".review", ".bid", ".men", ".webcam", ".cricket",
    ".email", ".space", ".site", ".online", ".fun", ".vip", ".rest",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "account", "secure", "security",
    "update", "verify", "verification", "confirm", "confirmation", "bank",
    "banking", "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "instagram", "twitter", "netflix", "ebay", "wallet", "crypto", "bitcoin",
    "password", "credential", "support", "helpdesk", "service", "official",
    "authenticate", "invoice", "payment", "transfer", "recover", "recovery",
    "alert", "notice", "suspended", "blocked", "unlock", "validate",
]

KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "instagram", "twitter", "netflix", "ebay", "chase", "wellsfargo",
    "bankofamerica", "citibank", "americanexpress", "visa", "mastercard",
    "dropbox", "linkedin", "yahoo", "outlook", "hotmail", "gmail",
    "whatsapp", "telegram", "tiktok", "youtube", "spotify", "adobe",
    "salesforce", "wordpress", "binance", "coinbase", "stripe",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "shop", "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "cdn", "static", "assets", "images", "img", "video", "media",
    "m", "mobile", "app", "dashboard", "login", "secure", "help", "support",
    "docs", "wiki", "forum", "news", "store", "pay", "billing", "status",
    "monitor", "git", "gitlab", "jenkins", "ns1", "ns2", "mx", "mx1", "mx2",
    "cpanel", "whm", "autodiscover", "autoconfig", "pop3", "smtp2", "cloud",
    "download", "uploads", "files", "backup", "db", "mysql", "data",
]

SECURITY_HEADERS: Dict[str, Tuple[str, str]] = {
    "Strict-Transport-Security":    ("HSTS",     "Enforces HTTPS connections"),
    "Content-Security-Policy":      ("CSP",      "Controls resources browser can load"),
    "X-Frame-Options":              ("XFO",      "Prevents clickjacking attacks"),
    "X-Content-Type-Options":       ("XCTO",     "Prevents MIME-type sniffing"),
    "Referrer-Policy":              ("Ref-Pol",  "Controls referrer header info"),
    "Permissions-Policy":           ("Perm-Pol", "Controls browser API access"),
    "X-XSS-Protection":             ("XSS-Prot", "Legacy XSS browser filter"),
    "Cross-Origin-Opener-Policy":   ("COOP",     "Isolates browsing context"),
    "Cross-Origin-Resource-Policy": ("CORP",     "Controls cross-origin resource sharing"),
}

# ─────────────────────────────────────────────────────────────────────────────
#  REQUIRED TOOLS
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_TOOLS: Dict[str, Dict[str, str]] = {
    "nmap": {
        "termux": "pkg install nmap",
        "apt":    "sudo apt install nmap",
        "yum":    "sudo yum install nmap",
        "pacman": "sudo pacman -S nmap",
    },
    "whois": {
        "termux": "pkg install whois",
        "apt":    "sudo apt install whois",
        "yum":    "sudo yum install whois",
        "pacman": "sudo pacman -S whois",
    },
    "dig": {
        "termux": "pkg install dnsutils",
        "apt":    "sudo apt install dnsutils",
        "yum":    "sudo yum install bind-utils",
        "pacman": "sudo pacman -S bind",
    },
    "whatweb": {
        "termux": "pkg install ruby && gem install whatweb --no-document",
        "apt":    "sudo apt install whatweb",
        "yum":    "gem install whatweb --no-document",
        "pacman": "gem install whatweb --no-document",
    },
    "ping": {
        "termux": "pkg install iputils",
        "apt":    "sudo apt install iputils-ping",
        "yum":    "sudo yum install iputils",
        "pacman": "sudo pacman -S iputils",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  DATA CONTAINERS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:     str = ""
    ip_address: str = ""
    timestamp:  str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Nmap
    nmap_raw:   str            = ""
    open_ports: List[Dict]     = field(default_factory=list)
    cve_flags:  List[str]      = field(default_factory=list)
    os_guess:   str            = ""
    host_state: str            = ""

    # WHOIS
    whois_raw:    str       = ""
    registrar:    str       = ""
    reg_date:     str       = ""
    exp_date:     str       = ""
    updated_date: str       = ""
    name_servers: List[str] = field(default_factory=list)
    org:          str       = ""
    country:      str       = ""
    abuse_email:  str       = ""

    # DNS / DIG
    dig_raw:      str        = ""
    a_records:    List[str]  = field(default_factory=list)
    aaaa_records: List[str]  = field(default_factory=list)
    mx_records:   List[Dict] = field(default_factory=list)
    ns_records:   List[str]  = field(default_factory=list)
    txt_records:  List[str]  = field(default_factory=list)
    cname:        str        = ""
    soa:          str        = ""

    # WhatWeb
    whatweb_raw: str       = ""
    cms:         str       = ""
    server:      str       = ""
    tech_stack:  List[str] = field(default_factory=list)
    powered_by:  str       = ""
    http_status: str       = ""
    page_title:  str       = ""
    cookies:     List[str] = field(default_factory=list)

    # Ping
    ping_latency: str = ""
    ping_loss:    str = ""
    ping_ttl:     str = ""

    # SSL / TLS
    ssl_valid:     bool      = False
    ssl_subject:   str       = ""
    ssl_issuer:    str       = ""
    ssl_expires:   str       = ""
    ssl_days_left: int       = -1
    ssl_sans:      List[str] = field(default_factory=list)
    ssl_cipher:    str       = ""
    ssl_version:   str       = ""
    ssl_error:     str       = ""

    # HTTP Security Headers
    sec_headers: Dict[str, str] = field(default_factory=dict)  # header_name → "PRESENT"/"MISSING"

    # Subdomain Enumeration
    subdomains_found: List[str] = field(default_factory=list)

    # GeoIP
    geo_country: str = ""
    geo_region:  str = ""
    geo_city:    str = ""
    geo_isp:     str = ""
    geo_org:     str = ""
    geo_asn:     str = ""

    # Phishing Analysis
    phishing_score:      int       = 0
    phishing_level:      str       = ""
    phishing_indicators: List[str] = field(default_factory=list)
    phishing_safe:       List[str] = field(default_factory=list)

    # Errors per module
    errors: Dict[str, str] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
#  PLATFORM HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def is_termux() -> bool:
    """Detect Termux (Android) environment."""
    return bool(os.environ.get("TERMUX_VERSION") or os.path.isdir("/data/data/com.termux"))


def is_root() -> bool:
    """Check if running as root (uid 0)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows — getuid not available


def _fix_gem_path() -> None:
    """
    Termux (and some Linux) installs gem binaries to paths outside $PATH.
    Auto-detect gem bin directories and prepend them so WhatWeb is found.
    """
    # Method 1: Ask gem directly
    try:
        r = subprocess.run(
            ["gem", "environment", "gempath"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            for gem_path in r.stdout.strip().split(":"):
                bin_dir = os.path.join(gem_path.strip(), "bin")
                if os.path.isdir(bin_dir) and bin_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass

    # Method 2: Glob ~/.gem/ruby/*/bin
    try:
        for gem_bin in sorted(Path.home().glob(".gem/ruby/*/bin"), reverse=True):
            bin_str = str(gem_bin)
            if os.path.isdir(bin_str) and bin_str not in os.environ.get("PATH", ""):
                os.environ["PATH"] = bin_str + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass

    # Method 3: Termux prefix gem paths
    if is_termux():
        termux_prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
        for candidate in [
            os.path.join(termux_prefix, "lib", "ruby", "gems"),
            os.path.join(termux_prefix, "share", "gem", "bin"),
        ]:
            if os.path.isdir(candidate):
                for sub in os.listdir(candidate):
                    bin_dir = os.path.join(candidate, sub, "bin")
                    if os.path.isdir(bin_dir) and bin_dir not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")


# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY CHECKER
# ─────────────────────────────────────────────────────────────────────────────

def _detect_pkg_manager() -> str:
    for pm in ("pkg", "apt", "yum", "pacman"):
        if shutil.which(pm):
            return pm
    return "apt"


def check_dependencies(tools: Optional[List[str]] = None) -> Tuple[List[str], List[str]]:
    """Validate required system tools exist in $PATH. Returns (found, missing)."""
    check_list = tools or list(REQUIRED_TOOLS.keys())
    found:   List[str] = []
    missing: List[str] = []
    for tool in check_list:
        binary = "dig" if tool == "dig" else tool
        if shutil.which(binary):
            found.append(tool)
        else:
            missing.append(tool)
    return found, missing


def print_dependency_report() -> bool:
    """Print a rich dependency check table. Returns True if all satisfied."""
    found, missing = check_dependencies()
    tbl = Table(
        title="[header] System Dependency Check [/header]",
        box=box.ROUNDED, show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_blue", expand=False,
    )
    tbl.add_column("Tool",   style="field",  width=12)
    tbl.add_column("Status", style="value",  width=14)
    tbl.add_column("Binary Path / Note",      width=48)

    for tool in REQUIRED_TOOLS:
        if tool in found:
            binary = shutil.which("dig" if tool == "dig" else tool) or "in PATH"
            tbl.add_row(tool, "[success]✔  Found[/success]", f"[muted]{binary}[/muted]")
        else:
            tbl.add_row(tool, "[error]✘  Missing[/error]", "[yellow]run: bash setup.sh[/yellow]")

    console.print(tbl)
    return len(missing) == 0


def _find_setup_sh() -> Optional[Path]:
    for p in (Path(__file__).parent / "setup.sh", Path.cwd() / "setup.sh"):
        if p.is_file():
            return p
    return None


def auto_install_prompt(missing: List[str]) -> bool:
    """Offer to run setup.sh when dependencies are missing."""
    setup_path = _find_setup_sh()
    console.print()
    console.print(Panel(
        f"[error]✘  Missing tools:[/error] [bold]{', '.join(missing)}[/bold]\n\n"
        "[info]Pickaxe can install everything automatically right now.[/info]\n"
        f"  Setup script: [cyan]{setup_path or 'setup.sh (not found in current dir)'}[/cyan]",
        title="[warning]⚠  Dependencies Missing[/warning]",
        border_style="yellow",
    ))
    if not setup_path:
        console.print("[error]setup.sh not found.[/error] Clone the full repo and run [cyan]bash setup.sh[/cyan].")
        return False
    if not sys.stdin.isatty():
        console.print("[muted]Non-interactive mode — skipping auto-install.[/muted]")
        return False
    try:
        answer = console.input(
            "\n  [bold bright_cyan]Install all dependencies now?[/bold bright_cyan] [bold](y/N):[/bold] "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[muted]Skipped.[/muted]")
        return False
    if answer not in ("y", "yes"):
        console.print("[muted]Skipped. Run [cyan]bash setup.sh[/cyan] manually, then retry.[/muted]")
        return False
    console.print()
    console.print(Rule("[info]Running setup.sh[/info]", style="bright_blue"))
    try:
        ret = subprocess.run(["bash", str(setup_path)], check=False)
        if ret.returncode == 0:
            console.print("[success]✔  setup.sh completed. Re-checking dependencies…[/success]")
            return True
        console.print(f"[error]✘  setup.sh exited with code {ret.returncode}.[/error]")
        return False
    except FileNotFoundError:
        console.print("[error]✘  bash not found — cannot run setup.sh.[/error]")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  ASYNC SUBPROCESS HELPER
# ─────────────────────────────────────────────────────────────────────────────

async def _run_subprocess(cmd: List[str], timeout: int = 120) -> Tuple[str, str]:
    """Async subprocess wrapper. Returns (stdout, stderr). Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        return "", f"[TIMEOUT] '{' '.join(cmd)}' exceeded {timeout}s"
    except FileNotFoundError:
        return "", f"[NOT FOUND] '{cmd[0]}' binary not in PATH"
    except Exception as exc:
        return "", f"[ERROR] {exc}"


# ─────────────────────────────────────────────────────────────────────────────
#  SYNC HELPERS — run in thread executor (blocking I/O)
# ─────────────────────────────────────────────────────────────────────────────

def _ssl_check_sync(hostname: str) -> Dict[str, Any]:
    """Blocking SSL certificate inspection. Returns a dict of cert info."""
    try:
        ctx = ssl_lib.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                ver    = ssock.version()

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                expire_str = cert.get("notAfter", "")
                days_left  = -1
                if expire_str:
                    try:
                        exp_dt    = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                        # datetime.utcnow() is deprecated in 3.12, use timezone-aware version
                        days_left = (exp_dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
                    except ValueError:
                        pass

                return {
                    "valid":     True,
                    "subject":   subject.get("commonName", ""),
                    "issuer":    issuer.get("organizationName", issuer.get("commonName", "")),
                    "expires":   expire_str,
                    "days_left": days_left,
                    "sans":      sans,
                    "cipher":    cipher[0] if cipher else "",
                    "tls":       ver or "",
                }
    except ssl_lib.SSLCertVerificationError as exc:
        return {"valid": False, "error": f"Verification failed: {exc}"}
    except ssl_lib.SSLError as exc:
        return {"valid": False, "error": f"SSL error: {exc}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"valid": False, "error": f"Connection failed: {exc}"}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def _http_headers_sync(hostname: str, use_https: bool = True) -> Dict[str, Any]:
    """Blocking HTTP HEAD request to retrieve response headers."""
    try:
        if use_https:
            ctx  = ssl_lib.create_default_context()
            conn = http.client.HTTPSConnection(hostname, 443, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(hostname, 80, timeout=10)
        conn.request("HEAD", "/", headers={"User-Agent": f"Pickaxe-OSINT/{VERSION}"})
        resp    = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
        return {"status": resp.status, "headers": headers}
    except Exception as exc:
        return {"error": str(exc)}


def _geoip_sync(ip: str) -> Dict[str, Any]:
    """GeoIP lookup via ip-api.com — free, no API key, 45 req/min limit."""
    fields = "status,message,country,regionName,city,isp,org,as,query"
    url    = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"Pickaxe-OSINT/{VERSION}"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
            return {"error": data.get("message", "GeoIP lookup failed")}
    except urllib.error.URLError as exc:
        return {"error": f"Network error: {exc}"}
    except Exception as exc:
        return {"error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
#  ASYNC SCAN RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

async def run_nmap(target: str, result: ScanResult, timeout: int = 240) -> None:
    """Full TCP scan + version detection + vuln scripts. Termux/non-root safe."""
    console.log("[info]↳ Nmap:[/info] launching...")

    non_root = is_termux() or not is_root()
    if non_root:
        # non-root requires TCP connect on specific ports
        flags = ["-sT", "-sV", "--open", "-T4",
                 "-p", "21,22,23,25,80,443,3306,3389,5432,6379,8080,8443,8888,9200",
                 "-oN", "-"]
        console.log("[warning]↳ Nmap:[/warning] non-root — TCP connect on common ports, OS detection skipped")
    else:
        # root mode allows faster SYN scans
        flags = ["-sS", "-sV", "-O", "--open", "-T4", "-oN", "-"]

    stdout, stderr = await _run_subprocess(["nmap"] + flags + [target], timeout=timeout)

    if stderr and not stdout:
        result.errors["nmap"] = stderr.strip()
        console.log(f"[error]Nmap error:[/error] {stderr.strip()[:120]}")
        return

    result.nmap_raw = stdout
    _parse_nmap(stdout, result)
    console.log(f"[success]↳ Nmap:[/success] complete — {len(result.open_ports)} open port(s)")


async def run_whois(target: str, result: ScanResult, timeout: int = 30) -> None:
    """WHOIS domain registration data."""
    console.log("[info]↳ WHOIS:[/info] launching...")
    stdout, stderr = await _run_subprocess(["whois", target], timeout=timeout)
    if stderr and not stdout:
        result.errors["whois"] = stderr.strip()
        console.log(f"[error]WHOIS error:[/error] {stderr.strip()[:120]}")
        return
    result.whois_raw = stdout
    _parse_whois(stdout, result)
    console.log("[success]↳ WHOIS:[/success] complete")


async def run_dig(target: str, result: ScanResult, timeout: int = 20) -> None:
    """DNS enumeration — A, AAAA, MX, NS, TXT, CNAME, SOA records."""
    console.log("[info]↳ DNS:[/info] launching...")

    async def _dig(qtype: str) -> str:
        out, _ = await _run_subprocess(
            ["dig", "+noall", "+answer", target, qtype], timeout=timeout
        )
        return out

    records = await asyncio.gather(
        _dig("A"), _dig("AAAA"), _dig("MX"),
        _dig("NS"), _dig("TXT"), _dig("CNAME"), _dig("SOA"),
    )
    result.dig_raw = "\n".join(records)
    _parse_dig(records, result)
    console.log(f"[success]↳ DNS:[/success] complete — {len(result.a_records)} A, {len(result.mx_records)} MX")


async def run_whatweb(target: str, result: ScanResult, timeout: int = 60) -> None:
    """WhatWeb technology fingerprinting with fallback mode."""
    console.log("[info]↳ WhatWeb:[/info] launching...")
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"

    # Try brief mode first
    stdout, stderr = await _run_subprocess(
        ["whatweb", "-a", "3", "--log-brief=-", url], timeout=timeout
    )

    # Fallback to plain mode if brief returns nothing useful
    if not stdout or stdout.strip() in ("", url):
        stdout2, stderr2 = await _run_subprocess(
            ["whatweb", "-a", "3", url], timeout=timeout
        )
        if stdout2 and len(stdout2) > len(stdout):
            stdout, stderr = stdout2, stderr2

    if stderr and not stdout:
        result.errors["whatweb"] = stderr.strip()
        console.log(f"[error]WhatWeb error:[/error] {stderr.strip()[:120]}")
        return

    result.whatweb_raw = stdout
    _parse_whatweb(stdout, result)
    console.log(f"[success]↳ WhatWeb:[/success] complete — CMS: {result.cms or 'unknown'}")


async def run_ping(target: str, result: ScanResult) -> None:
    """ICMP latency check — platform-aware flags for Termux/Linux/macOS."""
    console.log("[info]↳ Ping:[/info] launching...")

    # Build platform-correct ping command
    if platform.system() == "Darwin":
        # macOS: -W timeout in ms, requires integer
        cmd = ["ping", "-c", "4", "-W", "2000", target]
    else:
        # Linux / Termux / BSD: -W timeout in seconds
        cmd = ["ping", "-c", "4", "-W", "3", target]

    stdout, stderr = await _run_subprocess(cmd, timeout=20)

    if not stdout:
        result.errors["ping"] = stderr.strip() or "No ICMP response"
        result.ping_latency   = "N/A"
        result.ping_loss      = "100%"
        console.log("[warning]↳ Ping:[/warning] no response — ICMP may be filtered")
        return

    # Linux/Termux: "rtt min/avg/max/mdev = 1.2/2.3/3.4/0.5 ms"
    rtt = re.search(r"rtt min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/", stdout)
    if not rtt:
        # macOS: "round-trip min/avg/max/stddev = 1.2/2.3/3.4/0.5 ms"
        rtt = re.search(r"round-trip min/avg/max/\S+\s*=\s*[\d.]+/([\d.]+)/", stdout)

    result.ping_latency = (f"{rtt.group(1)} ms") if rtt else "?"
    result.ping_loss    = _extract(r"([\d.]+)%\s+packet loss", stdout) or "0%"
    result.ping_ttl     = _extract(r"ttl=(\d+)", stdout, re.IGNORECASE) or "?"
    console.log(f"[success]↳ Ping:[/success] {result.ping_latency} avg, {result.ping_loss} loss")


async def run_ssl(target: str, result: ScanResult) -> None:
    """SSL/TLS certificate inspection — stdlib only, no extra dependencies."""
    console.log("[info]↳ SSL:[/info] launching...")
    hostname = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

    loop = asyncio.get_event_loop()
    try:
        data = await loop.run_in_executor(None, _ssl_check_sync, hostname)
    except Exception as exc:
        result.errors["ssl"] = str(exc)
        console.log(f"[error]SSL error:[/error] {exc}")
        return

    if data.get("valid"):
        result.ssl_valid     = True
        result.ssl_subject   = data.get("subject", "")
        result.ssl_issuer    = data.get("issuer", "")
        result.ssl_expires   = data.get("expires", "")
        result.ssl_days_left = data.get("days_left", -1)
        result.ssl_sans      = data.get("sans", [])
        result.ssl_cipher    = data.get("cipher", "")
        result.ssl_version   = data.get("tls", "")
        console.log(f"[success]↳ SSL:[/success] valid — {result.ssl_days_left}d left, TLS {result.ssl_version}")
    else:
        result.ssl_valid = False
        result.ssl_error = data.get("error", "Unknown SSL error")
        console.log(f"[warning]↳ SSL:[/warning] {result.ssl_error[:80]}")


async def run_http_headers(target: str, result: ScanResult) -> None:
    """HTTP security header analysis via HEAD request."""
    console.log("[info]↳ HTTP Headers:[/info] launching...")
    hostname = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    loop     = asyncio.get_event_loop()

    # Try HTTPS first, then HTTP
    data: Dict[str, Any] = await loop.run_in_executor(None, _http_headers_sync, hostname, True)
    if "error" in data:
        data = await loop.run_in_executor(None, _http_headers_sync, hostname, False)

    if "error" in data:
        result.errors["http_headers"] = data["error"]
        console.log(f"[warning]↳ HTTP Headers:[/warning] {data['error'][:80]}")
        return

    raw_headers_lower = {k.lower(): v for k, v in data.get("headers", {}).items()}
    for header_name in SECURITY_HEADERS:
        status = "PRESENT" if header_name.lower() in raw_headers_lower else "MISSING"
        result.sec_headers[header_name] = status

    present = sum(1 for v in result.sec_headers.values() if v == "PRESENT")
    console.log(f"[success]↳ HTTP Headers:[/success] {present}/{len(SECURITY_HEADERS)} security headers present")


async def run_subdomains(target: str, result: ScanResult, timeout: int = 5) -> None:
    """Async subdomain brute-force using a built-in wordlist + dig."""
    console.log(f"[info]↳ Subdomains:[/info] launching ({len(COMMON_SUBDOMAINS)} probes)...")

    # Extract base domain (last 2 labels)
    clean = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    parts = clean.split(".")
    base  = ".".join(parts[-2:]) if len(parts) >= 2 else clean

    # Semaphore limits concurrent subprocesses (avoid Termux OOM)
    sem = asyncio.Semaphore(12)

    # filter out common wildcard DNS ranges
    _BOGON_PREFIXES: Tuple[str, ...] = (
        "192.0.2.",    # test ranges
        "198.51.100.",
        "203.0.113.",
        "127.",        # loopback
        "0.",          # invalid
    )

    async def _check(sub: str) -> Optional[str]:
        async with sem:
            fqdn     = f"{sub}.{base}"
            out, err = await _run_subprocess(
                ["dig", "+short", "+time=2", "+tries=1", fqdn, "A"], timeout=timeout
            )
            lines = [l.strip() for l in out.strip().splitlines()
                     if l.strip() and not l.strip().startswith(";")]
            if lines and re.match(r"[\d.]+", lines[0]):
                ip = lines[0]
                # Filter wildcard DNS false positives
                if any(ip.startswith(prefix) for prefix in _BOGON_PREFIXES):
                    return None  # wildcard DNS hit
                return f"{fqdn} [{ip}]"
        return None

    raw = await asyncio.gather(*[_check(s) for s in COMMON_SUBDOMAINS], return_exceptions=True)
    result.subdomains_found = [r for r in raw if isinstance(r, str) and r]
    console.log(f"[success]↳ Subdomains:[/success] {len(result.subdomains_found)} found")


async def run_geoip(ip: str, result: ScanResult) -> None:
    """GeoIP lookup — country, city, ISP, ASN via ip-api.com (free, no key)."""
    console.log("[info]↳ GeoIP:[/info] launching...")
    if not ip or ip == "Unresolved":
        result.errors["geoip"] = "Cannot look up — IP unresolved"
        return

    loop = asyncio.get_event_loop()
    try:
        data: Dict[str, Any] = await loop.run_in_executor(None, _geoip_sync, ip)
    except Exception as exc:
        result.errors["geoip"] = str(exc)
        return

    if "error" in data:
        result.errors["geoip"] = data["error"]
        console.log(f"[warning]↳ GeoIP:[/warning] {data['error']}")
        return

    result.geo_country = data.get("country", "")
    result.geo_region  = data.get("regionName", "")
    result.geo_city    = data.get("city", "")
    result.geo_isp     = data.get("isp", "")
    result.geo_org     = data.get("org", "")
    result.geo_asn     = data.get("as", "")
    console.log(f"[success]↳ GeoIP:[/success] {result.geo_city}, {result.geo_country} — {result.geo_isp}")


# ─────────────────────────────────────────────────────────────────────────────
#  PARSERS
# ─────────────────────────────────────────────────────────────────────────────

def _extract(pattern: str, text: str, flags: int = 0) -> str:
    """Safe single-group regex extractor."""
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ""


def _parse_nmap(raw: str, r: ScanResult) -> None:
    # Host state
    r.host_state = _extract(r"Host is (\w+)", raw)

    # OS detection
    os_m = re.search(r"OS details?:\s*(.+)", raw)
    if os_m:
        r.os_guess = os_m.group(1).strip()
    else:
        ag_m = re.search(r"Aggressive OS guesses?:\s*(.+?)(?:\n|,\()", raw)
        if ag_m:
            r.os_guess = ag_m.group(1).strip()

    # Open ports — "22/tcp  open  ssh  OpenSSH 8.9p1"
    port_re = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", re.MULTILINE)
    for m in port_re.finditer(raw):
        port, proto, state, service, version = m.groups()
        r.open_ports.append({
            "port":    port,
            "proto":   proto,
            "state":   state,
            "service": service,
            "version": version.strip()[:60],
        })

    # CVE identifiers — deduplicated
    cve_re = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
    r.cve_flags = list(dict.fromkeys(cve_re.findall(raw)))

    # Explicit VULNERABLE:/EXPLOITABLE: lines (non-CVE)
    # Only keep lines that start with those keywords to avoid noise
    vuln_re = re.compile(r"^\s*((?:VULNERABLE|EXPLOITABLE):\s*.+)", re.IGNORECASE | re.MULTILINE)
    for m in vuln_re.finditer(raw):
        line = m.group(1).strip()[:80]
        if line not in r.cve_flags:
            r.cve_flags.append(line)


def _parse_whois(raw: str, r: ScanResult) -> None:
    def _w(patterns: List[str]) -> str:
        for p in patterns:
            val = _extract(p, raw, re.IGNORECASE | re.MULTILINE)
            if val:
                return val
        return ""

    r.registrar    = _w([r"Registrar:\s*(.+)",            r"registrar:\s*(.+)"])
    r.reg_date     = _w([r"Creation Date:\s*(.+)",        r"created:\s*(.+)",
                         r"Registered on:\s*(.+)",         r"Registration Time:\s*(.+)"])
    r.exp_date     = _w([r"Expir\w+ Date:\s*(.+)",        r"expiry-date:\s*(.+)",
                         r"Renewal Date:\s*(.+)",          r"Registry Expiry Date:\s*(.+)"])
    r.updated_date = _w([r"Updated Date:\s*(.+)",         r"last-modified:\s*(.+)",
                         r"Last Updated:\s*(.+)"])
    r.org          = _w([r"Registrant Organization:\s*(.+)", r"org-name:\s*(.+)",
                         r"organisation:\s*(.+)"])
    r.country      = _w([r"Registrant Country:\s*(.+)",   r"country:\s*(.+)"])
    r.abuse_email  = _w([r"Abuse Email:\s*(.+)",          r"abuse-mailbox:\s*(.+)",
                         r"OrgAbuseEmail:\s*(.+)"])

    ns_matches    = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
    r.name_servers = [ns.strip().lower() for ns in ns_matches if ns.strip()]


def _parse_dig(records: Tuple[str, ...], r: ScanResult) -> None:
    a_raw, aaaa_raw, mx_raw, ns_raw, txt_raw, cname_raw, soa_raw = records

    # A records — flexible: handle "IN A x.x.x.x" and plain "x.x.x.x" output
    a_hits = re.findall(r"\b(?:IN\s+)?A\s+([\d.]+)", a_raw)
    if not a_hits:
        # dig +short returns plain IPs, one per line
        a_hits = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", a_raw)
    r.a_records = a_hits

    r.aaaa_records = re.findall(r"\b(?:IN\s+)?AAAA\s+([0-9a-f:]+)", aaaa_raw, re.IGNORECASE)

    for m in re.finditer(r"\b(?:IN\s+)?MX\s+(\d+)\s+(\S+)", mx_raw, re.IGNORECASE):
        r.mx_records.append({"priority": m.group(1), "host": m.group(2).rstrip(".")})

    r.ns_records = [
        ns.rstrip(".").strip()
        for ns in re.findall(r"\b(?:IN\s+)?NS\s+(\S+)", ns_raw, re.IGNORECASE)
        if ns.strip()
    ]

    raw_txts    = re.findall(r'\b(?:IN\s+)?TXT\s+"(.+?)"', txt_raw, re.IGNORECASE | re.DOTALL)
    r.txt_records = [t.replace('"\\t"', "").replace('" "', "").strip() for t in raw_txts]

    r.cname = _extract(r"\b(?:IN\s+)?CNAME\s+(\S+)", cname_raw, re.IGNORECASE).rstrip(".")

    soa_m = re.search(r"\b(?:IN\s+)?SOA\s+(\S+)\s+(\S+)", soa_raw, re.IGNORECASE)
    if soa_m:
        r.soa = f"{soa_m.group(1)} / {soa_m.group(2)}"


def _parse_whatweb(raw: str, r: ScanResult) -> None:
    r.http_status = (_extract(r"\[(\d{3})\s+\w[\w ]*\]", raw) or
                     _extract(r"HTTPStatus\[(\d+)\]", raw))
    r.page_title  = _extract(r"Title\[(.+?)\]", raw)
    r.server      = (_extract(r"HTTPServer\[(.+?)\]", raw) or
                     _extract(r"Server\[(.+?)\]", raw))

    cms_list = [
        ("WordPress",     r"WordPress(?:\[(.+?)\])?"),
        ("Joomla",        r"Joomla(?:\[(.+?)\])?"),
        ("Drupal",        r"Drupal(?:\[(.+?)\])?"),
        ("Shopify",       r"Shopify(?:\[(.+?)\])?"),
        ("Wix",           r"Wix(?:\[(.+?)\])?"),
        ("Ghost",         r"Ghost(?:\[(.+?)\])?"),
        ("Magento",       r"Magento(?:\[(.+?)\])?"),
        ("PrestaShop",    r"PrestaShop(?:\[(.+?)\])?"),
        ("TYPO3",         r"TYPO3(?:\[(.+?)\])?"),
        ("OpenCart",      r"OpenCart(?:\[(.+?)\])?"),
        ("Laravel",       r"Laravel(?:\[(.+?)\])?"),
        ("Django",        r"Django(?:\[(.+?)\])?"),
        ("Ruby on Rails", r"Ruby-on-Rails(?:\[(.+?)\])?"),
        ("Next.js",       r"Next\.js(?:\[(.+?)\])?"),
    ]
    for name, pattern in cms_list:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            ver   = (m.group(1) or "") if m.lastindex else ""
            r.cms = f"{name} {ver}".strip()
            break

    r.powered_by = (_extract(r"X-Powered-By\[(.+?)\]", raw) or
                    _extract(r"PoweredBy\[(.+?)\]", raw))

    tech_re = re.compile(
        r"(PHP|Python|Ruby|Node\.js|jQuery|Bootstrap|React|Angular|Vue|"
        r"Nginx|Apache|IIS|Cloudflare|Varnish|Webpack|ASP\.NET|"
        r"Java|Go|Perl|Symfony|CodeIgniter|Next\.js|Nuxt\.js)"
        r"(?:\[(.+?)\])?",
        re.IGNORECASE,
    )
    seen: set = set()
    for m in tech_re.finditer(raw):
        tech  = m.group(1)
        ver   = m.group(2) or ""
        label = f"{tech} {ver}".strip() if ver else tech
        if tech.lower() not in seen:
            seen.add(tech.lower())
            r.tech_stack.append(label)

    r.cookies = re.findall(r"Cookies\[(.+?)\]", raw, re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
#  IP RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

def resolve_ip(target: str) -> str:
    try:
        clean = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        return socket.gethostbyname(clean)
    except socket.gaierror:
        return "Unresolved"


# ─────────────────────────────────────────────────────────────────────────────
#  PHISHING ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _parse_domain_age_days(date_str: str) -> Optional[int]:
    """Parse various WHOIS date formats → age in days. Returns None on failure."""
    if not date_str:
        return None
    clean = date_str.strip()
    for snippet in (clean[:19], clean[:10]):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
            "%d-%b-%Y", "%d/%m/%Y", "%m/%d/%Y",
            "%Y.%m.%d", "%Y%m%d",
        ):
            try:
                dt = datetime.strptime(snippet, fmt)
                return (datetime.now() - dt).days
            except ValueError:
                continue
    return None


def analyze_phishing(result: ScanResult, raw_target: str) -> None:
    """
    Compute a phishing risk score (0-100+) from all collected scan data.
    Populates result.phishing_score, .phishing_level, .phishing_indicators,
    and .phishing_safe.
    """
    score       = 0
    indicators: List[str] = []
    safe:       List[str] = []

    domain = re.sub(r"^https?://", "", raw_target).split("/")[0].split(":")[0].lower()
    parts  = domain.split(".")

    # ── 1. IP-based URL ───────────────────────────────────────────────────────
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 25
        indicators.append("🔴 IP-based URL — legitimate sites never use raw IPs as their primary address")

    # ── 2. Domain age ─────────────────────────────────────────────────────────
    age = _parse_domain_age_days(result.reg_date)
    if age is not None:
        if age < 30:
            score += 35
            indicators.append(f"🔴 Extremely new domain — registered only {age} days ago")
        elif age < 180:
            score += 20
            indicators.append(f"🟠 Newly registered domain — only {age} days old (< 6 months)")
        elif age < 365:
            score += 8
            indicators.append(f"🟡 Less than 1 year old ({age} days)")
        else:
            years = age // 365
            safe.append(f"✅ Established domain — {years} year(s) old ({age} days)")
    else:
        score += 10
        indicators.append("🟡 Registration date unavailable — WHOIS data may be private or redacted")

    # ── 3. Suspicious TLD ─────────────────────────────────────────────────────
    tld = ("." + parts[-1]) if len(parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        score += 20
        indicators.append(f"🔴 Suspicious TLD '{tld}' — heavily abused in phishing and spam campaigns")

    # ── 4. Domain length ──────────────────────────────────────────────────────
    if len(domain) > 40:
        score += 15
        indicators.append(f"🟠 Unusually long domain ({len(domain)} chars) — phishing sites tend to be verbose")
    elif len(domain) > 25:
        score += 5
        indicators.append(f"🟡 Long domain name ({len(domain)} chars)")

    # ── 5. Excessive hyphens ──────────────────────────────────────────────────
    hyphens = domain.count("-")
    if hyphens >= 4:
        score += 20
        indicators.append(f"🔴 {hyphens} hyphens in domain — strong phishing indicator")
    elif hyphens >= 2:
        score += 10
        indicators.append(f"🟠 {hyphens} hyphens in domain — uncommon for legitimate sites")

    # ── 6. Suspicious keywords ────────────────────────────────────────────────
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain]
    if found_kw:
        kw_score = min(25, len(found_kw) * 8)
        score += kw_score
        indicators.append(f"🟠 Suspicious keywords found in domain: {', '.join(found_kw[:4])}")

    # ── 7. Brand impersonation ────────────────────────────────────────────────
    # Flag if a known brand name appears in the domain BUT is NOT the official brand TLD
    domain_name = parts[-2] if len(parts) >= 2 else parts[0]
    brand_hits  = [
        b for b in KNOWN_BRANDS
        if b in domain                         # brand appears somewhere
        and b != domain_name                   # it's not the actual brand's own domain
        and not domain.endswith(f".{b}.com")   # not a legitimate official subdomain
    ]
    if brand_hits:
        score += 30
        indicators.append(
            f"🔴 Brand impersonation detected — domain contains '{brand_hits[0]}' "
            f"but is not the official brand domain"
        )

    # ── 8. Punycode / IDN homograph attack ───────────────────────────────────
    if "xn--" in domain:
        score += 25
        indicators.append("🔴 Punycode / IDN domain detected — possible homograph attack using look-alike characters")

    # ── 9. Deep subdomain nesting ─────────────────────────────────────────────
    if len(parts) > 4:
        score += 10
        indicators.append(f"🟠 Deep subdomain nesting ({len(parts)} levels) — used to fake legitimacy (e.g. paypal.com.evil.xyz)")

    # ── 10. SSL / TLS certificate ─────────────────────────────────────────────
    if result.ssl_valid:
        safe.append("✅ Valid SSL certificate is present")
        if result.ssl_days_left > 0:
            if result.ssl_days_left < 15:
                score += 12
                indicators.append(f"🟠 SSL cert expires in only {result.ssl_days_left} days — site may be abandoned")
            else:
                safe.append(f"✅ SSL certificate valid for {result.ssl_days_left} more days")
        # Free CA is not suspicious alone, but combined with other factors matters
        if any(s in result.ssl_issuer for s in ("Let's Encrypt", "R3", "E1", "E5", "R10", "R11")):
            score += 5
            indicators.append("🟡 Free SSL (Let's Encrypt) — low-cost, also commonly used in phishing")
    else:
        if result.ssl_error:
            score += 20
            indicators.append(f"🔴 No valid SSL — {result.ssl_error[:60]}")
        else:
            score += 10
            indicators.append("🟡 SSL certificate not checked or port 443 not open")

    # ── 11. MX records ────────────────────────────────────────────────────────
    if result.mx_records:
        safe.append(f"✅ Has {len(result.mx_records)} MX record(s) — domain handles email legitimately")
    else:
        score += 8
        indicators.append("🟡 No MX records — domain does not appear to handle email")

    # ── 12. No A records (non-resolving domain) ───────────────────────────────
    if result.a_records:
        safe.append(f"✅ Domain resolves to {len(result.a_records)} IP(s): {', '.join(result.a_records[:2])}")
    else:
        score += 15
        indicators.append("🔴 Domain does not resolve to any IP — possibly parked or typosquat")

    # ── 13. WHOIS privacy ─────────────────────────────────────────────────────
    if not result.org and not result.registrar:
        score += 8
        indicators.append("🟡 No WHOIS organization info — registrant identity is hidden")
    elif result.registrar:
        safe.append(f"✅ Registered via: {result.registrar}")

    # ── 14. HTTPS port open ───────────────────────────────────────────────────
    if any(p.get("port") == "443" for p in result.open_ports):
        safe.append("✅ HTTPS (port 443) is open and responding")

    # ── 15. Security headers ─────────────────────────────────────────────────
    if result.sec_headers:
        present = sum(1 for v in result.sec_headers.values() if v == "PRESENT")
        total   = len(result.sec_headers)
        if present == 0:
            score += 15
            indicators.append("🟠 Zero HTTP security headers — well-maintained sites implement these")
        elif present < 3:
            score += 8
            indicators.append(f"🟡 Only {present}/{total} security headers present — site may be poorly maintained")
        else:
            safe.append(f"✅ {present}/{total} HTTP security headers implemented")

    # ── Final risk classification ──────────────────────────────────────────────
    if score <= 15:
        level = "✅  LOW RISK"
    elif score <= 35:
        level = "⚠️   SUSPICIOUS"
    elif score <= 60:
        level = "🟠  LIKELY PHISHING"
    else:
        level = "🔴  HIGH RISK / PHISHING"

    result.phishing_score      = score
    result.phishing_level      = level
    result.phishing_indicators = indicators
    result.phishing_safe       = safe


# ─────────────────────────────────────────────────────────────────────────────
#  RICH DISPLAY BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_header(result: ScanResult) -> Panel:
    """Summary header panel with geo, phishing risk, and scan metadata."""
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left")
    grid.add_column(justify="right")

    lat = result.ping_latency
    lat_display = lat if lat in ("?", "N/A", "") or "ms" in lat else f"{lat} ms"

    grid.add_row(
        Text(f"  🎯  Target  : {result.target}", style="bold bright_cyan"),
        Text(f"⏰  {result.timestamp}", style="muted"),
    )
    grid.add_row(
        Text(f"  🌐  IP      : {result.ip_address}", style="bold bright_white"),
        Text(f"🔬  Pickaxe OSINT v{VERSION}", style="info"),
    )
    grid.add_row(
        Text(f"  📡  Host    : {result.host_state or 'unknown'}",
             style="bold green" if result.host_state == "up" else "bold red"),
        Text(f"📶  Latency : {lat_display}  |  Loss : {result.ping_loss or 'N/A'}", style="value"),
    )
    if result.geo_country:
        location = ", ".join(filter(None, [result.geo_city, result.geo_region, result.geo_country]))
        grid.add_row(
            # shows CDN edge location, not necessarily where the company is based
            Text(f"  🌍  Anycast Node Location: {location}", style="geo_info"),
            Text(f"🏢  {result.geo_isp[:42]}" if result.geo_isp else "", style="muted"),
        )
    if result.phishing_level:
        grid.add_row(
            Text(f"  🕵️   Risk    : {result.phishing_level}  (score {result.phishing_score}/100)", style="bold"),
            Text(""),
        )

    # Border colour reflects phishing risk
    if "HIGH RISK" in result.phishing_level:
        border = "bright_red"
    elif "LIKELY" in result.phishing_level:
        border = "orange1"
    elif "SUSPICIOUS" in result.phishing_level:
        border = "yellow"
    else:
        border = "bright_cyan"

    return Panel(
        grid,
        border_style=border,
        title=f"[banner]⛏  PICKAXE v{VERSION}[/banner]",
        subtitle="[muted]Hybrid OSINT & Threat Recon[/muted]",
    )


def _table_ports(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🔌  Open Ports & Services[/section]",
        box=box.SIMPLE_HEAD, header_style="bold cyan",
        border_style="blue", show_lines=True, expand=True,
    )
    tbl.add_column("Port",    style="port_open", width=8)
    tbl.add_column("Proto",   style="muted",     width=6)
    tbl.add_column("State",   width=10)
    tbl.add_column("Service", style="bold white", width=14)
    tbl.add_column("Version / Banner", style="value")
    if not result.open_ports:
        tbl.add_row("—", "—", "—", "No open ports found", "")
        return tbl
    for p in result.open_ports:
        st = "[port_open]open[/port_open]" if p["state"] == "open" else f"[port_closed]{p['state']}[/port_closed]"
        tbl.add_row(p["port"], p["proto"], st, p["service"], p["version"])
    return tbl


def _table_cve(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🔴  Vulnerability Flags[/section]",
        box=box.SIMPLE_HEAD, header_style="bold red",
        border_style="red", expand=True,
    )
    tbl.add_column("#", width=4, style="muted")
    tbl.add_column("CVE / Finding", style="cve")
    if not result.cve_flags:
        tbl.add_row("—", "[success]No CVEs detected in scan scope[/success]")
        return tbl
    for i, cve in enumerate(result.cve_flags, 1):
        tbl.add_row(str(i), cve)
    return tbl


def _table_whois(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]📋  WHOIS Registration[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_yellow",
        border_style="yellow", expand=True,
    )
    tbl.add_column("Field", style="field", width=20)
    tbl.add_column("Value", style="value")
    for fname, val in [
        ("Registrar",     result.registrar),
        ("Registered On", result.reg_date),
        ("Expires On",    result.exp_date),
        ("Last Updated",  result.updated_date),
        ("Organisation",  result.org),
        ("Country",       result.country),
        ("Abuse Contact", result.abuse_email),
        ("Name Servers",  " | ".join(result.name_servers) if result.name_servers else "—"),
    ]:
        tbl.add_row(fname, val or "[muted]N/A[/muted]")
    return tbl


def _table_dns(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🌍  DNS Records[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_yellow",
        border_style="bright_yellow", expand=True,
    )
    tbl.add_column("Type",   style="field",      width=8)
    tbl.add_column("Record", style="dns_record")
    for v in result.a_records:    tbl.add_row("A",    v)
    for v in result.aaaa_records: tbl.add_row("AAAA", v)
    for mx in result.mx_records:
        tbl.add_row("MX", f"[bold]{mx['priority']}[/bold]  {mx['host']}")
    for v in result.ns_records:   tbl.add_row("NS",   v)
    for v in result.txt_records:  tbl.add_row("TXT",  v[:120])
    if result.cname: tbl.add_row("CNAME", result.cname)
    if result.soa:   tbl.add_row("SOA",   result.soa)
    if not any([result.a_records, result.aaaa_records, result.mx_records,
                result.ns_records, result.txt_records, result.cname, result.soa]):
        tbl.add_row("—", "[muted]No DNS records resolved[/muted]")
    return tbl


def _table_web(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🌐  Web Fingerprint[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_magenta",
        border_style="magenta", expand=True,
    )
    tbl.add_column("Attribute", style="field",  width=18)
    tbl.add_column("Value",     style="value")
    rows = [
        ("HTTP Status",    result.http_status),
        ("Page Title",     result.page_title),
        ("CMS / Platform", result.cms),
        ("Web Server",     result.server),
        ("Powered By",     result.powered_by),
        ("OS Guess",       result.os_guess),
        ("Technologies",   ", ".join(result.tech_stack) if result.tech_stack else ""),
        ("Cookies",        " | ".join(result.cookies)   if result.cookies     else ""),
    ]
    found_any = False
    for attr, val in rows:
        if val:
            tbl.add_row(attr, val)
            found_any = True
    if not found_any:
        tbl.add_row("—", "[muted]No web data collected[/muted]")
    return tbl


def _table_ssl(result: ScanResult) -> Table:
    """SSL/TLS certificate info table."""
    tbl = Table(
        title="[section]🔐  SSL / TLS Certificate[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_cyan",
        border_style="cyan", expand=True,
    )
    tbl.add_column("Field", style="field", width=14)
    tbl.add_column("Value", style="value")

    if not result.ssl_valid:
        tbl.add_row("Status", "[ssl_bad]✘  Invalid or not present[/ssl_bad]")
        err = result.ssl_error or "Port 443 not checked / not open"
        tbl.add_row("Reason", f"[warning]{err}[/warning]")
        return tbl

    days = result.ssl_days_left
    if days < 0:
        days_str = "[muted]Unknown[/muted]"
    elif days < 15:
        days_str = f"[ssl_bad]{days} days — CRITICAL, expires very soon[/ssl_bad]"
    elif days < 30:
        days_str = f"[ssl_warn]{days} days — expiring soon[/ssl_warn]"
    else:
        days_str = f"[ssl_good]{days} days[/ssl_good]"

    tbl.add_row("Status",      "[ssl_good]✔  Valid[/ssl_good]")
    tbl.add_row("Subject",     result.ssl_subject)
    tbl.add_row("Issuer",      result.ssl_issuer)
    tbl.add_row("Expires",     result.ssl_expires)
    tbl.add_row("Days Left",   days_str)
    tbl.add_row("TLS Version", result.ssl_version)
    tbl.add_row("Cipher",      result.ssl_cipher)
    if result.ssl_sans:
        tbl.add_row("SANs", ", ".join(result.ssl_sans[:6]))
    return tbl


def _table_http_headers(result: ScanResult) -> Table:
    """HTTP security header analysis table."""
    tbl = Table(
        title="[section]🛡️  HTTP Security Headers[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_blue",
        border_style="blue", expand=True,
    )
    tbl.add_column("Header",    style="field",  width=33)
    tbl.add_column("Tag",       style="muted",  width=10)
    tbl.add_column("Status",    width=14)
    tbl.add_column("Purpose",   style="muted")

    if not result.sec_headers:
        tbl.add_row("—", "—", "[muted]Not checked[/muted]", "")
        return tbl

    for hdr, (tag, purpose) in SECURITY_HEADERS.items():
        status = result.sec_headers.get(hdr, "MISSING")
        s_str  = "[hdr_good]✔  Present[/hdr_good]" if status == "PRESENT" else "[hdr_miss]✘  Missing[/hdr_miss]"
        tbl.add_row(hdr, tag, s_str, purpose)
    return tbl


def _table_subdomains(result: ScanResult) -> Table:
    """Discovered subdomains table."""
    tbl = Table(
        title=f"[section]🔍  Subdomain Enum ({len(result.subdomains_found)} found)[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_green",
        border_style="green", expand=True,
    )
    tbl.add_column("#",         style="muted",     width=5)
    tbl.add_column("Subdomain [IP]", style="sub_found")
    if not result.subdomains_found:
        tbl.add_row("—", "[muted]No common subdomains resolved[/muted]")
        return tbl
    for i, sub in enumerate(result.subdomains_found, 1):
        tbl.add_row(str(i), sub)
    return tbl


def _table_geoip(result: ScanResult) -> Optional[Table]:
    """GeoIP / network info table. Returns None if no geo data available."""
    if not result.geo_country:
        return None
    tbl = Table(
        title="[section]🌍  GeoIP & Network Info[/section]",
        box=box.SIMPLE_HEAD, header_style="bold bright_cyan",
        border_style="cyan", expand=True,
    )
    tbl.add_column("Field", style="field", width=10)
    tbl.add_column("Value", style="geo_info")
    for fname, val in [
        ("Country", result.geo_country),
        ("Region",  result.geo_region),
        ("City",    result.geo_city),
        ("ISP",     result.geo_isp),
        ("Org",     result.geo_org),
        ("ASN",     result.geo_asn),
    ]:
        if val:
            tbl.add_row(fname, val)
    return tbl


def _table_phishing(result: ScanResult) -> Table:
    """Phishing risk analysis table with colour-coded scoring."""
    level = result.phishing_level
    score = result.phishing_score

    if "HIGH RISK" in level:
        bc, sc = "bright_red",   "phish_high"
    elif "LIKELY" in level:
        bc, sc = "orange1",      "phish_likely"
    elif "SUSPICIOUS" in level:
        bc, sc = "yellow",       "phish_sus"
    else:
        bc, sc = "bright_green", "phish_low"

    tbl = Table(
        title="[section]🕵️  Phishing & Threat Analysis[/section]",
        box=box.SIMPLE_HEAD, header_style=f"bold {bc}",
        border_style=bc, expand=True,
    )
    tbl.add_column("Category", style="field",  width=16)
    tbl.add_column("Detail",   style="value")

    tbl.add_row("Risk Level", f"[{sc}]{level}[/{sc}]")
    tbl.add_row("Risk Score", f"[{sc}]{score}/100[/{sc}]")

    if result.phishing_indicators:
        tbl.add_row("[bold red]⚠ Risk Signals[/bold red]", "")
        for indicator in result.phishing_indicators:
            tbl.add_row("", indicator)

    if result.phishing_safe:
        tbl.add_row("[bold green]✅ Safe Signals[/bold green]", "")
        for sig in result.phishing_safe:
            tbl.add_row("", sig)

    return tbl


def _table_errors(result: ScanResult) -> Optional[Table]:
    if not result.errors:
        return None
    tbl = Table(
        title="[warning]⚠  Scan Errors / Warnings[/warning]",
        box=box.SIMPLE_HEAD, header_style="bold yellow",
        border_style="yellow", expand=True,
    )
    tbl.add_column("Module", style="field",   width=14)
    tbl.add_column("Detail", style="warning")
    for module, msg in result.errors.items():
        tbl.add_row(module, msg[:200])
    return tbl


def display_results(result: ScanResult) -> None:
    """Render all collected scan data as Rich tables."""
    console.print()
    console.print(_make_header(result))
    console.print()

    # Row 1: Ports + CVE
    console.print(Columns([_table_ports(result), _table_cve(result)], equal=False, expand=True))
    console.print()

    # Row 2: WHOIS + DNS
    console.print(Columns([_table_whois(result), _table_dns(result)], equal=False, expand=True))
    console.print()

    # Row 3: Web fingerprint + SSL
    console.print(Columns([_table_web(result), _table_ssl(result)], equal=False, expand=True))
    console.print()

    # Row 4: HTTP Security Headers + Subdomains
    console.print(Columns([_table_http_headers(result), _table_subdomains(result)], equal=False, expand=True))
    console.print()

    # Row 5: GeoIP (if available) + Phishing analysis
    geo = _table_geoip(result)
    if geo:
        console.print(Columns([geo, _table_phishing(result)], equal=False, expand=True))
    else:
        console.print(_table_phishing(result))
    console.print()

    # Errors (conditional)
    err_tbl = _table_errors(result)
    if err_tbl:
        console.print(err_tbl)
        console.print()

    # Footer
    console.print(Rule(style="bright_blue"))
    console.print(
        f"[muted]  Scan completed at {datetime.now().strftime('%H:%M:%S')} — "
        f"{len(result.open_ports)} open port(s)  |  "
        f"{len(result.cve_flags)} CVE/vuln flag(s)  |  "
        f"{len(result.subdomains_found)} subdomain(s)  |  "
        f"Phishing score: {result.phishing_score}/100  ({result.phishing_level})[/muted]"
    )
    console.print(Rule(style="bright_blue"))


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT EXPORTERS
# ─────────────────────────────────────────────────────────────────────────────

def export_json(result: ScanResult, filepath: str) -> None:
    """Export all scan results to a JSON file."""
    data = {
        "meta": {
            "pickaxe_version": VERSION,
            "target":    result.target,
            "ip":        result.ip_address,
            "timestamp": result.timestamp,
        },
        "nmap": {
            "host_state": result.host_state,
            "os_guess":   result.os_guess,
            "open_ports": result.open_ports,
            "cve_flags":  result.cve_flags,
        },
        "whois": {
            "registrar":    result.registrar,
            "reg_date":     result.reg_date,
            "exp_date":     result.exp_date,
            "updated_date": result.updated_date,
            "org":          result.org,
            "country":      result.country,
            "abuse_email":  result.abuse_email,
            "name_servers": result.name_servers,
        },
        "dns": {
            "a_records":    result.a_records,
            "aaaa_records": result.aaaa_records,
            "mx_records":   result.mx_records,
            "ns_records":   result.ns_records,
            "txt_records":  result.txt_records,
            "cname":        result.cname,
            "soa":          result.soa,
        },
        "web": {
            "http_status": result.http_status,
            "page_title":  result.page_title,
            "cms":         result.cms,
            "server":      result.server,
            "powered_by":  result.powered_by,
            "tech_stack":  result.tech_stack,
            "cookies":     result.cookies,
        },
        "ssl": {
            "valid":     result.ssl_valid,
            "subject":   result.ssl_subject,
            "issuer":    result.ssl_issuer,
            "expires":   result.ssl_expires,
            "days_left": result.ssl_days_left,
            "tls":       result.ssl_version,
            "cipher":    result.ssl_cipher,
            "sans":      result.ssl_sans,
            "error":     result.ssl_error,
        },
        "security_headers": result.sec_headers,
        "subdomains":        result.subdomains_found,
        "geoip": {
            "country": result.geo_country,
            "region":  result.geo_region,
            "city":    result.geo_city,
            "isp":     result.geo_isp,
            "org":     result.geo_org,
            "asn":     result.geo_asn,
        },
        "ping": {
            "latency": result.ping_latency,
            "loss":    result.ping_loss,
            "ttl":     result.ping_ttl,
        },
        "phishing": {
            "score":        result.phishing_score,
            "level":        result.phishing_level,
            "indicators":   result.phishing_indicators,
            "safe_signals": result.phishing_safe,
        },
        "errors": result.errors,
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    console.print(f"[success]✔  JSON report saved:[/success] [cyan]{filepath}[/cyan]")


def export_txt(result: ScanResult, filepath: str) -> None:
    """Export scan results to a plain text report file."""
    sep = "=" * 62
    lines = [
        sep,
        f"  PICKAXE OSINT v{VERSION} — Scan Report",
        sep,
        f"  Target    : {result.target}",
        f"  IP        : {result.ip_address}",
        f"  Timestamp : {result.timestamp}",
        "",
        "── NMAP ─────────────────────────────────────────────────",
        f"  Host State : {result.host_state or 'N/A'}",
        f"  OS Guess   : {result.os_guess or 'N/A'}",
        f"  Open Ports : {len(result.open_ports)}",
    ]
    for p in result.open_ports:
        lines.append(f"    {p['port']}/{p['proto']}  {p['state']}  {p['service']}  {p['version']}")
    lines += ["", "── CVEs / VULNS ──────────────────────────────────────────"]
    lines += ["  " + c for c in result.cve_flags] if result.cve_flags else ["  None detected"]
    lines += [
        "", "── WHOIS ────────────────────────────────────────────────",
        f"  Registrar  : {result.registrar or 'N/A'}",
        f"  Registered : {result.reg_date or 'N/A'}",
        f"  Expires    : {result.exp_date or 'N/A'}",
        f"  Org        : {result.org or 'N/A'}",
        f"  Country    : {result.country or 'N/A'}",
        f"  NS         : {', '.join(result.name_servers) or 'N/A'}",
        "", "── DNS ──────────────────────────────────────────────────",
        f"  A Records  : {', '.join(result.a_records) or 'None'}",
        f"  MX Records : {', '.join(mx['host'] for mx in result.mx_records) or 'None'}",
        f"  NS Records : {', '.join(result.ns_records) or 'None'}",
        f"  TXT        : {len(result.txt_records)} record(s)",
        "", "── SSL / TLS ─────────────────────────────────────────────",
        f"  Valid      : {result.ssl_valid}",
        f"  Issuer     : {result.ssl_issuer or 'N/A'}",
        f"  Expires    : {result.ssl_expires or 'N/A'}",
        f"  Days Left  : {result.ssl_days_left}",
        f"  TLS Ver    : {result.ssl_version or 'N/A'}",
        "", "── GEOIP ────────────────────────────────────────────────",
        f"  Country : {result.geo_country or 'N/A'}",
        f"  City    : {result.geo_city or 'N/A'}",
        f"  ISP     : {result.geo_isp or 'N/A'}",
        f"  ASN     : {result.geo_asn or 'N/A'}",
        "", "── SUBDOMAINS ───────────────────────────────────────────",
    ]
    lines += ["  " + s for s in result.subdomains_found] if result.subdomains_found else ["  None found"]
    lines += [
        "", "── PHISHING ANALYSIS ─────────────────────────────────────",
        f"  Score    : {result.phishing_score}/100",
        f"  Level    : {result.phishing_level}",
        "  Risk Indicators:",
    ]
    lines += ["    " + i for i in result.phishing_indicators]
    lines += ["  Safe Signals:"]
    lines += ["    " + s for s in result.phishing_safe]
    lines += ["", sep, f"  Generated by Pickaxe OSINT v{VERSION}", sep]

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    console.print(f"[success]✔  TXT report saved:[/success] [cyan]{filepath}[/cyan]")


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER & PROFILES
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
[bold bright_cyan]
 ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
 ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
 ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
 ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
 ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
 ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝[/bold bright_cyan]
[bold white]        Hybrid OSINT & Web Reconnaissance Utility[/bold white]
[muted]         Termux · Linux · v{VERSION} · MIT License[/muted]
"""

PROFILES: Dict[str, List[str]] = {
    "full":    [],                               # All modules
    "quick":   ["nmap"],                         # Skip slow port scan
    "stealth": ["nmap", "ping"],                 # No active probing
    "web":     ["nmap", "ping", "whois"],        # Web-focused only
    "dns":     ["nmap", "whatweb", "ping"],      # DNS-focused only
}


# ─────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def orchestrate(
    target:       str,
    skip:         Optional[List[str]] = None,
    nmap_timeout: int = 240,
    scan_timeout: int = 30,
) -> ScanResult:
    """
    Launch ALL scan modules in true parallel with asyncio.gather().
    Uses return_exceptions=True so one failed module never kills the rest.
    Phishing analysis runs AFTER all scans (uses combined data).
    """
    result = ScanResult(target=target)
    skip   = skip or []

    clean  = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    result.ip_address = resolve_ip(clean)

    coros:  List[Any] = []
    labels: List[str] = []

    if "nmap"         not in skip: coros.append(run_nmap(clean,  result, nmap_timeout)); labels.append("nmap")
    if "whois"        not in skip: coros.append(run_whois(clean, result, scan_timeout)); labels.append("whois")
    if "dig"          not in skip: coros.append(run_dig(clean,   result, scan_timeout)); labels.append("dns")
    if "whatweb"      not in skip: coros.append(run_whatweb(target, result));            labels.append("whatweb")
    if "ping"         not in skip: coros.append(run_ping(clean,  result));               labels.append("ping")
    if "ssl"          not in skip: coros.append(run_ssl(target,  result));               labels.append("ssl")
    if "http_headers" not in skip: coros.append(run_http_headers(target, result));       labels.append("headers")
    if "subdomains"   not in skip: coros.append(run_subdomains(clean, result));          labels.append("subdomains")
    if "geoip"        not in skip: coros.append(run_geoip(result.ip_address, result));   labels.append("geoip")

    with Progress(
        SpinnerColumn(spinner_name="dots2"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn(f"[muted]running {len(coros)} modules in parallel[/muted]"),
        console=console,
        transient=True,
    ) as progress:
        pid = progress.add_task(
            f"[info]Scanning: {', '.join(labels)}…[/info]", total=None
        )

        # return_exceptions=True: one failure does NOT propagate to others
        raw = await asyncio.gather(*coros, return_exceptions=True)

        for i, res in enumerate(raw):
            if isinstance(res, Exception):
                m = labels[i] if i < len(labels) else f"module_{i}"
                result.errors[m] = f"Uncaught exception: {res}"
                console.log(f"[error]Module '{m}' raised exception:[/error] {res}")

        progress.update(pid, description="[success]All modules complete![/success]")

    # Phishing analysis uses data from ALL modules — must run after gather
    analyze_phishing(result, target)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _usage() -> None:
    console.print(Panel(
        f"""[field]Usage:[/field]
  [bright_white]python hybrid_osint.py [OPTIONS] <target>[/bright_white]

[field]Positional:[/field]
  [value]<target>[/value]               Domain, hostname, or IP address

[field]Options:[/field]
  [value]-h, --help[/value]             Show this help message
  [value]--check[/value]                Dependency check and exit
  [value]--install[/value]              Run setup.sh to install deps and exit
  [value]--skip <modules>[/value]       Comma-separated modules to skip
                          nmap, whois, dig, whatweb, ping,
                          ssl, http_headers, subdomains, geoip
  [value]--force[/value]                Skip dependency check
  [value]--output <file>[/value]        Save report to file (.json or .txt)
  [value]--timeout <sec>[/value]        Per-scan timeout in seconds (default: 30)
  [value]--profile <name>[/value]       Scan profile preset (see below)

[field]Profiles:[/field]
  [bright_cyan]full[/bright_cyan]        All modules (default)
  [bright_cyan]quick[/bright_cyan]       Skip nmap — fast results
  [bright_cyan]stealth[/bright_cyan]     Skip nmap + ping — passive only
  [bright_cyan]web[/bright_cyan]         Skip nmap + ping + whois — web-centric
  [bright_cyan]dns[/bright_cyan]         Skip nmap + whatweb + ping — DNS-centric

[field]Examples:[/field]
  [bright_cyan]python hybrid_osint.py example.com[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --profile quick example.com[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --skip nmap,ping 192.168.1.1[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --output report.json example.com[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --timeout 60 --profile stealth target.org[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --check[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --install[/bright_cyan]
""",
        title="[banner]⛏  Pickaxe v" + VERSION + " Help[/banner]",
        border_style="bright_cyan",
    ))


def _parse_args(argv: List[str]) -> Dict[str, Any]:
    """
    Robust CLI argument parser — fixed version of the original buggy parser.
    Uses a clean pop-by-index approach that never accidentally removes targets.
    """
    args = list(argv)  # mutable copy
    cfg: Dict[str, Any] = {
        "target":       "",
        "skip":         [],
        "force":        False,
        "output":       "",
        "timeout":      30,
        "nmap_timeout": 240,
        "profile":      "",
        "check":        False,
        "install":      False,
        "help":         False,
    }

    if not args:
        cfg["help"] = True
        return cfg

    # Simple boolean flags — check then remove
    cfg["help"]    = ("-h" in args or "--help" in args)
    cfg["check"]   = "--check"   in args
    cfg["install"] = "--install" in args
    cfg["force"]   = "--force"   in args
    for flag in ("-h", "--help", "--check", "--install", "--force"):
        while flag in args:
            args.remove(flag)

    # Paired value flags — helper pops flag and its value safely
    def _pop_val(flag: str) -> Optional[str]:
        if flag in args:
            idx = args.index(flag)
            args.pop(idx)           # remove flag itself
            if idx < len(args):     # value follows immediately
                return args.pop(idx)
        return None

    skip_str    = _pop_val("--skip")
    profile_str = _pop_val("--profile")
    output_str  = _pop_val("--output")
    timeout_str = _pop_val("--timeout")

    if skip_str:
        cfg["skip"] = [s.strip().lower() for s in skip_str.split(",") if s.strip()]

    if profile_str:
        cfg["profile"] = profile_str.lower()
        extra = PROFILES.get(profile_str.lower(), [])
        cfg["skip"] = list(set(cfg["skip"] + extra))

    if output_str:
        cfg["output"] = output_str

    if timeout_str:
        try:
            t = int(timeout_str)
            cfg["timeout"]      = t
            cfg["nmap_timeout"] = max(60, t * 4)
        except ValueError:
            console.print(f"[warning]--timeout '{timeout_str}' is not a valid integer — using defaults.[/warning]")

    # Any remaining non-flag argument is the target
    remaining = [a for a in args if not a.startswith("-")]
    if remaining:
        cfg["target"] = remaining[0]

    return cfg


def main() -> None:
    # Fix gem PATH on Termux BEFORE dependency check so WhatWeb is found
    _fix_gem_path()

    cfg = _parse_args(sys.argv[1:])

    # Help / no args
    if cfg["help"] or (not cfg["target"] and not cfg["check"] and not cfg["install"]):
        console.print(BANNER)
        _usage()
        sys.exit(0)

    # Dependency check mode
    if cfg["check"]:
        console.print(BANNER)
        ok = print_dependency_report()
        if not ok:
            console.print(
                "\n[info]Tip:[/info] Run [cyan]bash setup.sh[/cyan] or "
                "[cyan]python hybrid_osint.py --install[/cyan] to fix missing tools."
            )
        sys.exit(0 if ok else 1)

    # Install mode
    if cfg["install"]:
        console.print(BANNER)
        setup_path = _find_setup_sh()
        if not setup_path:
            console.print("[error]✘  setup.sh not found.[/error] "
                          "Make sure setup.sh is in the same directory.")
            sys.exit(1)
        console.print(f"[info]  Running:[/info] [cyan]{setup_path}[/cyan]")
        console.print(Rule(style="bright_blue"))
        ret = subprocess.run(["bash", str(setup_path)], check=False)
        sys.exit(ret.returncode)

    target = cfg["target"]
    if not target:
        console.print("[error]✘  No target specified.[/error]")
        _usage()
        sys.exit(1)

    # Print banner and scan config
    console.print(BANNER)
    console.print(Rule(style="bright_blue"))
    console.print(f"[info]  Target  :[/info] [bold bright_white]{target}[/bold bright_white]")
    if cfg["profile"]:
        console.print(f"[info]  Profile :[/info] [bold]{cfg['profile'].upper()}[/bold]")
    if cfg["skip"]:
        console.print(f"[info]  Skipping:[/info] [muted]{', '.join(cfg['skip'])}[/muted]")
    if cfg["output"]:
        console.print(f"[info]  Output  :[/info] [cyan]{cfg['output']}[/cyan]")
    if is_termux():
        console.print("[info]  Platform:[/info] [bold cyan]Termux (Android)[/bold cyan]  "
                      "[muted]— gem PATH auto-fixed[/muted]")
    if not is_root() and "nmap" not in cfg["skip"]:
        console.print("[warning]  ⚠ Non-root: Nmap will use TCP connect scan (-sT), OS detection skipped[/warning]")
    console.print(Rule(style="bright_blue"))
    console.print()

    # Dependency check + auto-install prompt
    if not cfg["force"]:
        active_tools = [t for t in REQUIRED_TOOLS if t not in cfg["skip"]]
        _, missing   = check_dependencies(active_tools)
        to_skip      = [t for t in missing if t not in cfg["skip"]]

        if to_skip:
            print_dependency_report()
            installed = auto_install_prompt(to_skip)
            if installed:
                _fix_gem_path()  # Re-run after install — gem may now be in PATH
                _, still_missing = check_dependencies(active_tools)
                to_skip = [t for t in still_missing if t not in cfg["skip"]]
                if to_skip:
                    console.print(
                        f"[warning]⚠  Still missing after install (will skip):[/warning] "
                        f"[muted]{', '.join(to_skip)}[/muted]"
                    )
            cfg["skip"] = list(set(cfg["skip"] + to_skip))
            console.print()

    # Run all scans
    start = time.monotonic()
    try:
        result = asyncio.run(orchestrate(
            target,
            skip         = cfg["skip"],
            nmap_timeout = cfg["nmap_timeout"],
            scan_timeout = cfg["timeout"],
        ))
    except KeyboardInterrupt:
        console.print("\n[warning]⚠  Scan interrupted by user.[/warning]")
        sys.exit(130)

    elapsed = time.monotonic() - start
    console.print(f"\n[success]✔  Total acquisition time: {elapsed:.2f}s[/success]\n")

    # Display results
    display_results(result)

    # Export report if requested
    if cfg["output"]:
        out = cfg["output"]
        if out.endswith(".json"):
            export_json(result, out)
        elif out.endswith(".txt"):
            export_txt(result, out)
        else:
            # No extension — save both formats
            export_json(result, out + ".json")
            export_txt(result,  out + ".txt")


if __name__ == "__main__":
    main()
