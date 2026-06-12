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
#  Version : 2.1.0
#  Author  : Pickaxe Project
#  License : MIT
#  Target  : Termux (Android) | Linux
# =============================================================================

import asyncio
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL THEME & CONSOLE
# ─────────────────────────────────────────────────────────────────────────────

CUSTOM_THEME = Theme(
    {
        "banner":       "bold bright_cyan",
        "header":       "bold bright_white on #1a1a2e",
        "success":      "bold bright_green",
        "warning":      "bold yellow",
        "error":        "bold bright_red",
        "info":         "bold bright_blue",
        "muted":        "dim white",
        "field":        "bold cyan",
        "value":        "bright_white",
        "section":      "bold magenta",
        "cve":          "bold bright_red on #2d0000",
        "port_open":    "bold green",
        "port_closed":  "dim red",
        "dns_record":   "bright_yellow",
        "cms":          "bold bright_magenta",
        "highlight":    "bold bright_cyan on #0d2137",
    }
)

console = Console(theme=CUSTOM_THEME, highlight=False)

# ─────────────────────────────────────────────────────────────────────────────
#  DATA CONTAINERS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:     str = ""
    ip_address: str = ""
    timestamp:  str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Nmap
    nmap_raw:    str = ""
    open_ports:  list[dict] = field(default_factory=list)   # [{port, proto, service, version, state}]
    cve_flags:   list[str]  = field(default_factory=list)
    os_guess:    str        = ""
    host_state:  str        = ""

    # WHOIS
    whois_raw:    str = ""
    registrar:    str = ""
    reg_date:     str = ""
    exp_date:     str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    org:          str = ""
    country:      str = ""
    abuse_email:  str = ""

    # DNS / DIG
    dig_raw:     str = ""
    a_records:   list[str] = field(default_factory=list)
    aaaa_records:list[str] = field(default_factory=list)
    mx_records:  list[dict] = field(default_factory=list)   # [{priority, host}]
    ns_records:  list[str]  = field(default_factory=list)
    txt_records: list[str]  = field(default_factory=list)
    cname:       str        = ""
    soa:         str        = ""

    # WhatWeb
    whatweb_raw: str = ""
    cms:         str = ""
    server:      str = ""
    tech_stack:  list[str] = field(default_factory=list)
    powered_by:  str = ""
    http_status: str = ""
    page_title:  str = ""
    cookies:     list[str] = field(default_factory=list)
    headers:     dict      = field(default_factory=dict)

    # Ping
    ping_latency:  str = ""
    ping_loss:     str = ""
    ping_ttl:      str = ""

    # Errors
    errors: dict[str, str] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY CHECKER
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "nmap":    {
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
        "termux": "pkg install ruby && gem install whatweb",
        "apt":    "sudo apt install whatweb",
        "yum":    "gem install whatweb",
        "pacman": "gem install whatweb",
    },
    "ping": {
        "termux": "pkg install iputils",
        "apt":    "sudo apt install iputils-ping",
        "yum":    "sudo yum install iputils",
        "pacman": "sudo pacman -S iputils",
    },
}


def _detect_pkg_manager() -> str:
    for pm in ("pkg", "apt", "yum", "pacman"):
        if shutil.which(pm):
            return pm
    return "apt"


def check_dependencies(tools: list[str] | None = None) -> tuple[list[str], list[str]]:
    """
    Validate that required system tools exist in $PATH.
    Returns (found_list, missing_list).
    """
    check_list  = tools or list(REQUIRED_TOOLS.keys())
    found:   list[str] = []
    missing: list[str] = []

    for tool in check_list:
        binary = "dig" if tool == "dig" else tool
        if shutil.which(binary):
            found.append(tool)
        else:
            missing.append(tool)

    return found, missing


def print_dependency_report() -> bool:
    """Print a rich dependency table. Returns True if all deps satisfied."""
    found, missing = check_dependencies()

    tbl = Table(
        title="[header] System Dependency Check [/header]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_blue",
        expand=False,
    )
    tbl.add_column("Tool",   style="field",   width=12)
    tbl.add_column("Status", style="value",   width=14)
    tbl.add_column("Binary Path / Note",       width=46)

    for tool in REQUIRED_TOOLS:
        if tool in found:
            binary = shutil.which("dig" if tool == "dig" else tool) or "in PATH"
            tbl.add_row(tool, "[success]✔  Found[/success]", f"[muted]{binary}[/muted]")
        else:
            tbl.add_row(tool, "[error]✘  Missing[/error]", "[yellow]run: bash setup.sh[/yellow]")

    console.print(tbl)
    return len(missing) == 0


def _find_setup_sh() -> Path | None:
    """Locate setup.sh relative to this script or cwd."""
    candidates = [
        Path(__file__).parent / "setup.sh",
        Path.cwd() / "setup.sh",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def auto_install_prompt(missing: list[str]) -> bool:
    """
    Offer to run setup.sh automatically when tools are missing.
    Returns True if the user approved and setup ran successfully.
    """
    setup_path = _find_setup_sh()

    console.print()
    console.print(Panel(
        f"[error]✘  Missing tools detected:[/error] [bold]{', '.join(missing)}[/bold]\n\n"
        "[info]Pickaxe can install everything automatically right now.[/info]\n"
        f"  Setup script: [cyan]{setup_path or 'setup.sh (not found in current dir)'}[/cyan]",
        title="[warning]⚠  Dependencies Missing[/warning]",
        border_style="yellow",
    ))

    if not setup_path:
        console.print(
            "[error]setup.sh not found.[/error] "
            "Clone the full repo and run [cyan]bash setup.sh[/cyan] manually."
        )
        return False

    # Interactive prompt — skip if stdin is not a TTY (e.g. piped)
    if not sys.stdin.isatty():
        console.print("[muted]Non-interactive mode — skipping auto-install.[/muted]")
        return False

    try:
        answer = console.input(
            "\n  [bold bright_cyan]Install all dependencies now?[/bold bright_cyan] "
            "[bold](y/N):[/bold] "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[muted]Skipped.[/muted]")
        return False

    if answer not in ("y", "yes"):
        console.print(
            "[muted]Skipped. Run [cyan]bash setup.sh[/cyan] manually, then retry.[/muted]"
        )
        return False

    console.print()
    console.print(Rule("[info]Running setup.sh[/info]", style="bright_blue"))
    console.print()

    try:
        ret = subprocess.run(["bash", str(setup_path)], check=False)
        if ret.returncode == 0:
            console.print()
            console.print(Rule(style="bright_blue"))
            console.print("[success]✔  setup.sh completed. Re-checking dependencies…[/success]")
            return True
        else:
            console.print(f"[error]✘  setup.sh exited with code {ret.returncode}.[/error]")
            return False
    except FileNotFoundError:
        console.print("[error]✘  bash not found — cannot run setup.sh.[/error]")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  ASYNC SCAN RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

async def _run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[str, str]:
    """Async wrapper around asyncio subprocess. Returns (stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return "", f"[TIMEOUT] Command '{' '.join(cmd)}' exceeded {timeout}s"
    except FileNotFoundError:
        return "", f"[NOT FOUND] '{cmd[0]}' binary not in PATH"
    except Exception as exc:  # noqa: BLE001
        return "", f"[ERROR] {exc}"


async def run_nmap(target: str, result: ScanResult) -> None:
    """Full TCP SYN scan + version + script detection + OS guess."""
    console.log("[info]↳ Nmap:[/info] launching...")
    stdout, stderr = await _run_subprocess(
        ["nmap", "-sV", "-sC", "--script=vuln", "-O",
         "--open", "-T4", "-oN", "-", target],
        timeout=240,
    )
    if stderr and not stdout:
        result.errors["nmap"] = stderr.strip()
        console.log(f"[error]Nmap error:[/error] {stderr.strip()[:120]}")
        return
    result.nmap_raw = stdout
    _parse_nmap(stdout, result)
    console.log("[success]↳ Nmap:[/success] complete")


async def run_whois(target: str, result: ScanResult) -> None:
    """WHOIS registration data."""
    console.log("[info]↳ WHOIS:[/info] launching...")
    stdout, stderr = await _run_subprocess(["whois", target], timeout=30)
    if stderr and not stdout:
        result.errors["whois"] = stderr.strip()
        console.log(f"[error]WHOIS error:[/error] {stderr.strip()[:120]}")
        return
    result.whois_raw = stdout
    _parse_whois(stdout, result)
    console.log("[success]↳ WHOIS:[/success] complete")


async def run_dig(target: str, result: ScanResult) -> None:
    """DNS enumeration — A, AAAA, MX, NS, TXT, CNAME, SOA."""
    console.log("[info]↳ DIG:[/info] launching...")

    async def _dig(qtype: str) -> str:
        out, _ = await _run_subprocess(
            ["dig", "+noall", "+answer", target, qtype], timeout=20
        )
        return out

    records = await asyncio.gather(
        _dig("A"), _dig("AAAA"), _dig("MX"),
        _dig("NS"), _dig("TXT"), _dig("CNAME"), _dig("SOA"),
    )
    combined = "\n".join(records)
    result.dig_raw = combined
    _parse_dig(records, result)
    console.log("[success]↳ DIG:[/success] complete")


async def run_whatweb(target: str, result: ScanResult) -> None:
    """WhatWeb technology fingerprinting."""
    console.log("[info]↳ WhatWeb:[/info] launching...")
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    stdout, stderr = await _run_subprocess(
        ["whatweb", "-a", "3", "--log-brief=-", url], timeout=60
    )
    if not stdout:
        # Fallback: plain mode
        stdout, stderr = await _run_subprocess(
            ["whatweb", "-a", "3", url], timeout=60
        )
    if stderr and not stdout:
        result.errors["whatweb"] = stderr.strip()
        console.log(f"[error]WhatWeb error:[/error] {stderr.strip()[:120]}")
        return
    result.whatweb_raw = stdout
    _parse_whatweb(stdout, result)
    console.log("[success]↳ WhatWeb:[/success] complete")


async def run_ping(target: str, result: ScanResult) -> None:
    """ICMP latency / reachability check."""
    console.log("[info]↳ Ping:[/info] launching...")
    count_flag = "-c"
    stdout, stderr = await _run_subprocess(
        ["ping", count_flag, "4", "-W", "2", target], timeout=15
    )
    if not stdout:
        result.errors["ping"] = stderr.strip() or "No response"
        result.ping_latency = "N/A (host may block ICMP)"
        console.log("[warning]↳ Ping:[/warning] no response / ICMP filtered")
        return
    result.ping_latency = _extract(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", stdout) or \
                          _extract(r"avg\s*=\s*([\d.]+)", stdout) or "?"
    result.ping_loss    = _extract(r"([\d.]+)% packet loss", stdout)    or "0%"
    result.ping_ttl     = _extract(r"ttl=(\d+)",            stdout, re.IGNORECASE) or "?"
    console.log("[success]↳ Ping:[/success] complete")


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

    # Open ports — pattern: 22/tcp  open  ssh  OpenSSH 8.9p1
    port_re = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", re.MULTILINE
    )
    for m in port_re.finditer(raw):
        port, proto, state, service, version = m.groups()
        r.open_ports.append(
            {
                "port":    port,
                "proto":   proto,
                "state":   state,
                "service": service,
                "version": version.strip()[:60],
            }
        )

    # CVE / vulnerability flags
    cve_re = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
    r.cve_flags = list(dict.fromkeys(cve_re.findall(raw)))  # dedupe, preserve order

    # Script output risks (non-CVE)
    vuln_lines = re.findall(r"(?:VULNERABLE|EXPLOITABLE|CRITICAL).*", raw, re.IGNORECASE)
    for line in vuln_lines:
        cleaned = line.strip()
        if cleaned and cleaned not in r.cve_flags:
            r.cve_flags.append(cleaned[:80])


def _parse_whois(raw: str, r: ScanResult) -> None:
    def _w(patterns: list[str]) -> str:
        for p in patterns:
            val = _extract(p, raw, re.IGNORECASE | re.MULTILINE)
            if val:
                return val
        return ""

    r.registrar     = _w([r"Registrar:\s*(.+)", r"registrar:\s*(.+)"])
    r.reg_date      = _w([r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"])
    r.exp_date      = _w([r"Expir\w+ Date:\s*(.+)", r"expiry-date:\s*(.+)", r"Renewal Date:\s*(.+)"])
    r.updated_date  = _w([r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)"])
    r.org           = _w([r"Registrant Organization:\s*(.+)", r"org-name:\s*(.+)", r"organisation:\s*(.+)"])
    r.country       = _w([r"Registrant Country:\s*(.+)", r"country:\s*(.+)"])
    r.abuse_email   = _w([r"Abuse Email:\s*(.+)", r"abuse-mailbox:\s*(.+)"])

    # Name servers
    ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
    r.name_servers  = [ns.strip().lower() for ns in ns_matches if ns.strip()]


def _parse_dig(records: tuple[str, ...], r: ScanResult) -> None:
    a_raw, aaaa_raw, mx_raw, ns_raw, txt_raw, cname_raw, soa_raw = records

    # A records
    r.a_records = re.findall(r"\bA\s+([\d.]+)", a_raw)

    # AAAA records
    r.aaaa_records = re.findall(r"\bAAAA\s+([0-9a-f:]+)", aaaa_raw, re.IGNORECASE)

    # MX records: priority host
    for m in re.finditer(r"\bMX\s+(\d+)\s+(\S+)", mx_raw, re.IGNORECASE):
        r.mx_records.append({"priority": m.group(1), "host": m.group(2).rstrip(".")})

    # NS records
    r.ns_records = [
        ns.rstrip(".").strip()
        for ns in re.findall(r"\bNS\s+(\S+)", ns_raw, re.IGNORECASE)
        if ns.strip()
    ]

    # TXT records
    raw_txts = re.findall(r'\bTXT\s+"(.+?)"', txt_raw, re.IGNORECASE | re.DOTALL)
    r.txt_records = [t.replace('"\t"', "").replace('" "', "").strip() for t in raw_txts]

    # CNAME
    r.cname = _extract(r"\bCNAME\s+(\S+)", cname_raw, re.IGNORECASE).rstrip(".")

    # SOA
    soa_m = re.search(r"\bSOA\s+(\S+)\s+(\S+)", soa_raw, re.IGNORECASE)
    if soa_m:
        r.soa = f"{soa_m.group(1)} / {soa_m.group(2)}"


def _parse_whatweb(raw: str, r: ScanResult) -> None:
    # HTTP status
    r.http_status = _extract(r"\[(\d{3})\s+\w+\]", raw) or \
                    _extract(r"HTTPStatus\[(\d+)\]", raw)

    # Page title
    r.page_title = _extract(r"Title\[(.+?)\]", raw)

    # Server
    r.server = _extract(r"HTTPServer\[(.+?)\]", raw) or \
               _extract(r"Apache(?:\[(.+?)\])?", raw)

    # CMS detection – ordered preference list
    cms_candidates = [
        ("WordPress",  r"WordPress(?:\[(.+?)\])?"),
        ("Joomla",     r"Joomla(?:\[(.+?)\])?"),
        ("Drupal",     r"Drupal(?:\[(.+?)\])?"),
        ("Shopify",    r"Shopify(?:\[(.+?)\])?"),
        ("Wix",        r"Wix(?:\[(.+?)\])?"),
        ("Ghost",      r"Ghost(?:\[(.+?)\])?"),
        ("Magento",    r"Magento(?:\[(.+?)\])?"),
        ("PrestaShop", r"PrestaShop(?:\[(.+?)\])?"),
        ("TYPO3",      r"TYPO3(?:\[(.+?)\])?"),
        ("OpenCart",   r"OpenCart(?:\[(.+?)\])?"),
        ("Laravel",    r"Laravel(?:\[(.+?)\])?"),
        ("Django",     r"Django(?:\[(.+?)\])?"),
        ("Ruby on Rails", r"Ruby-on-Rails(?:\[(.+?)\])?"),
    ]
    for name, pattern in cms_candidates:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            version_part = m.group(1) if m.lastindex and m.group(1) else ""
            r.cms = f"{name} {version_part}".strip()
            break

    # Powered-by
    r.powered_by = _extract(r"X-Powered-By\[(.+?)\]", raw) or \
                   _extract(r"PoweredBy\[(.+?)\]", raw)

    # Technology stack — bracket tokens: Tool[value]
    tech_re = re.compile(
        r"(PHP|Python|Ruby|Node\.js|jQuery|Bootstrap|React|Angular|Vue|"
        r"Nginx|Apache|IIS|Cloudflare|Varnish|Webpack|ASP\.NET|"
        r"Java|Go|Perl|Symfony|CodeIgniter)"
        r"(?:\[(.+?)\])?",
        re.IGNORECASE,
    )
    seen = set()
    for m in tech_re.finditer(raw):
        tech = m.group(1)
        ver  = m.group(2) or ""
        label = f"{tech} {ver}".strip() if ver else tech
        if tech.lower() not in seen:
            seen.add(tech.lower())
            r.tech_stack.append(label)

    # Cookies
    r.cookies = re.findall(r"Cookies\[(.+?)\]", raw, re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
#  IP RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

def resolve_ip(target: str) -> str:
    try:
        # Strip scheme if present
        clean = re.sub(r"^https?://", "", target).split("/")[0]
        return socket.gethostbyname(clean)
    except socket.gaierror:
        return "Unresolved"


# ─────────────────────────────────────────────────────────────────────────────
#  RICH DISPLAY BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_header(result: ScanResult) -> Panel:
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    grid.add_row(
        Text(f"  🎯  Target : {result.target}", style="bold bright_cyan"),
        Text(f"⏰  {result.timestamp}", style="muted"),
    )
    grid.add_row(
        Text(f"  🌐  IP     : {result.ip_address}", style="bold bright_white"),
        Text("🔬  Pickaxe OSINT v2.0", style="info"),
    )
    grid.add_row(
        Text(f"  📡  Host   : {result.host_state or 'unknown'}", style="bold green"
             if result.host_state == "up" else "bold red"),
        Text(f"📶  Latency : {result.ping_latency} ms  |  Loss : {result.ping_loss}", style="value"),
    )
    return Panel(grid, border_style="bright_cyan", title="[banner]⛏  PICKAXE[/banner]", subtitle="[muted]Hybrid OSINT Recon[/muted]")


def _table_ports(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🔌  Open Ports & Services[/section]",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
        expand=True,
    )
    tbl.add_column("Port",    style="port_open",  width=8)
    tbl.add_column("Proto",   style="muted",      width=6)
    tbl.add_column("State",   width=10)
    tbl.add_column("Service", style="bold white",  width=14)
    tbl.add_column("Version / Banner", style="value")

    if not result.open_ports:
        tbl.add_row("—", "—", "—", "No open ports found", "")
        return tbl

    for p in result.open_ports:
        state_style = "[port_open]open[/port_open]" if p["state"] == "open" else f"[port_closed]{p['state']}[/port_closed]"
        tbl.add_row(p["port"], p["proto"], state_style, p["service"], p["version"])
    return tbl


def _table_cve(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🔴  Vulnerability Flags[/section]",
        box=box.SIMPLE_HEAD,
        header_style="bold red",
        border_style="red",
        expand=True,
    )
    tbl.add_column("#",   width=4,  style="muted")
    tbl.add_column("CVE / Finding", style="cve")

    if not result.cve_flags:
        tbl.add_row("—", "[success]No known CVEs detected in scan scope[/success]")
        return tbl

    for i, cve in enumerate(result.cve_flags, 1):
        tbl.add_row(str(i), cve)
    return tbl


def _table_whois(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]📋  WHOIS Registration[/section]",
        box=box.SIMPLE_HEAD,
        header_style="bold bright_yellow",
        border_style="yellow",
        expand=True,
    )
    tbl.add_column("Field",  style="field", width=20)
    tbl.add_column("Value",  style="value")

    rows = [
        ("Registrar",      result.registrar),
        ("Registered On",  result.reg_date),
        ("Expires On",     result.exp_date),
        ("Last Updated",   result.updated_date),
        ("Organisation",   result.org),
        ("Country",        result.country),
        ("Abuse Contact",  result.abuse_email),
        ("Name Servers",   " | ".join(result.name_servers) if result.name_servers else "—"),
    ]
    for field_name, value in rows:
        tbl.add_row(field_name, value or "[muted]N/A[/muted]")
    return tbl


def _table_dns(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🌍  DNS Records[/section]",
        box=box.SIMPLE_HEAD,
        header_style="bold bright_yellow",
        border_style="bright_yellow",
        expand=True,
    )
    tbl.add_column("Type",  style="field",      width=8)
    tbl.add_column("Record", style="dns_record")

    def _add_rows(rtype: str, values: list) -> None:
        for v in values:
            tbl.add_row(rtype, str(v))

    _add_rows("A",    result.a_records)
    _add_rows("AAAA", result.aaaa_records)

    for mx in result.mx_records:
        tbl.add_row("MX", f"[bold]{mx['priority']}[/bold]  {mx['host']}")

    _add_rows("NS",   result.ns_records)

    for txt in result.txt_records:
        tbl.add_row("TXT", txt[:120])

    if result.cname:
        tbl.add_row("CNAME", result.cname)
    if result.soa:
        tbl.add_row("SOA",   result.soa)

    if not (result.a_records or result.aaaa_records or result.mx_records or
            result.ns_records or result.txt_records or result.cname or result.soa):
        tbl.add_row("—", "[muted]No DNS records resolved[/muted]")

    return tbl


def _table_web(result: ScanResult) -> Table:
    tbl = Table(
        title="[section]🌐  Web Fingerprint[/section]",
        box=box.SIMPLE_HEAD,
        header_style="bold bright_magenta",
        border_style="magenta",
        expand=True,
    )
    tbl.add_column("Attribute", style="field",   width=18)
    tbl.add_column("Value",     style="value")

    rows = [
        ("HTTP Status",    result.http_status),
        ("Page Title",     result.page_title),
        ("CMS / Platform", result.cms),
        ("Web Server",     result.server),
        ("Powered By",     result.powered_by),
        ("OS Guess",       result.os_guess),
        ("Cookies",        " | ".join(result.cookies) if result.cookies else ""),
        ("Technologies",   ", ".join(result.tech_stack) if result.tech_stack else ""),
    ]
    for attr, val in rows:
        if val:
            tbl.add_row(attr, val)
    return tbl


def _table_errors(result: ScanResult) -> Table | None:
    if not result.errors:
        return None
    tbl = Table(
        title="[warning]⚠  Scan Errors[/warning]",
        box=box.SIMPLE_HEAD,
        header_style="bold yellow",
        border_style="yellow",
        expand=True,
    )
    tbl.add_column("Module", style="field", width=12)
    tbl.add_column("Detail", style="warning")
    for module, msg in result.errors.items():
        tbl.add_row(module, msg[:200])
    return tbl


def display_results(result: ScanResult) -> None:
    console.print()
    console.print(_make_header(result))
    console.print()

    # Ports + CVE side by side
    console.print(Columns([_table_ports(result), _table_cve(result)], equal=False, expand=True))
    console.print()

    # WHOIS + DNS side by side
    console.print(Columns([_table_whois(result), _table_dns(result)], equal=False, expand=True))
    console.print()

    # Web fingerprint full width
    console.print(_table_web(result))
    console.print()

    # Error table (conditional)
    err_tbl = _table_errors(result)
    if err_tbl:
        console.print(err_tbl)
        console.print()

    console.print(Rule(style="bright_blue"))
    console.print(
        f"[muted]  Scan completed at {datetime.now().strftime('%H:%M:%S')} — "
        f"{len(result.open_ports)} open ports  |  "
        f"{len(result.cve_flags)} CVE/vuln flags  |  "
        f"{len(result.txt_records)} TXT records[/muted]"
    )
    console.print(Rule(style="bright_blue"))


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
[bold bright_cyan]
 ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
 ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
 ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
 ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
 ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
 ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝[/bold bright_cyan]
[bold white]        Hybrid OSINT & Web Reconnaissance Utility[/bold white]
[muted]         Termux · Linux · v2.0.0 · MIT License[/muted]
"""


# ─────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def orchestrate(target: str, skip: list[str] | None = None) -> ScanResult:
    """
    Launch all scans in true parallel using asyncio.gather().
    Each coroutine populates a shared ScanResult dataclass in-place.
    """
    result  = ScanResult(target=target)
    skip    = skip or []

    # Resolve IP synchronously before async launch
    clean_target = re.sub(r"^https?://", "", target).split("/")[0]
    result.ip_address = resolve_ip(clean_target)

    tasks: dict[str, Any] = {}

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        pid = progress.add_task("[info]Launching parallel scans…[/info]", total=None)

        coros = []
        labels = []

        if "nmap" not in skip:
            coros.append(run_nmap(clean_target, result))
            labels.append("nmap")
        if "whois" not in skip:
            coros.append(run_whois(clean_target, result))
            labels.append("whois")
        if "dig" not in skip:
            coros.append(run_dig(clean_target, result))
            labels.append("dig")
        if "whatweb" not in skip:
            coros.append(run_whatweb(target, result))
            labels.append("whatweb")
        if "ping" not in skip:
            coros.append(run_ping(clean_target, result))
            labels.append("ping")

        progress.update(pid, description=f"[info]Running: {', '.join(labels)}…[/info]")
        await asyncio.gather(*coros, return_exceptions=False)
        progress.update(pid, description="[success]All scans complete![/success]")

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _usage() -> None:
    console.print(Panel(
        """[field]Usage:[/field]
  [bright_white]python hybrid_osint.py [OPTIONS] <target>[/bright_white]

[field]Positional:[/field]
  [value]<target>[/value]        Domain, hostname, or IP address

[field]Options:[/field]
  [value]-h, --help[/value]      Show this help message
  [value]--check[/value]         Run dependency check and exit
  [value]--install[/value]       Run setup.sh to install all dependencies and exit
  [value]--skip <modules>[/value] Comma-separated list of modules to skip
                 (nmap, whois, dig, whatweb, ping)
  [value]--force[/value]         Skip dependency check and scan anyway

[field]First time?[/field]
  [bright_cyan]bash setup.sh[/bright_cyan]                      # auto-installs everything
  [bright_cyan]python hybrid_osint.py --install[/bright_cyan]   # same, from inside Python

[field]Examples:[/field]
  [bright_cyan]python hybrid_osint.py example.com[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --skip nmap,ping 192.168.1.1[/bright_cyan]
  [bright_cyan]python hybrid_osint.py --check[/bright_cyan]
  [bright_cyan]python hybrid_osint.py https://target.org --force[/bright_cyan]
""",
        title="[banner]⛏  Pickaxe Help[/banner]",
        border_style="bright_cyan",
    ))


def main() -> None:
    args = sys.argv[1:]

    # No args
    if not args:
        console.print(BANNER)
        _usage()
        sys.exit(0)

    # Help
    if "-h" in args or "--help" in args:
        console.print(BANNER)
        _usage()
        sys.exit(0)

    # Dependency check only
    if "--check" in args:
        console.print(BANNER)
        ok = print_dependency_report()
        if not ok:
            console.print(
                "\n[info]Tip:[/info] Run [cyan]bash setup.sh[/cyan] or "
                "[cyan]python hybrid_osint.py --install[/cyan] to fix missing tools."
            )
        sys.exit(0 if ok else 1)

    # Install mode — run setup.sh and exit
    if "--install" in args:
        console.print(BANNER)
        setup_path = _find_setup_sh()
        if not setup_path:
            console.print(
                "[error]✘  setup.sh not found.[/error] "
                "Make sure setup.sh is in the same directory as hybrid_osint.py."
            )
            sys.exit(1)
        console.print(f"[info]  Running:[/info] [cyan]{setup_path}[/cyan]")
        console.print(Rule(style="bright_blue"))
        ret = subprocess.run(["bash", str(setup_path)], check=False)
        sys.exit(ret.returncode)

    # Parse flags
    force  = "--force" in args
    skip: list[str] = []

    if "--skip" in args:
        idx = args.index("--skip")
        if idx + 1 < len(args):
            skip = [s.strip().lower() for s in args[idx + 1].split(",")]
            args.pop(idx + 1)
        args.pop(idx if "--skip" in args else 0)

    # Strip known flags to find target
    clean_args = [a for a in args if not a.startswith("--")]
    if not clean_args:
        console.print("[error]✘  No target specified.[/error]")
        _usage()
        sys.exit(1)

    target = clean_args[0]

    # ─── Print banner
    console.print(BANNER)
    console.print(Rule(style="bright_blue"))
    console.print(f"[info]  Target  :[/info] [bold bright_white]{target}[/bold bright_white]")
    console.print(f"[info]  Skipping:[/info] [muted]{', '.join(skip) if skip else 'nothing'}[/muted]")
    console.print(Rule(style="bright_blue"))
    console.print()

    # ─── Dependency check + auto-install prompt
    if not force:
        found, missing = check_dependencies()
        tools_to_skip = [t for t in missing if t not in skip]

        if tools_to_skip:
            print_dependency_report()

            # Offer to run setup.sh automatically
            installed = auto_install_prompt(tools_to_skip)

            if installed:
                # Re-check after install
                found2, still_missing = check_dependencies()
                tools_to_skip = [t for t in still_missing if t not in skip]
                if tools_to_skip:
                    console.print(
                        f"[warning]⚠  Still missing after install (will skip):[/warning] "
                        f"[muted]{', '.join(tools_to_skip)}[/muted]"
                    )
            # Whatever is still missing gets skipped rather than crashing
            skip = list(set(skip + tools_to_skip))
            console.print()

    # ─── Run
    start = time.monotonic()
    try:
        result = asyncio.run(orchestrate(target, skip=skip))
    except KeyboardInterrupt:
        console.print("\n[warning]⚠  Scan interrupted by user.[/warning]")
        sys.exit(130)

    elapsed = time.monotonic() - start
    console.print(f"\n[success]✔  Total acquisition time: {elapsed:.2f}s[/success]\n")

    display_results(result)


if __name__ == "__main__":
    main()
