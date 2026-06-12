<div align="center">

```
 ██████╗ ██╗ ██████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
 ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝██╔════╝
 ██████╔╝██║██║     █████╔╝ ███████║ ╚███╔╝ █████╗
 ██╔═══╝ ██║██║     ██╔═██╗ ██╔══██║ ██╔██╗ ██╔══╝
 ██║     ██║╚██████╗██║  ██╗██║  ██║██╔╝ ██╗███████╗
 ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
```

**Hybrid OSINT & Website Reconnaissance Utility**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-brightgreen?logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/Version-2.1.0-cyan)
![Setup](https://img.shields.io/badge/Setup-Zero--Touch-orange)

*Parallel OSINT intelligence gathering — Nmap · WHOIS · DNS · WhatWeb · Ping*

</div>

---

## ⚡ Features

| Module | What It Does |
|--------|-------------|
| **Nmap** | Full TCP SYN + version scan, vuln scripts, OS fingerprinting, CVE flag extraction |
| **WHOIS** | Registrar, registration/expiry dates, org, country, abuse contact, nameservers |
| **DNS/Dig** | A, AAAA, MX, NS, TXT, CNAME, SOA record enumeration |
| **WhatWeb** | CMS detection (WordPress/Joomla/Drupal/etc.), tech stack, server, HTTP status |
| **Ping** | ICMP latency, packet loss percentage, TTL |
| **Rich UI** | Beautiful terminal tables, side-by-side panels, progress spinners, CVE highlighting |

### Architecture Highlights

- ✅ **Zero-touch install** — one command installs every system binary and Python package automatically
- ✅ **Runtime auto-install** — missing tools trigger an interactive install prompt at scan time
- ✅ **True parallel execution** — all 5 scanners run simultaneously via `asyncio.gather()`
- ✅ **Fail-safe dependency checks** — detects, installs, then re-verifies before scanning
- ✅ **Robust regex parsers** — handles varied output formats across distros and tool versions
- ✅ **Zero crash policy** — all subprocess errors are caught and surfaced cleanly
- ✅ **Termux-native** — tested on Android via Termux, no root required for most scans

---

## 📦 Installation

> **One command installs everything.** No manual steps. No copy-pasting shell commands.
> `setup.sh` auto-detects your environment and handles every dependency end-to-end.

### Step 1 — Clone

```bash
git clone https://github.com/your-username/pickaxe.git
cd pickaxe
```

### Step 2 — Run the zero-touch installer

```bash
bash setup.sh
```

**That's it.** The script handles everything automatically:

| Step | What Happens |
|------|-------------|
| 🔍 Detect OS | Identifies Termux / Debian / Kali / Arch / RHEL / Fedora automatically |
| 📦 Update index | Refreshes package manager repos before installing |
| 🔧 System tools | Installs `nmap`, `whois`, `dnsutils`, `ruby`, `python3`, `curl`, `wget` |
| 🕸️ WhatWeb | Tries `apt install whatweb` first; falls back to `gem install whatweb` automatically |
| 🐍 pip | Bootstraps pip via `ensurepip` → `get-pip.py` download if pip is missing |
| 📚 Python pkgs | Installs packages from `requirements.txt` (retries with `--user` if needed) |
| 🔐 Permissions | Marks `hybrid_osint.py` as executable (`chmod +x`) |
| ✅ Verify | Prints a full status table showing path of every installed binary |

### Alternative: trigger install from inside Python

If you already have Python but haven't run `setup.sh`:

```bash
python hybrid_osint.py --install
```

### Verify everything is ready

```bash
python hybrid_osint.py --check
```

---

### Platform support

| Platform | Package Manager | WhatWeb Source |
|----------|----------------|----------------|
| **Termux (Android)** | `pkg` | `gem install whatweb` |
| **Debian / Ubuntu / Kali** | `apt-get` | `apt-get install whatweb` |
| **Arch Linux** | `pacman` | `pacman -S whatweb` → gem fallback |
| **RHEL / CentOS / Fedora** | `dnf` / `yum` | `gem install whatweb` |

> **Termux users:** No root required. All packages install into your Termux user prefix.
> **Linux users:** `sudo` is invoked automatically only where the package manager requires it.

### setup.sh modes

```bash
bash setup.sh            # full auto install (default)
bash setup.sh --check    # verify only, no changes made
bash setup.sh --repair   # re-install only what's still missing
```

---

## 🚀 Usage

```
python hybrid_osint.py [OPTIONS] <target>
```

### Positional Argument

| Argument | Description |
|----------|-------------|
| `<target>` | Domain name, hostname, or IP address |

### Options

| Flag | Description |
|------|-------------|
| `-h, --help` | Display help and exit |
| `--check` | Run dependency check only; exits 0 if all found, 1 if missing |
| `--install` | Run `setup.sh` to install all dependencies, then exit |
| `--skip <modules>` | Comma-separated modules to skip: `nmap,whois,dig,whatweb,ping` |
| `--force` | Skip dependency check and scan regardless of missing tools |

### First run (missing tools)

When you run a scan with missing dependencies, Pickaxe will **prompt you to install everything automatically** before proceeding — no separate setup step needed:

```
  ⚠  Dependencies Missing
  ✘  Missing tools detected: nmap, whois, whatweb

  Pickaxe can install everything automatically right now.
  Setup script: /data/data/com.termux/files/home/pickaxe/setup.sh

  Install all dependencies now? (y/N): y

  ── Running setup.sh ──────────────────────────────────
  ... (live output streams here) ...
  ✔  setup.sh completed. Re-checking dependencies…
```

### Examples

```bash
# Full scan on a domain (auto-installs if tools missing)
python hybrid_osint.py example.com

# Scan an IP address — web fingerprint only (skip nmap + ping)
python hybrid_osint.py --skip nmap,ping 192.168.1.100

# HTTPS target
python hybrid_osint.py https://shop.example.com

# DNS + WHOIS only — no port scan
python hybrid_osint.py --skip nmap,whatweb,ping target.org

# Install all deps then exit
python hybrid_osint.py --install

# Check dependency status
python hybrid_osint.py --check

# Force-run with whatever is installed
python hybrid_osint.py --force target.org
```

---

## 🖥️ Running in VS Code

VS Code works great as a development environment for Pickaxe — you get syntax highlighting, an integrated terminal, and one-click debug runs with `F5`.

### Prerequisites

| Requirement | Download |
|-------------|----------|
| **VS Code** | [code.visualstudio.com](https://code.visualstudio.com/) |
| **Python 3.10+** | [python.org/downloads](https://www.python.org/downloads/) |
| **Python extension** | Install from VS Code Extensions (`Ctrl+Shift+X` → search "Python" by Microsoft) |
| **bash** (Windows only) | [Git for Windows](https://git-scm.com/download/win) — provides Git Bash |

> **Windows users:** `setup.sh` and the scan tools (`nmap`, `whois`, etc.) are Linux-native.
> Use **WSL 2** (Windows Subsystem for Linux) for the best experience — see the [WSL note](#-windows-wsl-2-note) at the bottom of this section.

---

### Step 1 — Open the project

```
File → Open Folder → select the pickaxe/ directory
```

Or from the terminal:

```bash
code d:\projects\pickaxe
```

---

### Step 2 — Open the integrated terminal

```
Terminal → New Terminal   (or  Ctrl + `)
```

The terminal opens at the project root automatically.

---

### Step 3 — Install dependencies (first time only)

In the integrated terminal:

```bash
# Linux / WSL / macOS / Git Bash on Windows
bash setup.sh

# Or trigger setup from inside Python
python hybrid_osint.py --install
```

---

### Step 4 — Select your Python interpreter

1. Press `Ctrl + Shift + P`
2. Type **"Python: Select Interpreter"** and press Enter
3. Choose the Python 3.10+ interpreter shown in the list

> If you're using WSL, VS Code will show WSL-based interpreters prefixed with `WSL:`.

---

### Step 5 — Run the script

**Option A — From the integrated terminal (recommended):**

```bash
python hybrid_osint.py example.com
python hybrid_osint.py --check
python hybrid_osint.py --skip nmap,ping 192.168.1.1
```

**Option B — Press `F5` (debug mode):**

Create a `.vscode/launch.json` file in your project (see next section) and press `F5` to launch with arguments pre-filled.

---

### VS Code `launch.json` (F5 Debug Config)

Create the file `.vscode/launch.json` in your project folder with the following content:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "⛏ Pickaxe — Full Scan",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/hybrid_osint.py",
            "args": ["example.com"],
            "console": "integratedTerminal",
            "justMyCode": true
        },
        {
            "name": "⛏ Pickaxe — Dependency Check",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/hybrid_osint.py",
            "args": ["--check"],
            "console": "integratedTerminal",
            "justMyCode": true
        },
        {
            "name": "⛏ Pickaxe — Install Dependencies",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/hybrid_osint.py",
            "args": ["--install"],
            "console": "integratedTerminal",
            "justMyCode": true
        },
        {
            "name": "⛏ Pickaxe — Skip Nmap & Ping",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/hybrid_osint.py",
            "args": ["--skip", "nmap,ping", "example.com"],
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}
```

Change `"example.com"` in the args to your actual target. Press `F5` to select and run any configuration.

---

### Recommended VS Code Extensions

| Extension | Why It Helps |
|-----------|-------------|
| **Python** (Microsoft) | Syntax highlighting, IntelliSense, interpreter management |
| **Pylance** | Fast type checking and autocomplete for the codebase |
| **Shell Script** (foxundermoon) | Syntax highlighting for `setup.sh` |
| **GitLens** | Visualise git history and blame annotations |
| **Error Lens** | Inline error highlighting as you type |

Install all at once via the VS Code Extensions panel (`Ctrl+Shift+X`).

---

### 🪟 Windows + WSL 2 Note

The system tools (`nmap`, `whois`, `dig`, `whatweb`) are Linux binaries and **do not run natively on Windows**. The recommended approach for Windows users is **WSL 2**:

**1. Install WSL 2:**
```powershell
wsl --install        # opens Ubuntu by default
```

**2. Install the WSL extension in VS Code:**
```
Extensions → search "WSL" (Microsoft) → Install
```

**3. Open the project inside WSL:**
```
Ctrl+Shift+P → "WSL: Open Folder in WSL"
```

**4. Run setup and scan inside the WSL terminal:**
```bash
bash setup.sh
python hybrid_osint.py example.com
```

Everything — the Rich UI, nmap, dig, whatweb — works perfectly inside the WSL integrated terminal in VS Code.

---

## 📊 Data Index — What Pickaxe Uncovers

### 🔌 Port & Service Intelligence (Nmap)

| Field | Example |
|-------|---------|
| Open port number | `443` |
| Protocol | `tcp` / `udp` |
| Port state | `open` / `filtered` |
| Service name | `https` |
| Version / banner | `nginx 1.24.0` |
| OS detection | `Linux 5.4 (Ubuntu 20.04)` |
| Host state | `up` / `down` |

### 🔴 Vulnerability Intelligence (Nmap vuln scripts)

| Field | Example |
|-------|---------|
| CVE identifiers | `CVE-2021-44228` |
| VULNERABLE flags | `VULNERABLE: Heartbleed` |
| EXPLOITABLE tags | `EXPLOITABLE: EternalBlue` |

### 📋 Domain Registration (WHOIS)

| Field | Example |
|-------|---------|
| Registrar | `GoDaddy LLC` |
| Registration date | `2010-05-14` |
| Expiry date | `2026-05-14` |
| Last updated | `2024-01-03` |
| Organisation | `Example Corp` |
| Country | `US` |
| Abuse contact | `abuse@registrar.com` |
| Name servers | `ns1.example.com` |

### 🌍 DNS Records (Dig)

| Record Type | What It Reveals |
|-------------|----------------|
| `A` | IPv4 address(es) of the host |
| `AAAA` | IPv6 address(es) |
| `MX` | Mail server(s) with priority |
| `NS` | Authoritative name servers |
| `TXT` | SPF, DKIM, DMARC, verification tokens |
| `CNAME` | Canonical name alias |
| `SOA` | Primary nameserver + admin email |

### 🌐 Web Fingerprint (WhatWeb)

| Field | Example |
|-------|---------|
| HTTP status | `200 OK` |
| Page title | `Welcome to Example` |
| CMS platform | `WordPress [6.4.2]` |
| Web server | `nginx [1.24.0]` |
| Powered-by | `PHP/8.2.1` |
| Technology stack | `jQuery, Bootstrap, React` |
| Cookies | `PHPSESSID, _ga` |

### 📶 Network Reachability (Ping)

| Field | Example |
|-------|---------|
| Round-trip latency | `12.4 ms` |
| Packet loss | `0%` |
| TTL | `64` |

---

## 🗂 Project Structure

```
pickaxe/
├── hybrid_osint.py    ← Main executable (scan engine + auto-install prompt)
├── requirements.txt   ← Python package dependencies
├── setup.sh           ← Zero-touch system dependency installer
└── README.md          ← This file
```

---

## ⚙️ How It Works

### Dependency Install Flow

```
python hybrid_osint.py example.com
          │
          ▼
  check_dependencies()
  ┌────────────────────────────────┐
  │  All tools found?              │
  │  YES ──────────────────────►  │ proceed to scan
  │  NO                           │
  │   └─► auto_install_prompt()   │
  │         │ user types 'y'      │
  │         ▼                     │
  │    bash setup.sh (live)       │
  │         │                     │
  │         ▼                     │
  │    re-check deps              │
  │    skip still-missing only    │
  └────────────────────────────────┘
```

### Scan Execution Flow

```
         ┌──────────────────────────────┐
         │      hybrid_osint.py         │
         │  orchestrate() coroutine     │
         └──────────┬───────────────────┘
                    │  asyncio.gather()  ← ALL fire simultaneously
          ┌─────────┼──────────┬─────────────┐
          ▼         ▼          ▼             ▼
      run_nmap  run_whois  run_dig     run_whatweb  run_ping
          │         │          │             │          │
          ▼         ▼          ▼             ▼          ▼
      _parse_   _parse_    _parse_      _parse_      parse
       nmap()   whois()     dig()      whatweb()    stdout
          │         │          │             │          │
          └─────────┴──────────┴─────────────┴──────────┘
                                  │
                            ScanResult
                           dataclass
                                  │
                          display_results()
                   [Rich tables, panels, CVE highlights]
```

All five scan modules execute **simultaneously** — a 120-second Nmap scan no longer blocks WHOIS (which finishes in ~2s). Total wall-clock time equals the slowest single module.

---

## 🔧 Troubleshooting

### WhatWeb not installing?

```bash
# Termux
pkg install ruby && gem install whatweb --no-document

# Linux
sudo apt install ruby-full
gem install whatweb --no-document
# or
sudo gem install whatweb --no-document
```

### pip not found after Python install?

```bash
python3 -m ensurepip --upgrade
# or
curl https://bootstrap.pypa.io/get-pip.py | python3
```

### `dig` not found on Termux?

```bash
pkg install dnsutils
```

### Nmap requires root for SYN scan?

On Linux, Nmap's `-sS` (SYN scan) requires root. Run:
```bash
sudo python hybrid_osint.py example.com
```
On Termux, raw socket scans are not supported — Nmap falls back to TCP connect scan automatically.

### Still broken after `bash setup.sh`?

```bash
bash setup.sh --repair      # re-installs only what's missing
python hybrid_osint.py --check   # shows exactly what's found/missing
```

---

## 🛡️ Legal & Ethical Notice

> **Pickaxe is intended for authorized security testing, educational purposes, and reconnaissance on infrastructure you own or have explicit written permission to test.**
>
> Running port scans or WHOIS lookups against targets without permission may violate computer fraud laws in your jurisdiction (e.g., CFAA in the US, Computer Misuse Act in the UK).
>
> **The author assumes no liability for misuse.**

---

## 📝 License

```
MIT License

Copyright (c) 2026 Pickaxe Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

<div align="center">

Made with ⛏️ by the Pickaxe Project &nbsp;·&nbsp; Built for Termux & Linux &nbsp;·&nbsp; Python + Rich

</div>
