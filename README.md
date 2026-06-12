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
![Version](https://img.shields.io/badge/Version-2.0.0-cyan)

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

- ✅ **True parallel execution** — all 5 scanners run simultaneously via `asyncio.gather()`
- ✅ **Fail-safe dependency checks** — gracefully skips missing tools with install hints
- ✅ **Robust regex parsers** — handles varied output formats across distros
- ✅ **Zero crash policy** — all subprocess errors are caught and surfaced cleanly
- ✅ **Termux-native** — tested on Android via Termux, no root required for most scans

---

## 📦 Installation

### Option A — Automated (Recommended)

```bash
git clone https://github.com/your-username/pickaxe.git
cd pickaxe
bash setup.sh
```

`setup.sh` auto-detects your environment and handles everything.

---

### Option B — Manual

#### 🤖 Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade -y

# System tools
pkg install nmap whois dnsutils ruby python -y

# WhatWeb via RubyGems
gem install whatweb --no-document

# Python dependencies
pip install -r requirements.txt
```

#### 🐧 Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils whatweb python3 python3-pip
pip3 install -r requirements.txt
```

#### 🏹 Arch Linux

```bash
sudo pacman -Sy nmap whois bind python python-pip
pip install -r requirements.txt
# WhatWeb (if not in repos):
gem install whatweb --no-document
```

#### 🎩 RHEL / CentOS / Fedora

```bash
sudo dnf install -y nmap whois bind-utils ruby python3 python3-pip
gem install whatweb --no-document
pip3 install -r requirements.txt
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
| `--check` | Run dependency check only and exit |
| `--skip <modules>` | Comma-separated list of modules to skip |
| `--force` | Bypass dependency check and scan anyway |

### Examples

```bash
# Full scan on a domain
python hybrid_osint.py example.com

# Scan an IP address, skip nmap (faster for web-only recon)
python hybrid_osint.py --skip nmap,ping 192.168.1.100

# HTTPS target
python hybrid_osint.py https://shop.example.com

# Check all dependencies before running
python hybrid_osint.py --check

# Force-run even if some tools are missing
python hybrid_osint.py --force target.org
```

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
├── hybrid_osint.py    ← Main executable
├── requirements.txt   ← Python dependencies
├── setup.sh           ← One-command installer
└── README.md          ← This file
```

---

## ⚙️ How It Works

```
         ┌──────────────────────────────┐
         │      hybrid_osint.py         │
         │  orchestrate() coroutine     │
         └──────────┬───────────────────┘
                    │  asyncio.gather()
          ┌─────────┼──────────────────────┐
          ▼         ▼         ▼            ▼
      run_nmap  run_whois  run_dig    run_whatweb
          │         │         │            │
          ▼         ▼         ▼            ▼
      _parse_   _parse_   _parse_     _parse_
       nmap()   whois()    dig()     whatweb()
          │         │         │            │
          └─────────┴─────────┴────────────┘
                          │
                    ScanResult
                   dataclass
                          │
                    display_results()
                  [Rich console tables]
```

All five scan modules execute **simultaneously** in the same event loop, dramatically reducing total wall-clock time compared to sequential execution.

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
