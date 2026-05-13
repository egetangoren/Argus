<p align="center">
  <pre>
     ___                           
    /   |  _________ ___  _______  
   / /| | / ___/ __ `/ / / / ___/ 
  / ___ |/ /  / /_/ / /_/ (__  )  
 /_/  |_/_/   \__, /\__,_/____/   
              /____/               
  </pre>
  <strong>The All-Seeing Recon Framework</strong><br>
  <em>Named after Argus Panoptes — the hundred-eyed giant of Greek mythology</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/version-1.0.0-orange?style=flat-square" alt="Version">
</p>

---

## 🏛️ About

**Argus** is a modular, CLI-based reconnaissance framework written in Python. It is designed for Red Team professionals and security researchers who need a unified toolkit for passive and active information gathering.

The name comes from **Argus Panoptes** (Ἄργος Πανόπτης) — the all-seeing giant of Greek mythology with a hundred eyes, tasked by Hera to be an ever-watchful guardian. Like its mythological namesake, this framework sees everything: domain registration data, DNS infrastructure, hidden subdomains, open ports, running services, and web server technologies — all under one roof.

## ⚡ Features

| Module | Description |
|--------|-------------|
| **WHOIS Lookup** | Domain registration info: registrar, dates, nameservers, country, DNSSEC |
| **DNS Enumeration** | Queries A, AAAA, MX, NS, TXT, CNAME, SOA records with TTL |
| **Subdomain Bruteforce** | Multithreaded wordlist-based subdomain discovery via DNS resolution |
| **Port Scanner** | TCP connect scan with top-100 defaults or custom ranges, service detection |
| **HTTP Probe** | HTTP/HTTPS probing with status codes, titles, headers, redirect chains |
| **Banner Grabbing** | Raw socket banner capture with protocol-aware payloads |
| **Report Generator** | Dual-format output: structured JSON + human-readable TXT |

### Framework Highlights

- 🧩 **Modular Architecture** — Each module works independently or orchestrated via CLI
- 🧵 **Multithreaded Scanning** — ThreadPoolExecutor for parallel DNS, port, and HTTP operations
- 🛡️ **Robust Error Handling** — Graceful degradation with per-module exception isolation
- 📊 **Rich CLI Output** — Color-coded tables, progress bars, and real-time status updates
- 📁 **Dual Reporting** — Automatic JSON + TXT report generation
- 🔗 **Inter-Module Data Flow** — Discovered subdomains and open ports automatically feed into HTTP probe

## 📦 Installation

### Prerequisites

- Python **3.10** or higher
- `pip` package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/egetangoren/Argus.git
cd Argus

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate    # Linux / macOS
# .venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `python-whois` | WHOIS domain registration queries |
| `dnspython` | DNS record resolution and enumeration |
| `requests` | HTTP/HTTPS endpoint probing |
| `rich` | Terminal UI: tables, progress bars, styled output |

## 🚀 Usage

### Basic Syntax

```bash
python main.py -t <TARGET> [MODULES] [OPTIONS]
```

### Flags

| Flag | Description |
|------|-------------|
| `-t`, `--target` | **Required.** Target domain or IP address |
| `--all` | Run all reconnaissance modules |
| `--whois` | WHOIS registration lookup |
| `--dns` | DNS record enumeration |
| `--sub` | Subdomain brute-force enumeration |
| `--ports [RANGE]` | TCP port scan (default: top 100, or specify range) |
| `--http` | HTTP/HTTPS probe + banner grabbing |
| `--output PATH` | Custom output path (file or directory) |

### Examples

```bash
# Run all modules against a target
python main.py -t example.com --all

# WHOIS + DNS only
python main.py -t example.com --whois --dns

# Subdomain enumeration + HTTP probe
python main.py -t example.com --sub --http

# Port scan with custom range
python main.py -t example.com --ports 1-1024

# Port scan specific ports + banner grab
python main.py -t example.com --ports 22,80,443,8080 --http

# Full scan with custom output file
python main.py -t example.com --all --output results.json

# Full scan with custom output directory
python main.py -t example.com --all --output ./reports
```

### Output

Reports are saved in **two formats** by default:

- **JSON** — Machine-readable, structured data for automation pipelines
- **TXT** — Human-readable report with labelled sections and formatting

```
output/
├── argus_example_com_20260513_120000.json
└── argus_example_com_20260513_120000.txt
```

## 🏗️ Project Structure

```
Argus/
├── main.py                    # CLI entry point and orchestration engine
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── modules/
│   ├── __init__.py            # Package exports
│   ├── whois_lookup.py        # WHOIS registration queries
│   ├── dns_enum.py            # DNS record enumeration (7 types)
│   ├── subdomain_enum.py      # Multithreaded subdomain bruteforce
│   ├── port_scanner.py        # TCP connect scanner with service detection
│   ├── banner_grabber.py      # Raw socket banner grabbing
│   ├── http_probe.py          # HTTP/HTTPS probing + banner integration
│   └── reporter.py            # JSON & TXT report generator
│
├── wordlists/
│   └── subdomains.txt         # Default subdomain wordlist (120 entries)
│
└── output/                    # Generated reports directory
    └── .gitkeep
```

## 🔒 Module Details

### WHOIS Lookup
Queries WHOIS servers to retrieve domain registration data. Handles the duality of WHOIS responses where fields may return as strings or lists. Extracts 12 fields including registrar, dates, nameservers, country, organization, and DNSSEC status.

### DNS Enumeration
Queries 7 DNS record types independently, each with isolated error handling. A timeout on TXT records won't prevent NS or MX records from being collected. MX records are sorted by priority. SOA records include full zone metadata.

### Subdomain Bruteforce
Uses `ThreadPoolExecutor` with configurable thread count (default: 20) and per-query timeout. Reads from a wordlist file, resolves each candidate via DNS A-record lookup, and collects live subdomains with their IP addresses. Real-time progress bar shows completion and discovery count.

### Port Scanner
TCP connect scan using `socket.connect_ex()` for minimal overhead. Ships with a curated top-100 port list covering common services (SSH, HTTP, databases, DevOps tools). Supports custom ranges (`1-1024`), comma-separated lists (`80,443`), and mixed formats. Service names are resolved via `socket.getservbyport()`.

### HTTP Probe & Banner Grabbing
Two-phase module: first sends HTTP/HTTPS requests to the target and all discovered subdomains, collecting status codes, page titles, server headers, and redirect chains. Then connects to open ports with raw sockets using protocol-aware payloads (HTTP HEAD for web ports, generic probe for others).

### Report Generator
Consolidates all module outputs into structured reports. Supports three output modes: default directory (auto-named), explicit `.json`/`.txt` file path (auto-generates the other format), or custom directory. TXT reports use section-based formatting with headers for each module.

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
>
> - Always obtain **explicit written permission** before scanning any target.
> - Unauthorized scanning of networks, systems, or domains you do not own or have permission to test is **illegal** in most jurisdictions.
> - The developers assume **no liability** for misuse of this tool.
> - Users are solely responsible for ensuring compliance with applicable laws and regulations, including but not limited to the **Computer Fraud and Abuse Act (CFAA)**, **GDPR**, and local cybersecurity legislation.
>
> **Use responsibly. Hack ethically.**

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 👤 Author

**Ege Tangören** — Red Team Developer & Security Researcher

- GitHub: [@egetangoren](https://github.com/egetangoren)

---

<p align="center">
  <em>"Even the hundred-eyed Argus could not see everything. But we try."</em>
</p>
