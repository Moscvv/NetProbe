# NetProbe 🔍

A command-line network reconnaissance tool built in Python.  
Performs **host discovery**, **port scanning**, and **service banner grabbing** — the first three steps of any penetration test or network audit.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit written permission to scan. Unauthorised scanning is illegal in most jurisdictions.

---

## What it does

| Feature | Description |
|---|---|
| **ICMP ping sweep** | Discovers live hosts in a subnet using raw ICMP Echo Requests |
| **TCP connect scan** | Checks if ports are open via full three-way handshake |
| **Banner grabbing** | Reads service banners to identify software versions |
| **Reverse DNS** | Resolves IPs back to hostnames |
| **Concurrent scanning** | Uses threading to scan hundreds of ports in seconds |
| **Report output** | Saves results to a plain-text file |

---

## Why I built this

This project is part of my cybersecurity portfolio. The goal was to understand what tools like **Nmap** are actually doing under the hood — crafting ICMP packets with `struct`, managing raw sockets, and building a threaded scanner from scratch. Writing it myself forced me to understand TCP handshakes, ICMP checksums, and banner protocols in a way that reading about them doesn't.

---

## Technical concepts demonstrated

- **Raw socket programming** (`SOCK_RAW`, `IPPROTO_ICMP`)
- **ICMP packet construction** — manual header packing with `struct`, one's complement checksum
- **TCP three-way handshake** — connect scan logic
- **Multithreading** with `concurrent.futures.ThreadPoolExecutor`
- **CIDR notation parsing** with the `ipaddress` module
- **Service fingerprinting** via banner grabbing
- **CLI design** with `argparse`

---

## Requirements

- Python 3.8+
- Linux/macOS (raw sockets require a Unix-like OS)
- `sudo` / root privileges for ICMP ping (port scan works without root)

No external libraries required — standard library only.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/netprobe.git
cd netprobe
```

That's it. No pip install needed.

---

## Usage

```bash
# Scan a single host (common ports)
sudo python3 netprobe.py --target 192.168.1.1

# Scan a subnet — discovers live hosts first
sudo python3 netprobe.py --target 192.168.1.0/24

# Scan specific ports
sudo python3 netprobe.py --target 10.0.0.5 --ports 22,80,443,3306

# Scan a port range
sudo python3 netprobe.py --target scanme.nmap.org --ports 1-1000

# Save results to a file
sudo python3 netprobe.py --target 192.168.1.1 --output report.txt

# All options
sudo python3 netprobe.py --target TARGET --ports PORTS --timeout 1.5 --threads 150 --output report.txt
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--target` / `-t` | required | IP, hostname, or CIDR subnet |
| `--ports` / `-p` | common ports | Port list: `80`, `22,80,443`, or `1-1024` |
| `--timeout` | `1.0` | Socket timeout in seconds |
| `--threads` | `100` | Parallel threads for scanning |
| `--output` / `-o` | none | Save report to file |

---

## Example output

```
[*] Target  : 192.168.1.1
[*] Ports   : 15 ports
[*] Started : 14:32:01

[+] Host: 192.168.1.1 (router.local)
    PORT     SERVICE        BANNER
    ──────── ────────────── ────────────────────────────────────────
    22/tcp   SSH            SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    80/tcp   HTTP           HTTP/1.1 200 OK
    443/tcp  HTTPS          (TLS — use openssl s_client for banner)

[*] Scan complete. 1 host(s) | 3 open port(s) found.
    Finished: 14:32:04
```

---

## Safe testing targets

These hosts are **intentionally public scanning targets** — legal and safe to test against:

| Target | Purpose |
|---|---|
| `scanme.nmap.org` | Official Nmap test server |
| `127.0.0.1` | Your own machine |
| A VM on your local network | Full control |

---

## Limitations & future improvements

- [ ] SYN scan (requires raw sockets — stealthier than connect scan)
- [ ] UDP scanning
- [ ] OS fingerprinting via TTL analysis
- [ ] XML/JSON output format
- [ ] IPv6 support
- [ ] Nmap XML import for comparison

---

## How this compares to Nmap

| | NetProbe | Nmap |
|---|---|---|
| Purpose | Learning + portfolio | Production use |
| Speed | Good (threaded) | Excellent (optimised C) |
| Scan types | TCP connect, ICMP | 15+ scan types |
| OS detection | No | Yes |
| Scripting | No | NSE scripts |

Nmap is the right tool for real engagements. NetProbe is for understanding how it works.

---

## Author

[Your Name] — Cybersecurity student, Australia → Japan  
[LinkedIn] | [GitHub]
