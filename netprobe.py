
#!/usr/bin/env python3
"""
NetProbe - Network Reconnaissance Tool
=======================================
A CLI tool for host discovery, port scanning, and service banner grabbing.
Built as a cybersecurity portfolio project.

Author: [Your Name]
Usage:  sudo python3 netprobe.py --target 192.168.1.1
        sudo python3 netprobe.py --target 192.168.1.0/24 --ports 22,80,443
        sudo python3 netprobe.py --target scanme.nmap.org --ports 1-1000

NOTE: Only scan hosts you own or have explicit permission to scan.
"""

import socket
import struct
import sys
import os
import argparse
import ipaddress
import concurrent.futures
from datetime import datetime

# ─────────────────────────────────────────────
# ANSI colour codes for terminal output
# Makes the output easier to read at a glance
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ─────────────────────────────────────────────
# ICMP PING  (raw sockets — requires sudo)
# ─────────────────────────────────────────────
# ICMP (Internet Control Message Protocol) is the protocol behind the
# classic `ping` command.  We craft a raw ICMP Echo Request packet by
# hand so you can see exactly what's being sent over the wire.
#
# Packet layout (8 bytes header + optional data):
#   [type 1B][code 1B][checksum 2B][id 2B][seq 2B]
#
# type=8  → Echo Request (we send this)
# type=0  → Echo Reply   (host sends this back if alive)
# ─────────────────────────────────────────────

def checksum(data: bytes) -> int:
    """
    Calculate the ICMP checksum.
    The checksum lets the receiver verify the packet wasn't corrupted.
    We sum every 16-bit word, fold the carry bits back in, then invert.
    """
    s = 0
    # Process data 2 bytes at a time
    for i in range(0, len(data) - 1, 2):
        # '!' = network (big-endian) byte order, 'H' = unsigned short (2 bytes)
        s += (data[i] << 8) + data[i + 1]
    # If data length is odd, handle the last byte
    if len(data) % 2:
        s += data[-1] << 8
    # Fold 32-bit sum into 16 bits by adding the carry
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    # Invert all bits (one's complement)
    return ~s & 0xFFFF


def icmp_ping(host: str, timeout: float = 1.0) -> bool:
    """
    Send a single ICMP Echo Request and return True if we get a reply.

    Why raw sockets?  Normal sockets are TCP/UDP — they work at the
    transport layer.  ICMP lives at the network layer, so we need
    socket.SOCK_RAW to bypass the transport layer entirely.
    """
    try:
        # AF_INET = IPv4 family
        # SOCK_RAW = raw socket (no TCP/UDP header added automatically)
        # IPPROTO_ICMP = tell the kernel we're speaking ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        # Build the ICMP header with a placeholder checksum of 0
        # struct.pack format:  'bbHHh'
        #   b = signed byte      → type (8 = Echo Request)
        #   b = signed byte      → code (0)
        #   H = unsigned short   → checksum (0 placeholder)
        #   H = unsigned short   → packet id (use our process id mod 65535)
        #   h = signed short     → sequence number (1)
        icmp_id  = os.getpid() % 65535
        header   = struct.pack("bbHHh", 8, 0, 0, icmp_id, 1)
        payload  = b"netprobe"        # Arbitrary data payload
        chk      = checksum(header + payload)
        # Rebuild header with real checksum
        header   = struct.pack("bbHHh", 8, 0, chk, icmp_id, 1)
        packet   = header + payload

        sock.sendto(packet, (host, 0))   # port is ignored for ICMP
        sock.recvfrom(1024)              # wait for any reply
        sock.close()
        return True
    except (socket.timeout, PermissionError, OSError):
        return False


# ─────────────────────────────────────────────
# TCP CONNECT SCAN
# ─────────────────────────────────────────────
# The most basic active port scan.  We attempt a full TCP three-way
# handshake (SYN → SYN-ACK → ACK).  If the handshake completes, the
# port is OPEN.  If the target sends RST, it's CLOSED.  If nothing
# comes back, it's FILTERED (a firewall is silently dropping our SYN).
#
# This is what Nmap calls a "TCP Connect scan" (-sT flag).
# It's louder than a SYN scan but doesn't require raw sockets.
# ─────────────────────────────────────────────

def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Return True if TCP port is open (handshake succeeded).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # connect_ex returns 0 on success instead of raising an exception
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0    # 0 means the connection was accepted
    except OSError:
        return False


# ─────────────────────────────────────────────
# BANNER GRABBING
# ─────────────────────────────────────────────
# Many services (SSH, FTP, SMTP, HTTP) send a "banner" — a text string
# identifying the software and version — as soon as you connect.
# Grabbing banners is one of the first things a pentester does because
# version info helps find known CVEs (Common Vulnerabilities and Exposures).
#
# Example SSH banner:  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
# ─────────────────────────────────────────────

# Well-known port → service name mapping
# Used when socket.getservbyport() doesn't know the port
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    222:  "SSH",
    2222: "SSH",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# For HTTP ports, we send a request so the server responds with headers
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to an open port and try to read the service banner.
    Returns a cleaned string, or empty string if nothing is received.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # HTTP-like ports won't send anything until we ask first
        if port in (80, 8080, 8000, 8888):
            sock.send(HTTP_PROBE)
        elif port in (443, 8443):
            # HTTPS requires TLS — skip banner for now
            sock.close()
            return "(TLS — use openssl s_client for banner)"

        # Read up to 1024 bytes of the response
        raw = sock.recv(1024)
        sock.close()

        # Decode bytes → string, ignoring characters we can't decode
        # Strip whitespace and control characters for clean display
        banner = raw.decode("utf-8", errors="ignore").strip()
        # Take only the first line (banners can be long)
        banner = banner.split("\n")[0].strip()
        return banner[:120]  # cap at 120 chars
    except Exception:
        return ""


def guess_service(port: int) -> str:
    """Return a human-readable service name for a port number."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        # Python's built-in service database (from /etc/services on Linux)
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ─────────────────────────────────────────────
# HOST DISCOVERY  (ping sweep)
# ─────────────────────────────────────────────
# When given a subnet like 192.168.1.0/24, we ping every address to
# find which hosts are alive before scanning ports.
# Running pings in parallel (ThreadPoolExecutor) keeps it fast.
# ─────────────────────────────────────────────

def discover_hosts(network_str: str, timeout: float = 1.0) -> list:
    """
    Ping-sweep a subnet and return a list of live host IPs.
    Works on a single IP too — just returns [ip] if it responds.
    """
    live = []

    # ipaddress module understands CIDR notation like 192.168.1.0/24
    try:
        net = ipaddress.ip_network(network_str, strict=False)
        hosts = list(net.hosts())   # .hosts() skips network + broadcast addresses
    except ValueError:
        # Not a network — treat as single host
        hosts = [ipaddress.ip_address(network_str)]

    if len(hosts) == 1:
        ip = str(hosts[0])
        if icmp_ping(ip, timeout):
            return [ip]
        # Even if ICMP is blocked, the host might still have open ports
        # Return it anyway so we still scan it
        return [ip]

    print(f"{CYAN}[*] Pinging {len(hosts)} addresses in {network_str}...{RESET}")

    # ThreadPoolExecutor runs multiple pings at the same time
    # max_workers=50 means up to 50 simultaneous pings
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        # Map each IP address to the icmp_ping function
        results = ex.map(lambda h: (str(h), icmp_ping(str(h), timeout)), hosts)
        for ip, alive in results:
            if alive:
                live.append(ip)

    return live


# ─────────────────────────────────────────────
# PORT RANGE PARSER
# ─────────────────────────────────────────────

def parse_ports(port_str: str) -> list:
    """
    Convert a port string into a sorted list of integers.
    Supports:  "80"          → [80]
               "22,80,443"   → [22, 80, 443]
               "1-1024"      → [1, 2, ..., 1024]
               "22,80,1000-1010" → mixed
    """
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))   # deduplicate and sort


# ─────────────────────────────────────────────
# PORT SCANNER  (threaded)
# ─────────────────────────────────────────────

def scan_ports(host: str, ports: list, timeout: float = 1.0, workers: int = 100) -> list:
    """
    Scan a list of ports on a single host. Returns list of open port dicts.
    Uses threading so we don't scan one port at a time (that would take forever).
    """
    open_ports = []

    def check_port(port):
        if tcp_connect(host, port, timeout):
            service = guess_service(port)
            banner  = grab_banner(host, port)
            return {"port": port, "service": service, "banner": banner}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort results by port number for clean output
    return sorted(open_ports, key=lambda x: x["port"])


# ─────────────────────────────────────────────
# REVERSE DNS LOOKUP
# ─────────────────────────────────────────────
# Turns an IP address back into a hostname (if one exists in DNS).
# e.g.  8.8.8.8  →  dns.google
# ─────────────────────────────────────────────

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


# ─────────────────────────────────────────────
# OUTPUT / REPORTING
# ─────────────────────────────────────────────

def print_banner():
    print(f"""
{CYAN}{BOLD}
  _   _      _   ____            _
 | \\ | | ___| |_|  _ \\ _ __ ___ | |__   ___
 |  \\| |/ _ \\ __| |_) | '__/ _ \\| '_ \\ / _ \\
 | |\\  |  __/ |_|  __/| | | (_) | |_) |  __/
 |_| \\_|\\___|\\__|_|   |_|  \\___/|_.__/ \\___|
{RESET}
 {YELLOW}Network Reconnaissance Tool — Portfolio Project{RESET}
 {RED}Only scan systems you own or have permission to scan.{RESET}
""")


def print_host_result(ip: str, hostname: str, open_ports: list):
    """Pretty-print the scan results for one host."""
    label = f"{ip}"
    if hostname:
        label += f" ({hostname})"

    print(f"\n{GREEN}{BOLD}[+] Host: {label}{RESET}")
    print(f"    {'PORT':<8} {'SERVICE':<14} {'BANNER'}")
    print(f"    {'─'*8} {'─'*14} {'─'*40}")

    if not open_ports:
        print(f"    {YELLOW}No open ports found in scanned range.{RESET}")
        return

    for p in open_ports:
        port_str    = f"{p['port']}/tcp"
        service_str = p["service"]
        banner_str  = p["banner"] if p["banner"] else "—"
        print(f"    {GREEN}{port_str:<8}{RESET} {CYAN}{service_str:<14}{RESET} {banner_str}")


def save_report(results: list, filename: str):
    """Write a plain-text report to disk for the portfolio."""
    with open(filename, "w") as f:
        f.write(f"NetProbe Scan Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        for host_data in results:
            ip       = host_data["ip"]
            hostname = host_data["hostname"]
            ports    = host_data["ports"]
            f.write(f"Host: {ip}")
            if hostname:
                f.write(f" ({hostname})")
            f.write("\n")
            if ports:
                f.write(f"  {'PORT':<10} {'SERVICE':<14} BANNER\n")
                for p in ports:
                    f.write(f"  {str(p['port'])+'/tcp':<10} {p['service']:<14} {p['banner']}\n")
            else:
                f.write("  No open ports found.\n")
            f.write("\n")
    print(f"\n{CYAN}[*] Report saved to {filename}{RESET}")


# ─────────────────────────────────────────────
# ARGUMENT PARSER  (CLI interface)
# ─────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description="NetProbe — network recon tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 netprobe.py --target 192.168.1.1
  sudo python3 netprobe.py --target 192.168.1.0/24
  sudo python3 netprobe.py --target scanme.nmap.org --ports 1-1000
  sudo python3 netprobe.py --target 10.0.0.1 --ports 22,80,443,3306 --output report.txt
        """
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="IP address, hostname, or CIDR subnet  (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--ports", "-p", default="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443",
        help="Ports to scan. Examples: 80  |  22,80,443  |  1-1024\n(default: common ports)"
    )
    parser.add_argument(
        "--timeout", default=1.0, type=float,
        help="Socket timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--threads", default=100, type=int,
        help="Max parallel threads for port scanning (default: 100)"
    )
    parser.add_argument(
        "--output", "-o", default="",
        help="Save report to this file (e.g. report.txt)"
    )
    return parser


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    # Warn if not running as root (ICMP ping requires raw socket privileges)
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Warning: not running as root. "
              f"ICMP ping disabled — TCP-only scan.{RESET}\n")

    ports = parse_ports(args.ports)
    print(f"{CYAN}[*] Target  : {args.target}{RESET}")
    print(f"{CYAN}[*] Ports   : {len(ports)} ports{RESET}")
    print(f"{CYAN}[*] Timeout : {args.timeout}s{RESET}")
    print(f"{CYAN}[*] Threads : {args.threads}{RESET}")
    print(f"{CYAN}[*] Started : {datetime.now().strftime('%H:%M:%S')}{RESET}\n")

    # ── Step 1: resolve hostname to IP if needed ──────────────────────
    target = args.target
    try:
        # If it's already an IP or CIDR, ip_network won't raise
        ipaddress.ip_network(target, strict=False)
        resolved = target
    except ValueError:
        # It's a hostname — resolve it
        try:
            resolved = socket.gethostbyname(target)
            print(f"{CYAN}[*] Resolved {target} → {resolved}{RESET}\n")
        except socket.gaierror:
            print(f"{RED}[!] Cannot resolve hostname: {target}{RESET}")
            sys.exit(1)

    # ── Step 2: host discovery ────────────────────────────────────────
    if os.geteuid() == 0:
        live_hosts = discover_hosts(resolved)
    else:
        # Without root, skip ICMP and scan directly
        live_hosts = [resolved]

    if not live_hosts:
        print(f"{RED}[!] No live hosts found.{RESET}")
        sys.exit(0)

    print(f"{GREEN}[+] {len(live_hosts)} host(s) to scan.{RESET}\n")

    # ── Step 3: port scan + banner grab ──────────────────────────────
    all_results = []
    for ip in live_hosts:
        hostname = reverse_dns(ip)
        print(f"{CYAN}[*] Scanning {ip} ({hostname or 'no rDNS'}) — {len(ports)} ports...{RESET}")

        open_ports = scan_ports(ip, ports, args.timeout, args.threads)
        print_host_result(ip, hostname, open_ports)

        all_results.append({"ip": ip, "hostname": hostname, "ports": open_ports})

    # ── Step 4: optional report file ─────────────────────────────────
    if args.output:
        save_report(all_results, args.output)

    # ── Summary ───────────────────────────────────────────────────────
    total_open = sum(len(h["ports"]) for h in all_results)
    print(f"\n{BOLD}[*] Scan complete. "
          f"{len(all_results)} host(s) | {total_open} open port(s) found.{RESET}")
    print(f"    Finished: {datetime.now().strftime('%H:%M:%S')}\n")


if __name__ == "__main__":
    main()
