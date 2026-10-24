#!/usr/bin/env python3
"""
port_scanner.py - a simple TCP connect port scanner.

Educational tool: only scan hosts you own or have permission to test.
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ports that commonly expose services on Windows, Linux and network gear.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433,
    1521, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Well-known service names, so open ports read like "80/http".
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def resolve_host(host: str) -> str:
    """Turn a hostname like example.com into an IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{RED}[!]{RESET} Could not resolve host: {host}")
        sys.exit(1)


def build_port_list(mode: str, custom: str) -> list[int]:
    """Build the list of ports to scan based on the user's choice."""
    if mode == "common":
        return COMMON_PORTS
    if mode == "all":
        return range(1, 65536)
    # custom mode: accept "80", "1-1024", or "22,80,443,8000-8100"
    ports = set()
    for part in custom.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_port(host: str, port: int, timeout: float) -> int | None:
    """Try one TCP connection. Returns the port number if open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) == 0:
            return port
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP connect port scanner")
    parser.add_argument("host", help="target host (IP or hostname)")
    parser.add_argument(
        "-m", "--mode",
        choices=["common", "all", "custom"],
        default="common",
        help="port selection: common (default), all (1-65535), or custom",
    )
    parser.add_argument(
        "-p", "--ports",
        default="",
        help="custom ports, e.g. 22,80,443 or 1-1024 (used with --mode custom)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="seconds to wait per connection (default: 1.0)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=200,
        help="number of simultaneous connections (default: 200)",
    )
    args = parser.parse_args()

    if args.mode == "custom" and not args.ports:
        print(f"{RED}[!]{RESET} --mode custom needs --ports, e.g. -p 22,80,443")
        sys.exit(1)

    ip = resolve_host(args.host)
    ports = build_port_list(args.mode, args.ports)

    print(f"{YELLOW}[*]{RESET} Scanning {args.host} ({ip})")
    print(f"{YELLOW}[*]{RESET} {len(ports)} ports, timeout {args.timeout}s, {args.workers} workers\n")

    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(scan_port, ip, p, args.timeout): p for p in ports}
            for future in as_completed(futures):
                port = future.result()
                if port is not None:
                    service = SERVICES.get(port, "?")
                    print(f"{GREEN}[+]{RESET} Open  {GREEN}port {port:<6}{RESET} ({service})")
                    open_ports.append(port)
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} Scan interrupted by user.")
        sys.exit(1)

    open_ports.sort()
    print(f"\n{YELLOW}[*]{RESET} Done. {len(open_ports)} open port(s): "
          f"{', '.join(map(str, open_ports)) if open_ports else 'none'}")


if __name__ == "__main__":
    main()
