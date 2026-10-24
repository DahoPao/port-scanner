# simple tcp port scanner
# only scan hosts you have permission to scan (scanme.nmap.org is ok to use)

import socket
import argparse

# some ports that usually have services running
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                3306, 3389, 5432, 8080]

# service names so the output looks nicer
SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "rpc", 139: "netbios",
            143: "imap", 443: "https", 445: "smb", 3306: "mysql",
            3389: "rdp", 5432: "postgres", 8080: "http-proxy"}

GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def check_port(host, port, timeout=1.0):
    # connect_ex returns 0 if the connection worked, other numbers for errors
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0


def get_ports(args):
    if args.mode == "common":
        return COMMON_PORTS
    if args.mode == "all":
        return range(1, 65536)

    # custom mode: takes stuff like "22,80,443" or "1-1024" or both mixed
    ports = []
    for part in args.ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports += list(range(int(start), int(end) + 1))
        elif part:
            ports.append(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(description="simple tcp port scanner")
    parser.add_argument("host", help="host to scan (ip or name)")
    parser.add_argument("-m", "--mode", choices=["common", "all", "custom"],
                        default="common", help="which ports to scan")
    parser.add_argument("-p", "--ports", default="",
                        help="ports for custom mode, example: 22,80,443")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="timeout per port in seconds")
    args = parser.parse_args()

    if args.mode == "custom" and not args.ports:
        print("custom mode needs -p, example: -p 22,80,443")
        return

    # resolve the hostname to an ip
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print("could not resolve host:", args.host)
        return

    ports = get_ports(args)
    print(f"{YELLOW}[*] scanning {args.host} ({ip}), {len(ports)} ports{RESET}")

    open_ports = []
    for port in ports:
        try:
            if check_port(ip, port, args.timeout):
                print(f"{GREEN}[+] open  port {port:<6} ({SERVICES.get(port, '?')}){RESET}")
                open_ports.append(port)
        except KeyboardInterrupt:
            print("\nstopped by user")
            return

    print(f"\n[*] done, {len(open_ports)} open ports:",
          ", ".join(str(p) for p in open_ports) if open_ports else "none")


main()
