# port-scanner

A simple TCP connect port scanner written in pure Python (`socket.socket`, no external libraries).

Built as a learning project while studying networking (CCNA) and security fundamentals.

## What it does

- Connects to each port in the chosen range using a TCP connect scan
- Shows open ports in green with their common service name (`[+] Open port 22 (ssh)`)
- Uses threads to scan many ports at once instead of one-by-one

## Usage

```bash
# scan the most common ports (default)
python port_scanner.py scanme.nmap.org

# scan ALL 65535 ports (slower)
python port_scanner.py scanme.nmap.org -m all

# custom list: single ports and ranges
python port_scanner.py 192.168.1.1 -m custom -p 22,80,443,8000-8100

# tweak timing and speed
python port_scanner.py 192.168.1.1 -t 0.5 -w 500
```

Options:

| Flag | Meaning | Default |
|------|---------|---------|
| `-m / --mode` | `common`, `all`, or `custom` | `common` |
| `-p / --ports` | ports for custom mode (`22,80,443` or `1-1024`) | — |
| `-t / --timeout` | seconds to wait per connection | `1.0` |
| `-w / --workers` | simultaneous connections | `200` |

## How it works

Each scan task creates a TCP socket, sets a timeout, and calls
`connect_ex()` against `(ip, port)`. A return value of `0` means the
three-way handshake succeeded, so the port is open. Any other result
(closed or filtered) is silently skipped. `ThreadPoolExecutor` runs
many of these checks in parallel, which is what makes scanning even
the full 65535-port range practical.

## Legal note

Only scan systems you own or have explicit written permission to test
(for example, `scanme.nmap.org`, which Nmap provides for this purpose).
Scanning hosts without permission is illegal in most countries.

## TODO / ideas

- [ ] service version detection (banner grabbing)
- [ ] `-o` option to save results to a file
- [ ] UDP scan mode
