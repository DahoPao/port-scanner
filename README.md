# port-scanner

A simple TCP connect port scanner written in pure Python (`socket.socket`, no external libraries).

Built as a learning project while studying networking (CCNA) and security fundamentals.

## What it does

- Connects to each port in the chosen range using a TCP connect scan
- Shows open ports in green with their common service name (`[+] open port 22 (ssh)`)

## Usage

```bash
# scan the most common ports (default)
python port_scanner.py scanme.nmap.org

# scan ALL 65535 ports (slower)
python port_scanner.py scanme.nmap.org -m all

# custom list: single ports and ranges
python port_scanner.py 192.168.1.1 -m custom -p 22,80,443,8000-8100

# tweak the timeout
python port_scanner.py 192.168.1.1 -t 0.5
```

Options:

| Flag | Meaning | Default |
|------|---------|---------|
| `-m / --mode` | `common`, `all`, or `custom` | `common` |
| `-p / --ports` | ports for custom mode (`22,80,443` or `1-1024`) | — |
| `-t / --timeout` | seconds to wait per connection | `1.0` |

## How it works

For every port the scanner creates a TCP socket, sets a timeout, and calls
`connect_ex()` against `(ip, port)`. A return value of `0` means the
connection succeeded, so the port is open. Any other result is skipped.
It checks ports one by one, so a full 65535 port scan takes a while —
that's the tradeoff for keeping the code simple.

## Legal note

Only scan systems you own or have explicit written permission to test
(for example, `scanme.nmap.org`, which Nmap provides for this purpose).
Scanning hosts without permission is illegal in most countries.

## TODO / ideas

- [ ] service version detection (banner grabbing)
- [ ] `-o` option to save results to a file
- [ ] UDP scan mode
