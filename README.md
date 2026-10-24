# port-scanner

A simple TCP port scanner in pure Python (only the standard library, no pip installs).

I'm a computer engineering student learning networking (working on CCNA) and
security, so I built this to understand how port scanning actually works
under the hood.

## What it does

- Opens a TCP connection to every port in the chosen range
- Ports that accept the connection are open, and get printed in green with
  their usual service name: `[+] open  port 22     (ssh)`
- Tries to grab the service banner, so you see stuff like
  `> SSH-2.0-OpenSSH_6.6.1p1` under open ports (not every service sends one)
- Two ways to run it: a menu that loops (so you can scan multiple hosts in
  a row), or normal command line arguments

## How to run it

Just run it with no arguments and answer the questions:

```
python port_scanner.py
```

Or pass arguments directly:

```
python port_scanner.py scanme.nmap.org                 # scan common ports
python port_scanner.py 192.168.1.1 -m all              # all 65535 ports (slow)
python port_scanner.py 192.168.1.1 -m custom -p 22,80,443,8000-8100
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
connection succeeded, so the port is open. Anything else means closed or
filtered, so it gets skipped.

It checks ports one by one, so a full 65535 port scan takes a while —
that's the tradeoff for keeping the code simple.

## Legal note

Only scan systems you own or have permission to test.
`scanme.nmap.org` is a machine Nmap set up exactly for this, so it's a
safe target to try. Scanning hosts without permission is illegal in
most countries.

## Ideas for later

- [x] grab the service banner after connecting (to show what software is running)
- [ ] option to save results to a file
- [ ] UDP scanning
