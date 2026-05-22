# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Int3rcept0r** — a Raspberry Pi Zero configured as a USB-to-Ethernet gadget for authorized penetration testing. The device sits in-line between a target computer and its Ethernet cable, bridging traffic through `usb0` ↔ `eth0` while running MITM/backdoor modules at boot.

Intended deployment: SSH into `192.168.220.1` (user `pi`, password `raspberry`) after plugging the Pi into a target machine via USB.

## Running the Tool

```bash
sudo python main.py
```

Select a module by number (0–8). Modules that configure startup behavior write startup commands into `/etc/rc.local` (injected before `exit 0`); they take effect on the **next reboot**. Multiple modules can be armed by running `main.py` multiple times.

## Architecture

All logic lives in `main.py` as a single `choice` class. Each method either:
- **Modifies `/etc/rc.local`** to arm a module at next boot (pas, arp, rev_ssh, rev_net, rev_met, power_only)
- **Modifies live system config files and restarts services** (dns, dns_dnsmasq, rst)

| Module | File modified | Tool used |
|--------|--------------|-----------|
| `pas` | `/etc/rc.local` | `pas/pas.py` → Ettercap unified sniff on `eth0` |
| `arp` | `/etc/rc.local` | `arp/arp.py` → Ettercap ARP spoof on `eth0` |
| `dns` | `/etc/dnsmasq.conf`, `/etc/hosts` | dnsmasq restarted live |
| `dns_dnsmasq` | `/etc/dnsmasq.conf`, `/etc/dnsmasq.hosts` | dnsmasq restarted live |
| `rev_ssh` | `/etc/rc.local` | autossh persistent reverse tunnel |
| `rev_net` | `/etc/rc.local`, `rev_net/nc.sh` | netcat reverse shell loop |
| `rev_met` | `/etc/rc.local`, `met/shell.py` | Python Meterpreter reverse TCP |
| `power_only` | `/etc/rc.local` | disables IP forwarding |
| `rst` | All of the above | restores from `default_files/` |

**`met/shell.py`** is generated at runtime from `met/default/shell.py` — the template contains literal placeholders `host` and `l_port` that are replaced with user-supplied values.

**`default_files/`** holds the canonical baseline configs used by `rst` (reset module).

**`dns/hosts`** is the DNS spoofing host file — edit this before running dns modules to define spoofed domain→IP mappings.

## System Dependencies (on the Pi)

- `ettercap-text-only` — password sniffing and ARP spoofing
- `dnsmasq` — DHCP server and DNS for the `usb0` subnet (`192.168.220.0/24`)
- `autossh` — persistent reverse SSH tunnel
- `netcat-traditional` (not OpenBSD nc) — reverse shell
- `metasploit` on the listener machine — for Meterpreter module

Log files land in:
- `pas/log/` — Ettercap unified sniff logs
- `arp/log/` — Ettercap ARP spoof logs
