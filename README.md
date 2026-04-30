# SuperNmap.py

**SuperNmap** is an advanced, highly-concurrent wrapper for `nmap` designed to optimize and automate network enumeration. It performs intelligent, multi-phased scanning to get results as fast as possible while maintaining a clean, noise-free terminal interface.

## Key Features

- **Multi-Phased Scanning**:
  - **Phase 1**: Fast, full-port TCP discovery scan.
  - **Phase 2**: Exhaustive version and script scanning (`-sV -sC -O`) targeted *only* at the open ports found in Phase 1.
  - **Phase 3 (Optional)**: UDP scanning (Top 100 or Full) that can be run in the background.
- **Concurrent Multi-Host & Network Scanning**: Scan multiple individual targets or entire CIDR ranges (with ARP or ICMP host discovery) simultaneously.
- **Interactive Live Status (SPACE)**: Terminal noise is aggressively suppressed during parallel scans. Press the `SPACE` bar at any time to view a real-time, clean progress report (with % completion and elapsed time) of all active worker threads.
- **Auto-Resolution & Naming**: Automatically attempts to resolve hostnames to keep output files cleanly named and organized.
- **Evasion & Stealth**: Built-in support for packet fragmentation, custom MTUs, decoys, source port spoofing, and disabling Layer 2 ARP pings.
- **HTML Reporting**: Automatically convert Nmap XML output to beautiful HTML reports using `xsltproc` (XML files are automatically cleaned up afterward).

---

## Usage

```bash
python3 supernmap.py <ip1> [ip2 ...] [options]
```
<img width="1545" height="940" alt="imagen" src="https://github.com/user-attachments/assets/21e65478-a7a6-4d94-ad3f-67e539fa8f3f" />


### Options

**Core & Timing:**
- `-h, --help` : Show help message.
- `--timing <0-5>` : Timing template (default is `T4` + `--min-rate 1000`).

**UDP Scanning:**
- `--udp-top` : Perform a UDP scan on the Top 100 ports after the TCP scan completes.
- `--udp-full` : Perform a full 65535-port UDP scan after TCP.
- `--udp-bg` : Run the UDP scan in the background so you can continue working while it finishes.

**Output:**
- `--html` : Save XML output and automatically convert it to HTML. Temporary XML files are deleted after successful conversion.

**Evasion & Stealth:**
- `--no-l2` : Disable OSI Layer 2 (ARP) discovery. Falls back to `-sT` for scanning.
- `--ack` : Perform an ACK scan (`-sA`) during Phase 1 instead of SYN.
- `--frag` : Fragment packets to 8 bytes (`-f`).
- `--frag-double` : Fragment packets to 16 bytes (`-ff`).
- `--mtu <N>` : Specify a custom MTU (must be a multiple of 8).
- `--decoy <N>` : Use `N` random decoy IPs (`-D RND:N`).
- `--source-port <N>` : Spoof the source port for the scan.
- `--dns-server <IP>` : Specify a custom DNS server.

**NSE Scripts:**
- `--script <name,...>` : Run specific Nmap Scripting Engine (NSE) script(s) during Phase 2.
- `--script-cat <cat>` : Run all NSE scripts from a specific category (e.g., `vuln`, `safe`).

**Naming & Multi-Host / Network Range:**
- `--name <LABEL>` : Manually override the base filename label (only works when scanning a single target).
- `--net-scan <CIDR>` : Discover active hosts in a network range and perform full 2-phase scans on all of them. Creates a dedicated output directory and a global summary file.
- `--parallel <N|all>` : Specify the number of hosts to scan simultaneously. Required when using `--net-scan`. Set to `all` to scan every discovered host concurrently.

---

## Output Structure

SuperNmap automatically saves files for each phase. If auto-resolution finds the hostname `gateway` for `192.168.1.1`:
- `ports_gateway.nmap` (Phase 1 fast scan results)
- `info_gateway.nmap` (Phase 2 exhaustive scan results)
- `UDP_gateway.nmap` (Optional Phase 3 results)

When using `--net-scan 192.168.1.0/24`:
- Output is organized into a newly created `netscan_192.168.1.0-24/` directory.
- A global summary file `netscan_summary_192.168.1.0-24.txt` is generated containing the active IPs, resolved hostnames, detected OS, and all open ports.

---

## Interactive Live Status

During parallel multi-host or `--net-scan` executions, standard Nmap output is silenced to prevent terminal formatting corruption.
**Simply press the `SPACE` bar** to display an instantly-updated dashboard showing:
- Which hosts are currently being scanned.
- The active phase (e.g., Exhaustive scanning on specific open ports).
- Real-time percentage completion.
- Elapsed time for each active worker.

---

## Examples

**1. Basic single host with Top 100 UDP:**
```bash
python3 supernmap.py 10.10.11.100 --udp-top
```

**2. Multi-host scan with slower timing:**
```bash
python3 supernmap.py 10.10.11.100 10.10.11.101 --timing 2
```

**3. Stealthy evasion scan with a custom filename:**
```bash
python3 supernmap.py 10.10.11.100 --name TargetWeb --no-l2 --frag --decoy 5 --source-port 53
```

**4. Vulnerability scanning with HTML report generation(per host):**
```bash
python3 supernmap.py 10.10.11.100 --script-cat vuln --html
```

**5. Full subnet discovery and parallel scanning (5 hosts at a time):**
```bash
python3 supernmap.py --net-scan 192.168.1.0/24 --parallel 5
```

**6. Maximum concurrency subnet scan without ARP (useful over ligolo):**
```bash
python3 supernmap.py --net-scan 10.10.10.0/24 --no-l2 --parallel all
```
