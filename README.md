# supernmap

**supernmap** is a Bash script that automates and optimizes your Nmap scanning workflow.

Instead of running a single slow scan, supernmap segments the process into **phases** to get detailed results in the most efficient way, with built-in evasion techniques, NSE script support, and automatic HTML report generation.

---

## 🚀 Features

- **Efficient 3-phase workflow** — fast all-port discovery, then deep scan only on open ports, optional UDP.
- **HTML reports** — generate visual reports via `xsltproc` and serve them instantly with Python's HTTP server.
- **Firewall & IDS evasion** — ACK scan, packet fragmentation, custom MTU, decoys, source port spoofing.
- **DNS evasion** — custom DNS server support for DMZ environments.
- **NSE scripts** — run any script or full category (vuln, brute, discovery, etc.) in Phase 2.
- **Background UDP** — run UDP scans in parallel while you keep working.
- **Organized output** — color-coded terminal, clearly named files per phase.

---

## 🔬 How It Works (3-Phase Scan)

| Phase | What it does | Output file |
|---|---|---|
| **Phase 1** | Fast TCP scan across all 65,535 ports | `ports_<name>.nmap` |
| **Phase 2** | Deep `-sV -sC` scan on discovered open ports only | `info_<name>.nmap` |
| **Phase 3** | Optional UDP scan (top-100 or full) | `UDP_<name>.nmap` |

When `--html` is used, each phase also generates a `.xml` + `.html` report.

---

## 🛠 Installation

```bash
chmod +x /path/to/supernmap

# (Optional) make it available system-wide
sudo ln -s /path/to/supernmap /usr/local/bin/supernmap
```

**Dependencies:** `nmap`, `xsltproc` (for HTML output), `python3` (for HTTP server).

---

## 🖥 Usage

```
supernmap <ip_address> [options]
```

The script will prompt you for a **base name** used to name all output files (e.g., `WebServer` → `ports_WebServer.nmap`).

---

## ⚙ Options

### General
| Flag | Description |
|---|---|
| `-h, --help` | Show the help message. |
| `--timing <0-5>` | Nmap timing template. Default: `-T4 --min-rate 1000`. Use lower values to evade IDS. |

### UDP
| Flag | Description |
|---|---|
| `--udp-top` | UDP scan on Top 100 ports (after TCP phases). |
| `--udp-full` | Full UDP scan on all ports (after TCP phases). |
| `--udp-bg` | Run the UDP scan in the **background** (parallel). Default is sequential. |

### Output
| Flag | Description |
|---|---|
| `--html` | Save scans as XML and auto-convert to HTML via `xsltproc`. |
| `--serve [port]` | Start a `python3 -m http.server` to view HTML reports in the browser. Implies `--html`. Default port: `8080`. |

### Evasion
| Flag | Description |
|---|---|
| `--ack` | ACK scan (`-sA`) in Phase 1 — evades stateless firewalls. |
| `--frag` | Fragment packets at 8 bytes (`-f`). |
| `--frag-double` | Fragment packets at 16 bytes (`-ff`). |
| `--mtu <N>` | Custom MTU (must be a multiple of 8). |
| `--decoy <N>` | Add N random decoy IPs (`-D RND:N`) to disguise the origin. |
| `--source-port <N>` | Spoof source port (e.g. `53` to pass through misconfigured firewalls). |
| `--dns-server <IP>` | Use a custom DNS server — useful inside DMZ to resolve internal hostnames. |

### NSE Scripts
| Flag | Description |
|---|---|
| `--script <name,...>` | Run specific NSE script(s) in Phase 2 (comma-separated). |
| `--script-cat <cat>` | Run all NSE scripts from a category in Phase 2. |

**Available categories:** `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`

---

## 💡 Examples

```bash
# Standard TCP scan
supernmap 10.10.11.100

# TCP + Top-100 UDP, slow timing
supernmap 10.10.11.100 --timing 2 --udp-top

# Generate HTML report and serve it in the browser
sudo supernmap 10.10.11.100 --html --serve 8080

# Evasion: fragmentation + decoys + source port 53
sudo supernmap 10.10.11.100 --frag --decoy 5 --source-port 53

# Source port 53 TCP (bypass misconfigured firewall)
sudo supernmap 10.10.11.100 --source-port 53 --html

# DMZ: use internal DNS server to resolve internal hostnames
sudo supernmap 10.10.11.100 --dns-server 10.10.10.1

# Vulnerability scan (NSE category)
sudo supernmap 10.10.11.100 --script-cat vuln --html

# Specific NSE scripts
sudo supernmap 10.10.11.100 --script http-title,ssl-cert

# Full UDP in background while you work
sudo supernmap 10.10.11.100 --udp-full --udp-bg
```

---

## 📄 Output Files

| File | Content |
|---|---|
| `ports_<name>.nmap` | Phase 1 raw output |
| `info_<name>.nmap` | Phase 2 deep scan output |
| `UDP_<name>.nmap` | Phase 3 UDP output |
| `*.xml` | XML output (when `--html` is used) |
| `*.html` | HTML report (when `--html` is used) |
| `UDP_<name>.log` | UDP stdout log (when `--udp-bg` is used) |

---

## ⚠ Notes on Evasion

- **`--frag` / `--frag-double` / `--mtu`** are ineffective against **stateful firewalls** (modern `iptables` with connection tracking). They also break OS detection (`-O`).
- **`--decoy`** requires the decoy IPs to be **alive**; dead decoys can trigger SYN-flood protections.
- **`--source-port 53`** exploits misconfigured firewalls that blindly trust DNS traffic. Pair with `-Pn` to skip ICMP ping.
- **`--dns-server`** is most powerful when used from a compromised host inside a DMZ.
