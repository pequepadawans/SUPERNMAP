# SUPERNMAP

`supernmap` is a simple Bash script that automates and optimizes your typical Nmap scanning workflow.

Instead of running a single, slow scan, `supernmap` segments the process into phases to get detailed results in the most efficient way.

## 🚀 Features

  * **Efficient Workflow:** Combines a fast all-port scan with an in-depth service & script scan *only* on the ports that matter.
  * **Organized Output:** Automatically saves the results of each phase into clearly named files (e.g., `ports_webserver.nmap`, `info_webserver.nmap`).
  * **Optional UDP Scanning:** Provides flags to add a Top-100 or a full UDP scan.
  * **Firewall Evasion:** Includes a `--timing <0-5>` option to slow down the scan and help evade firewall/IDS detection.
  * **Clean Output:** Uses a color-coded terminal interface for easy reading.

## 🔬 How It Works (The 3-Phase Scan)

1.  **Phase 1: Port Discovery (TCP)**

      * The script runs a fast scan against all 65,535 TCP ports to identify what's open.
      * It saves the results to `ports_<basename>.nmap`.

2.  **Phase 2: Deep Scan (TCP)**

      * The script reads the Phase 1 output and extracts the list of open ports.
      * It runs a detailed service and script scan (`-sV -sC`) *only* on those ports.
      * It saves the detailed results to `info_<basename>.nmap`.

3.  **Phase 3: UDP Scan (Optional)**

      * If the `--udp-top` or `--udp-full` flag is used, the script will perform a UDP scan.
      * It saves the results to `UDP_<basename>.nmap`.

## 🛠️ Installation

1.  **Make the script executable**:

    ```bash
    chmod +x /path/to/supernmap
    ```

2.  **(Recommended)** To run the command from anywhere, create a symbolic link to a directory in your `$PATH`:

    ```bash
    sudo ln -s /path/to/supernmap /usr/local/bin/supernmap
    ```

## 🖥️ Usage

```bash
supernmap <ip_address> [options]
```

The script will prompt you for a "base name," which will be used to name your output files.

### Options

| Flag | Description |
| :--- | :--- |
| `-h`, `--help` | Show the help message. |
| `--udp-top` | Run a UDP scan on the Top 100 ports (after TCP). |
| `--udp-full` | Run a full UDP scan (after TCP). |
| `--timing <0-5>` | Set the Nmap timing template (e.g., `T0` for paranoid, `T4` for aggressive). |

### 💡 Examples

**Standard TCP scan (fast):**

```bash
supernmap 10.10.11.100
```

**Slow (`T2`) TCP scan with a Top-100 UDP scan:**

```bash
supernmap 10.10.11.100 --timing 2 --udp-top
```
