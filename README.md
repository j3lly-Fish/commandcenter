# Command Center

A home lab network monitoring dashboard. Scan your network, pull Proxmox stats, and browse everything from a single web page.

![Dashboard tabs: Network · Proxmox · Port Explorer · Topology](https://img.shields.io/badge/Python-3.x%20stdlib%20only-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## What's included

| Script | What it does |
|--------|-------------|
| `scan_network.sh` | nmap sweep of your subnet → saves XML to `scan_results/` |
| `generate_diagram.py` | Parses scan results → generates a Mermaid network diagram |
| `proxmox_inventory.sh` | SSHs into your Proxmox host → saves VM/CT/storage inventory |
| `dashboard.py` | Serves the web dashboard at `http://localhost:8080` |

---

## Getting started

### Prerequisites

- Python 3 (no pip packages required)
- `nmap` installed and in your PATH
- SSH access to your Proxmox host (optional — dashboard works without it)

### 1. Scan your network

Edit `scan_network.sh` and set your subnet (default: `192.168.40.0/24`), then run:

```bash
./scan_network.sh
```

This creates `scan_results/detailed_scan_<timestamp>.xml`.

### 2. Generate the network diagram (optional)

```bash
python3 generate_diagram.py
```

Outputs `network_diagram.md` and `network_diagnosis.md`.

### 3. Pull Proxmox inventory (optional)

Edit `proxmox_inventory.sh` and set your Proxmox host IP and username, then:

```bash
./proxmox_inventory.sh
```

Outputs `proxmox_inventory.txt`.

### 4. Start the dashboard

```bash
python3 dashboard.py
```

Open **http://localhost:8080** in your browser.

To use a different port:

```bash
PORT=9000 python3 dashboard.py
```

---

## Dashboard tabs

- **Network** — searchable device table with type badges, MAC/vendor, open ports, and OS. Click any row to expand port details. Click a type badge to filter by that device type.
- **Proxmox** — host info, VM and container list with RAM/CPU usage bars, storage pools.
- **Port Explorer** — all open ports aggregated across every host. Filter by port number or service name.
- **Topology** — interactive Mermaid network diagram rendered from your scan data.

Hit **Refresh** at any time to re-parse the latest scan files without restarting the server.

---

## Sensitive files

The following are excluded from this repo via `.gitignore` — they contain live network data specific to your environment:

- `proxmox_inventory.txt`
- `network_diagnosis.md`
- `scan_results/`
