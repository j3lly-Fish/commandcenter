#!/usr/bin/env python3
"""
generate_diagram.py — Parse nmap XML output, classify devices, produce:
  - network_diagram.md    : Mermaid LR graph with color-coded device types
  - network_diagnosis.md  : Full device report with NAS identification

Requirements: Python 3 stdlib only (no pip installs needed)
Usage: python3 generate_diagram.py [path/to/detailed_scan.xml]
       (auto-detects latest XML in scan_results/ if no arg given)
"""

import xml.etree.ElementTree as ET
import glob
import os
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_RESULTS_DIR = os.path.join(SCRIPT_DIR, "scan_results")
OUTPUT_DIAGRAM = os.path.join(SCRIPT_DIR, "network_diagram.md")
OUTPUT_DIAGNOSIS = os.path.join(SCRIPT_DIR, "network_diagnosis.md")

GATEWAY_HINT = "192.168.40.1"
PROXMOX_HINT = "192.168.40.77"
THIS_MACHINE_IP = "192.168.40.51"

NAS_PORTS = {445, 2049, 548, 5000, 5001, 8080, 8081, 8443, 9000}
NAS_KEYWORDS = [
    "synology", "qnap", "freenas", "truenas", "nas", "diskstation",
    "rackstation", "asustor", "readynas", "drobo", "buffalo",
    "terramaster", "openmediavault",
]

PROXMOX_KEYWORDS = ["proxmox", "pve", "proxmox virtual environment"]
PROXMOX_PORTS = {8006}

ROUTER_KEYWORDS = ["router", "gateway", "openwrt", "dd-wrt", "tomato",
                   "ubiquiti", "mikrotik", "asus router", "linksys", "netgear"]
ROUTER_PORTS = {53}

PRINTER_KEYWORDS = ["printer", "print server", "hp jetdirect", "epson",
                    "canon", "brother", "xerox", "ricoh", "lexmark"]
PRINTER_PORTS = {9100, 515, 631}

IOT_KEYWORDS = ["esp", "arduino", "tasmota", "shelly", "home assistant",
                "homeassistant", "mqtt", "tuya", "zigbee", "zwave"]

DESKTOP_PORTS = {3389, 5900}

MERMAID_STYLES = {
    "Router":      "fill:#ff9900,stroke:#cc7700,color:#000",
    "NAS":         "fill:#0066cc,stroke:#004499,color:#fff",
    "Proxmox":     "fill:#e5530a,stroke:#b33d00,color:#fff",
    "Printer":     "fill:#8b5cf6,stroke:#6d28d9,color:#fff",
    "Desktop":     "fill:#10b981,stroke:#059669,color:#fff",
    "IoT":         "fill:#f59e0b,stroke:#d97706,color:#000",
    "Unknown":     "fill:#6b7280,stroke:#4b5563,color:#fff",
    "ThisMachine": "fill:#ec4899,stroke:#be185d,color:#fff",
}


class Device:
    def __init__(self, ip):
        self.ip = ip
        self.hostnames = []
        self.mac = None
        self.mac_vendor = None
        self.open_ports = {}
        self.scripts = {}
        self.os_matches = []
        self.device_type = "Unknown"
        self.classification_evidence = []
        self.score = {}

    def all_text(self):
        parts = list(self.hostnames) + list(self.scripts.values()) + list(self.os_matches)
        parts += [p.get("product", "") + " " + p.get("version", "")
                  for p in self.open_ports.values()]
        return " ".join(parts).lower()

    def node_id(self):
        return "node_" + self.ip.replace(".", "_")

    def label(self):
        name = self.hostnames[0] if self.hostnames else self.ip
        ports_str = ""
        if self.open_ports:
            top_ports = sorted(self.open_ports.keys())[:4]
            ports_str = "\\nPorts: " + ",".join(str(p) for p in top_ports)
            if len(self.open_ports) > 4:
                ports_str += f"+{len(self.open_ports) - 4}"
        vendor_str = f"\\n[{self.mac_vendor}]" if self.mac_vendor else ""
        return f"{name}\\n{self.ip}\\n{self.device_type}{vendor_str}{ports_str}"


def find_latest_xml():
    pattern = os.path.join(SCAN_RESULTS_DIR, "detailed_scan_*.xml")
    candidates = glob.glob(pattern)
    if not candidates:
        candidates = [f for f in glob.glob(os.path.join(SCAN_RESULTS_DIR, "*.xml"))
                      if "ping_sweep" not in f]
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def parse_nmap_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    devices = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
        if not ip:
            continue

        device = Device(ip)

        for addr in host.findall("address"):
            if addr.get("addrtype") == "mac":
                device.mac = addr.get("addr")
                device.mac_vendor = addr.get("vendor", "") or None

        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name", "")
                if name:
                    device.hostnames.append(name)

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                portid = int(port_el.get("portid", 0))
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                port_data = {"state": "open", "service": "", "product": "", "version": ""}
                if service_el is not None:
                    port_data["service"] = service_el.get("name", "")
                    port_data["product"] = service_el.get("product", "")
                    port_data["version"] = service_el.get("version", "")

                device.open_ports[portid] = port_data

                for script_el in port_el.findall("script"):
                    sid = script_el.get("id", "")
                    sout = script_el.get("output", "")
                    for elem in script_el.findall("elem"):
                        sout += " " + (elem.text or "")
                    device.scripts[f"{sid}:{portid}"] = sout.strip()

        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                sid = script_el.get("id", "")
                sout = script_el.get("output", "")
                for elem in script_el.findall("elem"):
                    sout += " " + (elem.text or "")
                device.scripts[sid] = sout.strip()

        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                name = osmatch.get("name", "")
                accuracy = osmatch.get("accuracy", "0")
                if name:
                    device.os_matches.append(f"{name} ({accuracy}%)")

        devices.append(device)

    return devices


def classify_device(device):
    scores = {t: 0 for t in MERMAID_STYLES}
    evidence = []
    text = device.all_text()
    port_set = set(device.open_ports.keys())

    if device.ip == THIS_MACHINE_IP:
        device.device_type = "ThisMachine"
        device.classification_evidence = ["This is the scanning machine itself"]
        return

    # Proxmox
    if device.ip == PROXMOX_HINT:
        scores["Proxmox"] += 10
        evidence.append(f"IP matches known Proxmox host {PROXMOX_HINT}")
    if 8006 in port_set:
        scores["Proxmox"] += 8
        evidence.append("Port 8006 open (Proxmox web UI)")
    for kw in PROXMOX_KEYWORDS:
        if kw in text:
            scores["Proxmox"] += 5
            evidence.append(f"Keyword '{kw}' found in banners/hostnames")

    # NAS
    for p in port_set & NAS_PORTS:
        if p in {5000, 5001}:
            scores["NAS"] += 6
            evidence.append(f"Port {p} open (Synology DSM web interface)")
        elif p in {8080, 8081, 8443}:
            scores["NAS"] += 4
            evidence.append(f"Port {p} open (QNAP/NAS management interface)")
        elif p == 2049:
            scores["NAS"] += 4
            evidence.append("Port 2049 open (NFS server)")
        elif p == 548:
            scores["NAS"] += 5
            evidence.append("Port 548 open (AFP — Apple Filing Protocol)")
        elif p == 445:
            scores["NAS"] += 2
            evidence.append("Port 445 open (SMB/CIFS file sharing)")
        else:
            scores["NAS"] += 2
            evidence.append(f"Port {p} open (NAS-relevant)")
    for kw in NAS_KEYWORDS:
        if kw in text:
            scores["NAS"] += 7
            evidence.append(f"NAS keyword '{kw}' in banners/hostnames/OS")
    if any("qnap" in k.lower() for k in device.scripts):
        scores["NAS"] += 10
        evidence.append("QNAP-specific nmap script returned data")

    # Router
    if device.ip == GATEWAY_HINT:
        scores["Router"] += 8
        evidence.append(f"IP matches network gateway {GATEWAY_HINT}")
    if 53 in port_set:
        scores["Router"] += 5
        evidence.append("Port 53 open (DNS — strong router indicator)")
    for kw in ROUTER_KEYWORDS:
        if kw in text:
            scores["Router"] += 5
            evidence.append(f"Router keyword '{kw}' found")

    # Printer
    for p in port_set & PRINTER_PORTS:
        scores["Printer"] += 6
        evidence.append(f"Printer port {p} open")
    for kw in PRINTER_KEYWORDS:
        if kw in text:
            scores["Printer"] += 6
            evidence.append(f"Printer keyword '{kw}' found")

    # Desktop
    for p in port_set & DESKTOP_PORTS:
        scores["Desktop"] += 5
        evidence.append(f"Remote desktop port {p} open (RDP/VNC)")
    if "windows" in text:
        scores["Desktop"] += 3
        evidence.append("Windows OS detected")

    # IoT
    for kw in IOT_KEYWORDS:
        if kw in text:
            scores["IoT"] += 6
            evidence.append(f"IoT keyword '{kw}' found")
    if len(port_set) == 1 and 80 in port_set:
        scores["IoT"] += 2
        evidence.append("Only port 80 open (common IoT pattern)")

    active_scores = {k: v for k, v in scores.items()
                     if k not in ("Unknown", "ThisMachine") and v > 0}
    if active_scores:
        winner = max(active_scores, key=lambda k: active_scores[k])
        device.device_type = winner
    else:
        device.device_type = "Unknown"

    device.classification_evidence = evidence
    device.score = scores


def generate_mermaid(devices, xml_path):
    lines = []
    lines.append("```mermaid")
    lines.append("graph LR")
    lines.append("")

    for dtype, style in MERMAID_STYLES.items():
        lines.append(f"    classDef {dtype} {style}")
    lines.append("")

    router_node = next((d for d in devices if d.device_type == "Router"), None)
    if router_node is None:
        synth_id = "node_192_168_40_1"
        lines.append(f'    {synth_id}["Gateway\\n{GATEWAY_HINT}\\nRouter"]')
        lines.append(f"    class {synth_id} Router")
        router_node_id = synth_id
    else:
        router_node_id = router_node.node_id()

    for device in devices:
        nid = device.node_id()
        label = device.label()
        if device.device_type == "NAS":
            lines.append(f'    {nid}[("{label}")]')
        elif device.device_type in ("IoT", "Printer"):
            lines.append(f'    {nid}>"{label}"]')
        else:
            lines.append(f'    {nid}["{label}"]')
        lines.append(f"    class {nid} {device.device_type}")
    lines.append("")

    for device in devices:
        nid = device.node_id()
        if nid == router_node_id:
            continue
        if device.device_type == "Proxmox":
            lines.append(f'    {router_node_id} -->|"Hypervisor"| {nid}')
        elif device.device_type == "NAS":
            port_set = set(device.open_ports.keys())
            if port_set & {5000, 5001}:
                vendor = "Synology DSM"
            elif port_set & {8080, 8081}:
                vendor = "QNAP"
            elif 2049 in port_set:
                vendor = "NFS"
            else:
                vendor = "NAS"
            lines.append(f'    {router_node_id} -->|"{vendor}"| {nid}')
        elif device.device_type == "ThisMachine":
            lines.append(f'    {nid} -->|"scanner"| {router_node_id}')
        else:
            lines.append(f"    {router_node_id} --- {nid}")
    lines.append("")
    lines.append("```")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = [
        "# Network Diagram — 192.168.40.0/24",
        "",
        f"Generated: {scan_time}  ",
        f"Source: `{os.path.basename(xml_path)}`",
        "",
        "> Render this file in VS Code (Markdown Preview), GitHub, or Obsidian.",
        "",
    ]
    return "\n".join(header + lines)


def generate_diagnosis(devices, xml_path):
    lines = []
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# Network Diagnosis Report — 192.168.40.0/24")
    lines.append("")
    lines.append(f"Generated: {scan_time}  ")
    lines.append(f"Source: `{os.path.basename(xml_path)}`  ")
    lines.append(f"Total devices found: **{len(devices)}**")
    lines.append("")

    lines.append("## Device Summary")
    lines.append("")
    lines.append("| IP | Hostname | Type | MAC Vendor | Open Ports |")
    lines.append("|-----|----------|------|------------|------------|")
    for d in sorted(devices, key=lambda x: [int(n) for n in x.ip.split(".")]):
        hostname = d.hostnames[0] if d.hostnames else "—"
        ports = ", ".join(str(p) for p in sorted(d.open_ports.keys())[:8])
        if len(d.open_ports) > 8:
            ports += f" (+{len(d.open_ports) - 8})"
        vendor = d.mac_vendor or "—"
        lines.append(f"| `{d.ip}` | {hostname} | **{d.device_type}** | {vendor} | {ports or '—'} |")
    lines.append("")

    lines.append("## NAS Detection Results")
    lines.append("")
    nas_devices = [d for d in devices if d.device_type == "NAS"]
    if nas_devices:
        for nas in nas_devices:
            lines.append(f"### NAS Found: `{nas.ip}`")
            if nas.hostnames:
                lines.append(f"- Hostname: `{', '.join(nas.hostnames)}`")
            if nas.mac_vendor:
                lines.append(f"- MAC Vendor: {nas.mac_vendor}")
            lines.append(f"- Open Ports: {', '.join(str(p) for p in sorted(nas.open_ports.keys()))}")
            lines.append(f"- NAS detection score: {nas.score.get('NAS', 0)}")
            lines.append("- Detection evidence:")
            for ev in nas.classification_evidence:
                lines.append(f"  - {ev}")
            port_set = set(nas.open_ports.keys())
            if port_set & {5000, 5001}:
                lines.append("- **Vendor: Synology** (ports 5000/5001 = DSM web interface)")
            elif port_set & {8080, 8081}:
                lines.append("- **Vendor: QNAP** (ports 8080/8081 = QTS web interface)")
            elif 9000 in port_set:
                lines.append("- **Vendor: TrueNAS/FreeNAS** (port 9000 = web UI)")
            elif 2049 in port_set and 445 in port_set:
                lines.append("- **Vendor: Generic NAS** (NFS + SMB both active)")
            lines.append("")
    else:
        lines.append("> **No NAS detected automatically.**")
        lines.append(">")
        lines.append("> The NAS may be offline, may block ICMP (not found in ping sweep),")
        lines.append("> or may use non-standard ports. Check 'Unknown' devices below.")
        lines.append("> If you know the NAS IP, re-scan it directly:")
        lines.append("> ```")
        lines.append("> nmap -Pn -sT -sV -p 22,80,443,139,445,548,2049,5000,5001,8080,8081,8443,9000 <NAS_IP>")
        lines.append("> ```")
        lines.append("")

    lines.append("## Per-Device Details")
    lines.append("")
    for d in sorted(devices, key=lambda x: [int(n) for n in x.ip.split(".")]):
        lines.append(f"### `{d.ip}` — {d.device_type}")
        if d.hostnames:
            lines.append(f"- **Hostnames**: {', '.join(d.hostnames)}")
        if d.mac:
            lines.append(f"- **MAC**: `{d.mac}` ({d.mac_vendor or 'unknown vendor'})")
        if d.os_matches:
            lines.append(f"- **OS**: {d.os_matches[0]}")
        if d.open_ports:
            lines.append("- **Open Ports**:")
            for port, info in sorted(d.open_ports.items()):
                svc = info.get("service", "")
                prod = info.get("product", "")
                ver = info.get("version", "")
                desc = " — ".join(filter(None, [svc, prod, ver]))
                lines.append(f"  - `{port}/tcp`: {desc or 'unknown service'}")
        if d.scripts:
            lines.append("- **Script Output**:")
            for script_id, output in d.scripts.items():
                if output:
                    lines.append(f"  - `{script_id}`: {output[:300]}")
        if d.classification_evidence:
            lines.append("- **Classification Evidence**:")
            for ev in d.classification_evidence:
                lines.append(f"  - {ev}")
        lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) > 1:
        xml_path = sys.argv[1]
        if not os.path.exists(xml_path):
            print(f"[ERROR] File not found: {xml_path}", file=sys.stderr)
            sys.exit(1)
    else:
        xml_path = find_latest_xml()
        if not xml_path:
            print(f"[ERROR] No scan XML found in {SCAN_RESULTS_DIR}/", file=sys.stderr)
            print("        Run scan_network.sh first.", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Using latest scan: {xml_path}")

    print("[+] Parsing nmap XML...")
    devices = parse_nmap_xml(xml_path)
    print(f"[+] Found {len(devices)} devices")

    print("[+] Classifying devices...")
    TYPE_ICONS = {"NAS": "NAS", "Router": "Router", "Proxmox": "Proxmox",
                  "Unknown": "?", "ThisMachine": "THIS"}
    for device in devices:
        classify_device(device)
        icon = TYPE_ICONS.get(device.device_type, device.device_type)
        print(f"    [{icon:^10}]  {device.ip:16}  ports: {sorted(device.open_ports.keys())}")

    print("[+] Generating Mermaid diagram...")
    diagram = generate_mermaid(devices, xml_path)
    with open(OUTPUT_DIAGRAM, "w", encoding="utf-8") as f:
        f.write(diagram)
    print(f"[+] Saved: {OUTPUT_DIAGRAM}")

    print("[+] Generating diagnosis report...")
    diagnosis = generate_diagnosis(devices, xml_path)
    with open(OUTPUT_DIAGNOSIS, "w", encoding="utf-8") as f:
        f.write(diagnosis)
    print(f"[+] Saved: {OUTPUT_DIAGNOSIS}")

    nas_list = [d for d in devices if d.device_type == "NAS"]
    print("")
    print("=" * 52)
    if nas_list:
        for nas in nas_list:
            hostname = nas.hostnames[0] if nas.hostnames else "no hostname"
            print(f"[NAS FOUND]  {nas.ip}  —  {hostname}")
            nas_open = sorted(set(nas.open_ports.keys()) & NAS_PORTS)
            print(f"             NAS-relevant ports open: {nas_open}")
    else:
        print("[!] NAS not auto-detected. Check network_diagnosis.md")
        print("    for 'Unknown' devices and the fallback scan command.")
    print("=" * 52)
    print(f"\nDiagram  : {OUTPUT_DIAGRAM}")
    print(f"Diagnosis: {OUTPUT_DIAGNOSIS}")


if __name__ == "__main__":
    main()
