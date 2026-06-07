#!/usr/bin/env python3
"""Command Center — network monitoring dashboard (stdlib only)
Usage: python3 dashboard.py  →  open http://localhost:8080
"""

import glob
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_RESULTS_DIR = os.path.join(SCRIPT_DIR, "scan_results")
PORT = int(os.environ.get("PORT", 8080))

GATEWAY_IP = "192.168.40.1"
PROXMOX_IP = "192.168.40.77"
THIS_MACHINE = "192.168.40.51"

NAS_PORTS = {445, 2049, 548, 5000, 5001, 8080, 8081, 8443, 9000}
NAS_KEYWORDS = ["synology", "qnap", "freenas", "truenas", "nas", "diskstation",
                "rackstation", "asustor", "readynas", "drobo", "buffalo",
                "terramaster", "openmediavault"]
PROXMOX_KEYWORDS = ["proxmox", "pve", "proxmox virtual environment"]
ROUTER_KEYWORDS = ["router", "gateway", "openwrt", "dd-wrt", "tomato",
                   "ubiquiti", "mikrotik", "asus router", "linksys", "netgear"]
PRINTER_KEYWORDS = ["printer", "print server", "hp jetdirect", "epson",
                    "canon", "brother", "xerox", "ricoh", "lexmark"]
PRINTER_PORTS = {9100, 515, 631}
IOT_KEYWORDS = ["esp", "arduino", "tasmota", "shelly", "home assistant",
                "homeassistant", "mqtt", "tuya", "zigbee", "zwave"]
DESKTOP_PORTS = {3389, 5900}


# ── Parsers ────────────────────────────────────────────────────────────────

def find_latest_xml():
    pattern = os.path.join(SCAN_RESULTS_DIR, "detailed_scan_*.xml")
    candidates = glob.glob(pattern)
    if not candidates:
        candidates = [f for f in glob.glob(os.path.join(SCAN_RESULTS_DIR, "*.xml"))
                      if "ping_sweep" not in f]
    return max(candidates, key=os.path.getmtime) if candidates else None


def _classify_host(ip, port_set, text):
    if ip == THIS_MACHINE:
        return "ThisMachine"
    scores = {t: 0 for t in ["Router", "NAS", "Proxmox", "Printer", "Desktop", "IoT"]}

    if ip == PROXMOX_IP:
        scores["Proxmox"] += 10
    if 8006 in port_set:
        scores["Proxmox"] += 8
    for kw in PROXMOX_KEYWORDS:
        if kw in text:
            scores["Proxmox"] += 5

    for p in port_set & NAS_PORTS:
        scores["NAS"] += 6 if p in {5000, 5001} else 5 if p == 548 else 4 if p in {2049, 8080, 8081, 8443} else 2
    for kw in NAS_KEYWORDS:
        if kw in text:
            scores["NAS"] += 7

    if ip == GATEWAY_IP:
        scores["Router"] += 8
    if 53 in port_set:
        scores["Router"] += 5
    for kw in ROUTER_KEYWORDS:
        if kw in text:
            scores["Router"] += 5

    for p in port_set & PRINTER_PORTS:
        scores["Printer"] += 6
    for kw in PRINTER_KEYWORDS:
        if kw in text:
            scores["Printer"] += 6

    for p in port_set & DESKTOP_PORTS:
        scores["Desktop"] += 5
    if "windows" in text:
        scores["Desktop"] += 3

    for kw in IOT_KEYWORDS:
        if kw in text:
            scores["IoT"] += 6
    if len(port_set) == 1 and 80 in port_set:
        scores["IoT"] += 2

    active = {k: v for k, v in scores.items() if v > 0}
    return max(active, key=active.get) if active else "Unknown"


def _compute_key_service(ports, scripts):
    bad = {"403 forbidden", "404 not found", "400 bad request",
           "401 unauthorized", "500 internal server error", ""}
    for key, val in scripts.items():
        if key.startswith("http-title:") and val.strip().lower() not in bad:
            return val.strip()[:60]
    for p in sorted(ports, key=lambda x: x["port"]):
        if p["service"] in ("http", "https", "http-proxy") and p["product"]:
            label = p["product"] + (" " + p["version"] if p["version"] else "")
            return label[:60]
    seen = []
    for p in sorted(ports, key=lambda x: x["port"]):
        if p["service"] and p["service"] not in seen:
            seen.append(p["service"])
    return ", ".join(seen[:3])


def parse_nmap_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ts = root.get("start")
    scan_time = (datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
                 if ts else root.get("startstr", "unknown"))

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = vendor = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or None
        if not ip:
            continue

        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                if hn.get("name"):
                    hostname = hn.get("name")
                    break

        ports, scripts = [], {}
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                portid = int(port_el.get("portid", 0))
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc = port_el.find("service")
                ports.append({
                    "port": portid,
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                    "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                })
                for script_el in port_el.findall("script"):
                    sid = script_el.get("id", "")
                    if sid == "http-title":
                        for elem in script_el.findall("elem"):
                            if elem.get("key") == "title":
                                t = (elem.text or "").strip()
                                if t:
                                    scripts[f"http-title:{portid}"] = t
                    else:
                        out = script_el.get("output", "")
                        for elem in script_el.findall("elem"):
                            out += " " + (elem.text or "")
                        scripts[f"{sid}:{portid}"] = out.strip()

        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                sid = script_el.get("id", "")
                out = script_el.get("output", "")
                for elem in script_el.findall("elem"):
                    out += " " + (elem.text or "")
                scripts[sid] = out.strip()

        os_name, os_acc = "", 0
        os_el = host.find("os")
        if os_el is not None:
            om = os_el.find("osmatch")
            if om is not None:
                os_name = om.get("name", "")
                os_acc = int(om.get("accuracy", 0))

        port_set = {p["port"] for p in ports}
        text = " ".join([hostname, vendor or "", os_name,
                         " ".join(p["product"] + " " + p["version"] for p in ports),
                         " ".join(scripts.values())]).lower()

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac or "",
            "vendor": vendor or "",
            "type": _classify_host(ip, port_set, text),
            "ports": ports,
            "scripts": scripts,
            "os": os_name,
            "os_accuracy": os_acc,
            "key_service": _compute_key_service(ports, scripts),
        })

    return hosts, scan_time


def _get_sections(content):
    sections = {}
    matches = list(re.finditer(r'^=== (.+?) ===$', content, re.MULTILINE))
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.end() + 1
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        sections[name] = content[start:end]
    return sections


def _parse_yaml_list(text):
    items, cur = [], {}
    for line in text.splitlines():
        if line.startswith("- "):
            if cur:
                items.append(cur)
            cur = {}
            rest = line[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                cur[k.strip()] = v.strip().strip("'")
        elif line.startswith("  ") and ":" in line:
            k, v = line.strip().split(":", 1)
            cur[k.strip()] = v.strip().strip("'")
    if cur:
        items.append(cur)
    return items


def _parse_configs(section_text, marker):
    configs = {}
    pat = rf'--- {marker} (\d+) config ---\n(.*?)(?=--- (?:VM|CT) \d+ (?:config|status) ---|$)'
    for m in re.finditer(pat, section_text, re.DOTALL):
        vmid = int(m.group(1))
        cfg = {}
        for kv in re.finditer(r'^(\S+):\s+(.+)$', m.group(2), re.MULTILINE):
            cfg[kv.group(1)] = kv.group(2).strip()
        disk_m = re.search(r'size=(\d+[GMK])',
                           cfg.get("scsi0", "") + cfg.get("virtio0", "") + cfg.get("rootfs", ""))
        ip_m = re.search(r'\bip=(\d{1,3}(?:\.\d{1,3}){3})', cfg.get("net0", ""))
        # VMs use DHCP; extract MAC so build_api_data can cross-ref nmap for the IP
        mac_m = re.search(r'(?:virtio|e1000|vmxnet3|rtl8139|ne2k_pci|pcnet)=([0-9A-Fa-f:]{17})',
                          cfg.get("net0", ""), re.IGNORECASE)
        configs[vmid] = {
            "name": cfg.get("name") or cfg.get("hostname") or f"{marker}-{vmid}",
            "cores": int(cfg.get("cores", 1)),
            "memory_mb": int(cfg.get("memory", 0)),
            "disk_size": disk_m.group(1) if disk_m else None,
            "ip": ip_m.group(1) if ip_m else None,
            "mac": mac_m.group(1).upper() if mac_m else None,
            "features": cfg.get("features", ""),
        }
    return configs


def parse_proxmox_inventory(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    sec = _get_sections(content)
    result = {
        "version": "unknown", "kernel": "unknown",
        "cpu_model": "unknown", "cpu_cores": 0,
        "ram_total_mb": 0, "ram_used_mb": 0,
        "vms": [], "containers": [], "storage": [],
    }

    ver_sec = sec.get("PROXMOX VERSION", "")
    m = re.search(r'^proxmox-ve:\s+(\S+)', ver_sec, re.MULTILINE)
    if m:
        result["version"] = m.group(1)

    node_sec = sec.get("NODE STATUS", "")
    kern_m = re.search(r'release:\s+(\S+)', node_sec)
    if kern_m:
        result["kernel"] = kern_m.group(1)

    cpu_block_m = re.search(r'^cpuinfo:\n((?:[ \t]+.+\n)*)', node_sec, re.MULTILINE)
    if cpu_block_m:
        blk = cpu_block_m.group(1)
        cm = re.search(r'model:\s+(.+)', blk)
        nm = re.search(r'cpus:\s+(\d+)', blk)
        if cm:
            result["cpu_model"] = cm.group(1).strip()
        if nm:
            result["cpu_cores"] = int(nm.group(1))

    mem_block_m = re.search(r'^memory:\n((?:[ \t]+.+\n)*)', node_sec, re.MULTILINE)
    if mem_block_m:
        blk = mem_block_m.group(1)
        tm = re.search(r'total:\s+(\d+)', blk)
        um = re.search(r'used:\s+(\d+)', blk)
        if tm:
            result["ram_total_mb"] = int(tm.group(1)) // (1024 * 1024)
        if um:
            result["ram_used_mb"] = int(um.group(1)) // (1024 * 1024)

    vm_cfgs = _parse_configs(sec.get("VM CONFIGURATIONS", ""), "VM")
    ct_cfgs = _parse_configs(sec.get("CONTAINER CONFIGURATIONS", ""), "CT")

    for item in _parse_yaml_list(sec.get("CLUSTER RESOURCES", "")):
        t = item.get("type", "")
        vmid_str = item.get("vmid", "")

        if t in ("qemu", "lxc") and vmid_str:
            try:
                vmid = int(vmid_str)
            except ValueError:
                continue
            cfg = (vm_cfgs if t == "qemu" else ct_cfgs).get(vmid, {})
            entry = {
                "vmid": vmid,
                "name": item.get("name") or cfg.get("name", f"{t}-{vmid}"),
                "status": item.get("status", "unknown"),
                "cores": cfg.get("cores") or int(float(item.get("maxcpu", 1))),
                "memory_mb": cfg.get("memory_mb") or int(item.get("maxmem", 0)) // (1024 * 1024),
                "disk_size": cfg.get("disk_size"),
                "ip": cfg.get("ip"),
                "mac": cfg.get("mac"),
                "cpu_pct": round(float(item.get("cpu", 0)) * 100, 1),
                "mem_used_mb": int(item.get("mem", 0)) // (1024 * 1024),
                "uptime": int(item.get("uptime", 0)),
            }
            if t == "lxc":
                entry["features"] = cfg.get("features", "")
                result["containers"].append(entry)
            else:
                result["vms"].append(entry)

        elif t == "storage":
            storage_name = item.get("storage", "")
            if not storage_name:
                continue
            total = int(item.get("maxdisk", 0) or 0)
            used = int(item.get("disk", 0) or 0)
            result["storage"].append({
                "name": storage_name,
                "type": item.get("plugintype", ""),
                "status": item.get("status", "unknown"),
                "total_gb": round(total / (1024 ** 3), 1),
                "used_gb": round(used / (1024 ** 3), 1),
                "pct": round(used / total * 100, 1) if total else 0,
            })

    result["vms"].sort(key=lambda x: x["vmid"])
    result["containers"].sort(key=lambda x: x["vmid"])
    return result


def extract_mermaid_source(md_path):
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'```mermaid\n(.*?)```', content, re.DOTALL)
    return m.group(1).strip() if m else ""


def build_api_data():
    result = {"scan_time": None, "hosts": [], "proxmox": None,
              "diagram_source": "", "errors": []}

    xml_path = find_latest_xml()
    if xml_path:
        try:
            result["hosts"], result["scan_time"] = parse_nmap_xml(xml_path)
        except Exception as e:
            result["errors"].append(f"nmap XML parse failed: {e}")
    else:
        result["errors"].append("No scan XML found — run scan_network.sh first.")

    inv = os.path.join(SCRIPT_DIR, "proxmox_inventory.txt")
    if os.path.exists(inv):
        try:
            result["proxmox"] = parse_proxmox_inventory(inv)
        except Exception as e:
            result["errors"].append(f"Proxmox inventory parse failed: {e}")
    else:
        result["errors"].append("proxmox_inventory.txt not found — run proxmox_inventory.sh.")

    # Cross-reference VM MACs with nmap data to recover DHCP-assigned IPs
    if result["proxmox"] and result["hosts"]:
        mac_to_ip = {h["mac"].upper(): h["ip"] for h in result["hosts"] if h.get("mac")}
        for vm in result["proxmox"].get("vms", []):
            if vm.get("ip") is None and vm.get("mac"):
                vm["ip"] = mac_to_ip.get(vm["mac"])

    diag = os.path.join(SCRIPT_DIR, "network_diagram.md")
    if os.path.exists(diag):
        try:
            result["diagram_source"] = extract_mermaid_source(diag)
        except Exception as e:
            result["errors"].append(f"Diagram parse failed: {e}")

    return result


# ── HTML Template ──────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Command Center</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class'}</script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
*{box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif}
.tab-btn{padding:.5rem 1rem;border-bottom:2px solid transparent;color:#9ca3af;cursor:pointer;font-size:.875rem;white-space:nowrap}
.tab-btn:hover{color:#f3f4f6}
.tab-btn.active{border-bottom-color:#22d3ee;color:#22d3ee}
.sortable:hover{color:#f3f4f6;cursor:pointer}
.sort-asc::after{content:" ↑"}
.sort-desc::after{content:" ↓"}
.row-detail{background:#111827}
tr.host-row{cursor:pointer}
tr.host-row:hover td{background:#1f2937}
.pill{display:inline-block;padding:.125rem .5rem;border-radius:9999px;font-size:.7rem;font-weight:600;white-space:nowrap;cursor:pointer}
.pill.active{outline:2px solid #22d3ee}
.port-badge{display:inline-block;background:#1f2937;color:#d1d5db;font-size:.7rem;font-family:monospace;padding:.1rem .35rem;border-radius:.25rem;margin:.1rem .1rem .1rem 0}
.bar-bg{background:#374151;border-radius:9999px;height:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:9999px;transition:width .3s}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#1f2937}
::-webkit-scrollbar-thumb{background:#4b5563;border-radius:3px}
</style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">

<!-- HEADER -->
<header class="bg-gray-900 border-b border-gray-800 px-5 py-3 flex items-center justify-between sticky top-0 z-50">
  <div class="flex items-center gap-3">
    <div class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></div>
    <h1 class="text-lg font-bold tracking-tight text-cyan-400">Command Center</h1>
    <span class="text-xs text-gray-500 hidden sm:inline" id="scan-time">Loading...</span>
  </div>
  <div class="flex items-center gap-2">
    <span class="text-xs text-gray-500 sm:hidden" id="scan-time-mobile"></span>
    <button id="refresh-btn"
      class="text-xs px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-gray-300 transition-colors">
      Refresh
    </button>
  </div>
</header>

<!-- STAT CARDS -->
<div class="grid grid-cols-2 md:grid-cols-4 gap-3 px-5 py-4">
  <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div class="text-3xl font-bold text-cyan-400" id="stat-hosts">—</div>
    <div class="text-xs text-gray-500 mt-1">Hosts Online</div>
  </div>
  <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div class="text-3xl font-bold text-orange-400" id="stat-vms">—</div>
    <div class="text-xs text-gray-500 mt-1">VMs</div>
  </div>
  <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div class="text-3xl font-bold text-emerald-400" id="stat-containers">—</div>
    <div class="text-xs text-gray-500 mt-1">Containers</div>
  </div>
  <div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div class="text-3xl font-bold text-purple-400" id="stat-services">—</div>
    <div class="text-xs text-gray-500 mt-1">Unique Services</div>
  </div>
</div>

<!-- ERROR BANNER -->
<div id="error-banner" class="hidden mx-5 mb-3 bg-amber-950 border border-amber-700 rounded-lg px-4 py-3">
  <div class="text-amber-400 text-xs font-semibold mb-1">Data warnings</div>
  <ul id="error-list" class="text-amber-300 text-xs space-y-0.5 list-disc list-inside"></ul>
</div>

<!-- TAB NAV -->
<nav class="flex gap-0 px-5 border-b border-gray-800 overflow-x-auto">
  <button class="tab-btn active" data-tab="network">Network</button>
  <button class="tab-btn" data-tab="proxmox">Proxmox</button>
  <button class="tab-btn" data-tab="ports">Port Explorer</button>
  <button class="tab-btn" data-tab="topology">Topology</button>
</nav>

<!-- ── NETWORK TAB ── -->
<div id="tab-network" class="tab-panel px-5 py-4">
  <div class="flex flex-wrap gap-3 mb-3 items-center">
    <input id="search-input" type="text" placeholder="Search IP, hostname, port, service, OS..."
      class="flex-1 min-w-48 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm
             placeholder-gray-500 focus:outline-none focus:border-cyan-600 text-gray-100">
    <div id="type-filters" class="flex flex-wrap gap-1.5"></div>
  </div>
  <div class="text-xs text-gray-500 mb-2" id="host-count-label"></div>
  <div class="overflow-x-auto rounded-lg border border-gray-800">
    <table class="w-full text-sm min-w-[700px]">
      <thead class="bg-gray-900 border-b border-gray-800">
        <tr>
          <th class="sortable text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider" data-col="ip">IP</th>
          <th class="sortable text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider" data-col="hostname">Hostname</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Type</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">MAC / Vendor</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Ports</th>
          <th class="sortable text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider" data-col="key_service">Key Service</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">OS</th>
        </tr>
      </thead>
      <tbody id="hosts-tbody"></tbody>
    </table>
  </div>
  <div id="no-hosts" class="hidden text-center py-12 text-gray-500">
    <div class="text-2xl mb-2">No hosts found</div>
    <div class="text-sm">Run <code class="bg-gray-800 px-1 rounded">scan_network.sh</code> to discover devices</div>
  </div>
</div>

<!-- ── PROXMOX TAB ── -->
<div id="tab-proxmox" class="tab-panel hidden px-5 py-4">
  <div id="pve-host-card" class="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-5">
    <div class="text-gray-500 text-sm">Run proxmox_inventory.sh to populate Proxmox data.</div>
  </div>
  <h2 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Virtual Machines</h2>
  <div class="overflow-x-auto rounded-lg border border-gray-800 mb-5">
    <table class="w-full text-sm min-w-[640px]">
      <thead class="bg-gray-900 border-b border-gray-800">
        <tr>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">VMID</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Name</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Status</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Cores</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">RAM</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Disk</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">IP</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">CPU%</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Uptime</th>
        </tr>
      </thead>
      <tbody id="vms-tbody"></tbody>
    </table>
  </div>
  <h2 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">LXC Containers</h2>
  <div class="overflow-x-auto rounded-lg border border-gray-800 mb-5">
    <table class="w-full text-sm min-w-[640px]">
      <thead class="bg-gray-900 border-b border-gray-800">
        <tr>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">CTID</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Hostname</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Status</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Cores</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">RAM</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Disk</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">IP</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">CPU%</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Uptime</th>
        </tr>
      </thead>
      <tbody id="cts-tbody"></tbody>
    </table>
  </div>
  <h2 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Storage</h2>
  <div id="storage-cards" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
</div>

<!-- ── PORT EXPLORER TAB ── -->
<div id="tab-ports" class="tab-panel hidden px-5 py-4">
  <input id="port-search" type="text" placeholder="Filter by port number or service name..."
    class="w-full mb-4 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm
           placeholder-gray-500 focus:outline-none focus:border-cyan-600 text-gray-100">
  <div class="overflow-x-auto rounded-lg border border-gray-800">
    <table class="w-full text-sm min-w-[600px]">
      <thead class="bg-gray-900 border-b border-gray-800">
        <tr>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Port</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Proto</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Service</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Product / Version</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">Hosts</th>
          <th class="text-left py-3 px-4 text-xs text-gray-400 font-semibold uppercase tracking-wider">IP Addresses</th>
        </tr>
      </thead>
      <tbody id="ports-tbody"></tbody>
    </table>
  </div>
  <div id="no-ports" class="hidden text-center py-12 text-gray-500 text-sm">No ports match your filter.</div>
</div>

<!-- ── TOPOLOGY TAB ── -->
<div id="tab-topology" class="tab-panel hidden px-5 py-4">
  <div id="topology-container" class="bg-gray-900 border border-gray-800 rounded-xl p-5 overflow-auto min-h-64">
    <div class="text-gray-500 text-sm">Click the Topology tab to render the diagram.</div>
  </div>
</div>

<script>
const TYPE_COLORS = {
  Router:      "bg-amber-600 text-white",
  NAS:         "bg-blue-600 text-white",
  Proxmox:     "bg-orange-600 text-white",
  Printer:     "bg-purple-600 text-white",
  Desktop:     "bg-emerald-600 text-white",
  IoT:         "bg-yellow-500 text-gray-900",
  Unknown:     "bg-gray-600 text-white",
  ThisMachine: "bg-pink-600 text-white",
};

let allData = __INITIAL_DATA__;
let activeTab = "network";
let searchQuery = "";
let typeFilter = "all";
let sortField = "ip";
let sortDir = "asc";
let mermaidRendered = false;
let portQuery = "";
let searchTimer = null;
let portTimer = null;

mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "loose" });

function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function fmtMB(mb) {
  if (!mb) return "0 MB";
  return mb >= 1024 ? (mb / 1024).toFixed(1) + " GB" : mb + " MB";
}
function fmtUptime(s) {
  if (!s) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
        m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  return m + "m";
}
function ipToInt(ip) {
  return (ip || "0.0.0.0").split(".").reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
}
function statusBadge(status) {
  const running = status === "running" || status === "online";
  const cls = running ? "bg-green-800 text-green-300 border border-green-700"
                      : "bg-gray-800 text-gray-400 border border-gray-700";
  return `<span class="pill ${cls}">${esc(status)}</span>`;
}
function typeBadge(type) {
  const c = TYPE_COLORS[type] || TYPE_COLORS.Unknown;
  return `<span class="pill ${c}">${esc(type)}</span>`;
}
function barHtml(pct, color) {
  color = color || "bg-cyan-500";
  return `<div class="bar-bg"><div class="bar-fill ${color}" style="width:${Math.min(pct,100)}%"></div></div>`;
}

function filterHosts(hosts) {
  const words = searchQuery.toLowerCase().trim().split(/[\\s]+/).filter(Boolean);
  return hosts.filter(h => {
    if (typeFilter !== "all" && h.type !== typeFilter) return false;
    if (!words.length) return true;
    const blob = [
      h.ip, h.hostname, h.mac, h.vendor, h.type, h.os, h.key_service,
      ...h.ports.map(p => p.port + " " + p.service + " " + p.product + " " + p.version)
    ].join(" ").toLowerCase();
    return words.every(w => blob.includes(w));
  });
}

function sortHosts(hosts) {
  return [...hosts].sort((a, b) => {
    if (sortField === "ip") {
      const diff = ipToInt(a.ip) - ipToInt(b.ip);
      return sortDir === "asc" ? diff : -diff;
    }
    const av = String(a[sortField] || "").toLowerCase();
    const bv = String(b[sortField] || "").toLowerCase();
    const diff = av.localeCompare(bv);
    return sortDir === "asc" ? diff : -diff;
  });
}

function renderStatCards(data) {
  const hosts = data.hosts || [];
  const pve = data.proxmox || {};
  const svcs = new Set(hosts.flatMap(h => h.ports.map(p => p.service).filter(Boolean)));
  document.getElementById("stat-hosts").textContent = hosts.length;
  document.getElementById("stat-vms").textContent = (pve.vms || []).length;
  document.getElementById("stat-containers").textContent = (pve.containers || []).length;
  document.getElementById("stat-services").textContent = svcs.size;
}

function renderErrors(errors) {
  const banner = document.getElementById("error-banner");
  const list = document.getElementById("error-list");
  if (!errors || !errors.length) { banner.classList.add("hidden"); return; }
  banner.classList.remove("hidden");
  list.innerHTML = errors.map(e => `<li>${esc(e)}</li>`).join("");
}

function renderTypeFilters(hosts) {
  const types = ["all", ...new Set(hosts.map(h => h.type).filter(Boolean).sort())];
  document.getElementById("type-filters").innerHTML = types.map(t => {
    const active = t === typeFilter ? " active" : "";
    const color = t === "all" ? "bg-gray-700 text-gray-300"
                              : (TYPE_COLORS[t] || "bg-gray-700 text-gray-300");
    return `<button class="pill ${color}${active}" onclick="setTypeFilter('${esc(t)}')">${t === "all" ? "All" : esc(t)}</button>`;
  }).join("");
}

function renderNetworkTable(data) {
  const hosts = sortHosts(filterHosts(data.hosts || []));
  const tbody = document.getElementById("hosts-tbody");
  const noHosts = document.getElementById("no-hosts");
  const label = document.getElementById("host-count-label");

  label.textContent = hosts.length + " of " + (data.hosts || []).length + " hosts";
  tbody.innerHTML = "";

  if (!hosts.length) {
    noHosts.classList.remove("hidden");
    return;
  }
  noHosts.classList.add("hidden");

  for (const h of hosts) {
    const portBadges = h.ports.slice(0, 8).map(p =>
      `<span class="port-badge">${p.port}</span>`
    ).join("") + (h.ports.length > 8 ? `<span class="text-gray-500 text-xs">+${h.ports.length - 8}</span>` : "");

    const tr = document.createElement("tr");
    tr.className = "host-row border-b border-gray-800 transition-colors";
    tr.innerHTML = `
      <td class="py-3 px-4 font-mono text-cyan-300 text-xs">${esc(h.ip)}</td>
      <td class="py-3 px-4 text-gray-200">${esc(h.hostname) || '<span class="text-gray-600">—</span>'}</td>
      <td class="py-3 px-4"><button class="pill ${TYPE_COLORS[h.type] || TYPE_COLORS.Unknown}" onclick="event.stopPropagation();setTypeFilter('${esc(h.type)}')" title="Filter by ${esc(h.type)}">${esc(h.type)}</button></td>
      <td class="py-3 px-4 text-xs text-gray-400">
        ${h.mac ? `<span class="font-mono">${esc(h.mac)}</span>` : ""}
        ${h.vendor ? `<span class="text-gray-500 ml-1">${esc(h.vendor)}</span>` : ""}
        ${!h.mac && !h.vendor ? '<span class="text-gray-600">—</span>' : ""}
      </td>
      <td class="py-3 px-4">${portBadges || '<span class="text-gray-600">—</span>'}</td>
      <td class="py-3 px-4 text-gray-300 text-xs max-w-48 truncate">${esc(h.key_service) || '<span class="text-gray-600">—</span>'}</td>
      <td class="py-3 px-4 text-gray-400 text-xs">${h.os ? esc(h.os.substring(0, 40)) + (h.os_accuracy ? ` <span class="text-gray-600">${h.os_accuracy}%</span>` : "") : '<span class="text-gray-600">—</span>'}</td>`;

    const detailTr = document.createElement("tr");
    detailTr.className = "row-detail hidden";
    const portRows = h.ports.map(p => {
      const svc = [p.service, p.product, p.version, p.extrainfo].filter(Boolean).join(" · ");
      return `<div class="flex gap-3 py-0.5"><span class="font-mono text-cyan-400 w-16 shrink-0">${p.port}/${p.protocol}</span><span class="text-gray-300">${esc(svc) || "unknown"}</span></div>`;
    }).join("");
    const scriptRows = Object.entries(h.scripts || {}).filter(([, v]) => v).map(([k, v]) =>
      `<div class="py-0.5"><span class="text-yellow-500">${esc(k)}:</span> <span class="text-gray-300">${esc(v.substring(0, 300))}</span></div>`
    ).join("");
    detailTr.innerHTML = `<td colspan="7" class="px-8 py-4 border-b border-gray-800">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        <div><div class="text-gray-500 uppercase text-[10px] tracking-wider mb-2">Ports &amp; Services</div>${portRows || "<div class='text-gray-600'>No open ports</div>"}</div>
        <div><div class="text-gray-500 uppercase text-[10px] tracking-wider mb-2">Script Outputs</div>${scriptRows || "<div class='text-gray-600'>None</div>"}</div>
      </div></td>`;

    tr.addEventListener("click", () => {
      detailTr.classList.toggle("hidden");
      tr.classList.toggle("bg-gray-900");
    });
    tbody.appendChild(tr);
    tbody.appendChild(detailTr);
  }

  document.querySelectorAll(".sortable").forEach(th => {
    th.classList.remove("sort-asc", "sort-desc");
    if (th.dataset.col === sortField) {
      th.classList.add(sortDir === "asc" ? "sort-asc" : "sort-desc");
    }
  });
}

function renderProxmox(data) {
  const pve = data.proxmox;
  if (!pve) {
    document.getElementById("pve-host-card").innerHTML =
      `<div class="text-gray-500 text-sm">Run <code class="bg-gray-800 px-1 rounded">proxmox_inventory.sh</code> to populate Proxmox data.</div>`;
    document.getElementById("vms-tbody").innerHTML = "";
    document.getElementById("cts-tbody").innerHTML = "";
    document.getElementById("storage-cards").innerHTML = "";
    return;
  }

  const ramPct = pve.ram_total_mb ? Math.round(pve.ram_used_mb / pve.ram_total_mb * 100) : 0;
  document.getElementById("pve-host-card").innerHTML = `
    <div class="flex items-center gap-2 mb-4">
      <span class="text-orange-400 font-bold text-sm">Proxmox VE</span>
      <span class="pill bg-orange-900 text-orange-300 border border-orange-800">${esc(pve.version)}</span>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
      <div><div class="text-xs text-gray-500 mb-1">CPU</div><div class="text-gray-200">${esc(pve.cpu_model)}</div><div class="text-xs text-gray-500">${pve.cpu_cores} vCPUs</div></div>
      <div><div class="text-xs text-gray-500 mb-1">RAM</div>
        <div class="text-gray-200">${fmtMB(pve.ram_used_mb)} / ${fmtMB(pve.ram_total_mb)}</div>
        <div class="mt-1">${barHtml(ramPct, ramPct > 80 ? "bg-red-500" : "bg-cyan-500")}</div>
        <div class="text-xs text-gray-500 mt-0.5">${ramPct}%</div>
      </div>
      <div><div class="text-xs text-gray-500 mb-1">Kernel</div><div class="font-mono text-xs text-gray-300">${esc(pve.kernel)}</div></div>
      <div><div class="text-xs text-gray-500 mb-1">Workloads</div>
        <div class="text-gray-200">${(pve.vms || []).length} VMs · ${(pve.containers || []).length} CTs</div>
        <div class="text-xs text-gray-500">${(pve.vms || []).filter(v => v.status === "running").length + (pve.containers || []).filter(c => c.status === "running").length} running</div>
      </div>
    </div>`;

  function vmRow(v) {
    const ramPct = v.memory_mb ? Math.round(v.mem_used_mb / v.memory_mb * 100) : 0;
    return `<tr class="border-b border-gray-800 hover:bg-gray-800 transition-colors">
      <td class="py-3 px-4 font-mono text-gray-400 text-xs">${v.vmid}</td>
      <td class="py-3 px-4 font-semibold text-gray-100">${esc(v.name)}</td>
      <td class="py-3 px-4">${statusBadge(v.status)}</td>
      <td class="py-3 px-4 text-gray-300">${v.cores}</td>
      <td class="py-3 px-4 text-xs">
        <div class="text-gray-300">${fmtMB(v.memory_mb)}</div>
        ${v.status === "running" ? `<div class="text-gray-500">${fmtMB(v.mem_used_mb)} used</div><div class="mt-1">${barHtml(ramPct)}</div>` : ""}
      </td>
      <td class="py-3 px-4 font-mono text-xs text-gray-400">${esc(v.disk_size) || "—"}</td>
      <td class="py-3 px-4 font-mono text-xs text-gray-400">${esc(v.ip) || "—"}</td>
      <td class="py-3 px-4 text-xs text-gray-400">${v.status === "running" ? v.cpu_pct + "%" : "—"}</td>
      <td class="py-3 px-4 text-xs text-gray-400">${fmtUptime(v.uptime)}</td>
    </tr>`;
  }

  document.getElementById("vms-tbody").innerHTML =
    (pve.vms || []).map(vmRow).join("") ||
    `<tr><td colspan="9" class="py-6 text-center text-gray-600 text-sm">No VMs found</td></tr>`;
  document.getElementById("cts-tbody").innerHTML =
    (pve.containers || []).map(vmRow).join("") ||
    `<tr><td colspan="9" class="py-6 text-center text-gray-600 text-sm">No containers found</td></tr>`;

  document.getElementById("storage-cards").innerHTML = (pve.storage || []).map(s => {
    const pct = s.pct || 0;
    const barColor = pct > 85 ? "bg-red-500" : pct > 65 ? "bg-yellow-500" : "bg-cyan-500";
    return `<div class="bg-gray-800 border border-gray-700 rounded-xl p-4">
      <div class="flex justify-between items-start mb-2">
        <div>
          <div class="font-semibold text-gray-100">${esc(s.name)}</div>
          <div class="text-xs text-gray-500">${esc(s.type)} · ${statusBadge(s.status)}</div>
        </div>
        <div class="text-right text-xs text-gray-400">
          <div class="text-lg font-bold text-cyan-400">${pct}%</div>
          used
        </div>
      </div>
      ${barHtml(pct, barColor)}
      <div class="flex justify-between text-xs text-gray-500 mt-1.5">
        <span>${s.used_gb} GB used</span>
        <span>${s.total_gb} GB total</span>
      </div>
    </div>`;
  }).join("") || `<div class="text-gray-600 text-sm">No storage pools found</div>`;
}

function renderPortExplorer(data) {
  const portMap = new Map();
  for (const h of data.hosts || []) {
    for (const p of h.ports) {
      const key = p.port + "/" + p.protocol + ":" + p.service;
      if (!portMap.has(key)) {
        portMap.set(key, { port: p.port, protocol: p.protocol, service: p.service,
                           product: p.product, version: p.version, hosts: [] });
      }
      portMap.get(key).hosts.push(h.ip);
    }
  }
  let rows = [...portMap.values()].sort((a, b) =>
    b.hosts.length !== a.hosts.length ? b.hosts.length - a.hosts.length : a.port - b.port
  );

  const q = portQuery.toLowerCase().trim();
  if (q) {
    rows = rows.filter(r => {
      const blob = [r.port, r.service, r.product, r.version].join(" ").toLowerCase();
      return blob.includes(q);
    });
  }

  const tbody = document.getElementById("ports-tbody");
  const noPorts = document.getElementById("no-ports");
  if (!rows.length) {
    tbody.innerHTML = "";
    noPorts.classList.remove("hidden");
    return;
  }
  noPorts.classList.add("hidden");
  tbody.innerHTML = rows.map(r => `
    <tr class="border-b border-gray-800 hover:bg-gray-800 transition-colors">
      <td class="py-3 px-4 font-mono text-cyan-300 font-bold">${r.port}</td>
      <td class="py-3 px-4 text-xs text-gray-400 font-mono">${esc(r.protocol)}</td>
      <td class="py-3 px-4 text-gray-200">${esc(r.service) || "—"}</td>
      <td class="py-3 px-4 text-xs text-gray-400">${esc([r.product, r.version].filter(Boolean).join(" ")) || "—"}</td>
      <td class="py-3 px-4"><span class="pill bg-gray-700 text-gray-200">${r.hosts.length}</span></td>
      <td class="py-3 px-4 text-xs font-mono text-gray-400">${r.hosts.map(ip => `<span class="port-badge">${esc(ip)}</span>`).join("")}</td>
    </tr>`).join("");
}

async function renderTopology() {
  if (mermaidRendered) return;
  const container = document.getElementById("topology-container");
  const src = (allData.diagram_source || "").trim();
  if (!src) {
    container.innerHTML = `<div class="text-gray-500 text-sm">No diagram available. Run <code class="bg-gray-800 px-1 rounded">generate_diagram.py</code> after scanning.</div>`;
    return;
  }
  container.innerHTML = "";
  const pre = document.createElement("pre");
  pre.className = "mermaid text-xs";
  pre.textContent = src;
  container.appendChild(pre);
  try {
    await mermaid.run({ nodes: [pre] });
    mermaidRendered = true;
    const svg = container.querySelector("svg");
    if (svg) { svg.style.maxWidth = "100%"; svg.style.height = "auto"; }
  } catch (e) {
    container.innerHTML = `<div class="text-red-400 text-sm mb-2">Diagram render error: ${esc(e.message)}</div>
      <pre class="text-gray-500 text-xs overflow-auto max-h-48">${esc(src.substring(0, 800))}</pre>`;
  }
}

function renderAll(data) {
  const st = data.scan_time;
  const timeStr = st ? "Last scan: " + st : "No scan data";
  document.getElementById("scan-time").textContent = timeStr;
  const mob = document.getElementById("scan-time-mobile");
  if (mob) mob.textContent = st ? st : "";
  renderStatCards(data);
  renderErrors(data.errors || []);
  renderTypeFilters(data.hosts || []);
  if (activeTab === "network") renderNetworkTable(data);
  if (activeTab === "proxmox") renderProxmox(data);
  if (activeTab === "ports") renderPortExplorer(data);
  if (activeTab === "topology") renderTopology();
}

function setSort(field) {
  if (sortField === field) {
    sortDir = sortDir === "asc" ? "desc" : "asc";
  } else {
    sortField = field;
    sortDir = field === "ip" ? "asc" : "asc";
  }
  renderNetworkTable(allData);
}

function setTypeFilter(type) {
  typeFilter = type;
  renderTypeFilters(allData.hosts || []);
  renderNetworkTable(allData);
}

function initEventListeners() {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      activeTab = btn.dataset.tab;
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
      document.getElementById("tab-" + activeTab).classList.remove("hidden");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      if (activeTab === "proxmox") renderProxmox(allData);
      if (activeTab === "ports") renderPortExplorer(allData);
      if (activeTab === "topology") renderTopology();
    });
  });

  document.querySelectorAll(".sortable").forEach(th => {
    th.addEventListener("click", () => setSort(th.dataset.col));
  });

  const searchInput = document.getElementById("search-input");
  searchInput.addEventListener("input", e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      searchQuery = e.target.value;
      renderNetworkTable(allData);
    }, 150);
  });

  document.getElementById("port-search").addEventListener("input", e => {
    clearTimeout(portTimer);
    portTimer = setTimeout(() => {
      portQuery = e.target.value;
      renderPortExplorer(allData);
    }, 150);
  });

  document.getElementById("refresh-btn").addEventListener("click", async () => {
    const btn = document.getElementById("refresh-btn");
    btn.textContent = "Refreshing...";
    btn.disabled = true;
    try {
      const resp = await fetch("/api/data");
      allData = await resp.json();
      mermaidRendered = false;
      renderAll(allData);
    } catch (e) {
      alert("Refresh failed: " + e.message);
    } finally {
      btn.textContent = "Refresh";
      btn.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initEventListeners();
  renderAll(allData);
});
</script>
</body>
</html>"""


# ── HTTP Server ────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default access log

    def do_GET(self):
        try:
            if self.path in ("/", "/index.html"):
                data = build_api_data()
                json_str = json.dumps(data, default=str)
                json_str = json_str.replace("</script", "<\\/script").replace("<!--", "<\\!--")
                page = HTML_TEMPLATE.replace("__INITIAL_DATA__", json_str)
                body = page.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            elif self.path == "/api/data":
                data = build_api_data()
                body = json.dumps(data, default=str).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            else:
                self.send_response(404)
                self.end_headers()

        except Exception as e:
            err = json.dumps({"error": str(e)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(err)


def main():
    server = ThreadingHTTPServer(("", PORT), DashboardHandler)
    print(f"[+] Command Center: http://localhost:{PORT}")
    print(f"    Reading data from: {SCRIPT_DIR}")
    print(f"    Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopped.")


if __name__ == "__main__":
    main()
