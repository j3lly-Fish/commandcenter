#!/usr/bin/env bash
# scan_network.sh — Network discovery for 192.168.40.0/24
# Usage: bash scan_network.sh          (TCP connect scan, no root needed)
#        sudo bash scan_network.sh     (SYN scan + OS detection, recommended)

set -euo pipefail

TARGET="192.168.40.0/24"
OUTDIR="$(dirname "$(realpath "$0")")/scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

NAS_PORTS="22,80,443,139,445,548,2049,5000,5001,8080,8081,8443,9000"
COMMON_PORTS="21,23,25,53,110,143,8080,8443,3389,5900,9100,515,631,62078"
ALL_PORTS="${NAS_PORTS},${COMMON_PORTS}"
SCAN_PORTS=$(echo "$ALL_PORTS" | tr ',' '\n' | sort -nu | tr '\n' ',' | sed 's/,$//')

mkdir -p "$OUTDIR"

echo "=============================================="
echo " Command Center — Network Scanner"
echo " Target : $TARGET"
echo " Output : $OUTDIR"
echo " Time   : $(date)"
echo "=============================================="
echo ""

# ── Root detection ──────────────────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
    ROOT_FLAGS="-sS -O"
    echo "[+] Running as root: SYN scan + OS detection enabled"
else
    ROOT_FLAGS="-sT"
    echo "[!] Running as non-root: TCP connect scan (no OS detection)"
    echo "    Tip: run 'sudo bash scan_network.sh' for full OS fingerprinting"
fi
echo ""

# ── Phase 1: Ping sweep ──────────────────────────────────────────────────────
echo "[1/2] Ping sweep — discovering live hosts on ${TARGET}..."
echo ""

nmap -sn \
    --reason \
    -oA "${OUTDIR}/ping_sweep_${TIMESTAMP}" \
    "$TARGET" 2>&1 | tee "${OUTDIR}/ping_sweep_latest.txt"

# Extract live IPs from gnmap (stable columnar format designed for grepping)
LIVE_HOSTS=$(grep "^Host:" "${OUTDIR}/ping_sweep_${TIMESTAMP}.gnmap" \
    | awk '{print $2}' | tr '\n' ' ')
LIVE_COUNT=$(echo "$LIVE_HOSTS" | wc -w)

echo ""
echo "[+] Phase 1 complete: ${LIVE_COUNT} hosts found"
echo "    Live hosts: $LIVE_HOSTS"
echo ""

if [ "$LIVE_COUNT" -eq 0 ]; then
    echo "[!] No live hosts found. Your current network interfaces:"
    ip -br addr show
    echo ""
    echo "    If your NAS blocks ICMP, try a direct port scan:"
    echo "    nmap -Pn -sT -p ${NAS_PORTS} 192.168.40.0/24"
    exit 1
fi

# ── Phase 2: Detailed port + service + script scan ───────────────────────────
echo "[2/2] Detailed port/service/script scan on ${LIVE_COUNT} live hosts..."
echo "      Ports : $SCAN_PORTS"
echo "      Scripts: http-title, http-server-header, http-qnap-nas-info,"
echo "               banner, smb-os-discovery, nfs-showmount"
echo "      (Estimated time: 2-8 minutes)"
echo ""

NMAP_CMD=(
    nmap
    $ROOT_FLAGS
    -sV
    --version-intensity 5
    -p "$SCAN_PORTS"
    --script "http-title,http-server-header,http-qnap-nas-info,banner,smb-os-discovery,nfs-showmount"
    --script-timeout 10s
    -T4
    --open
    --reason
    -oA "${OUTDIR}/detailed_scan_${TIMESTAMP}"
)

for host in $LIVE_HOSTS; do
    NMAP_CMD+=("$host")
done

echo "      Full command: ${NMAP_CMD[*]}"
echo ""

"${NMAP_CMD[@]}" 2>&1 | tee "${OUTDIR}/detailed_scan_latest.txt"

echo ""
echo "=============================================="
echo "[+] Scan complete!"
echo "    XML (for Python) : ${OUTDIR}/detailed_scan_${TIMESTAMP}.xml"
echo "    Text (human)     : ${OUTDIR}/detailed_scan_${TIMESTAMP}.nmap"
echo "    Ping sweep XML   : ${OUTDIR}/ping_sweep_${TIMESTAMP}.xml"
echo ""
echo "Next step: python3 generate_diagram.py"
echo "=============================================="
