#!/usr/bin/env bash
# proxmox_inventory.sh — Collect Proxmox VE inventory via SSH
# Usage: bash proxmox_inventory.sh
# Prerequisites: SSH access to root@192.168.40.77 (password or key-based)

set -euo pipefail

PROXMOX_HOST="192.168.40.77"
PROXMOX_USER="root"
OUTDIR="$(dirname "$(realpath "$0")")"
OUTFILE="${OUTDIR}/proxmox_inventory.txt"

echo "=============================================="
echo " Proxmox Inventory Collector"
echo " Host  : ${PROXMOX_USER}@${PROXMOX_HOST}"
echo " Output: ${OUTFILE}"
echo " Time  : $(date)"
echo "=============================================="
echo ""
echo "[i] You will be prompted for the SSH password if key auth is not set up."
echo ""

if ! ping -c1 -W3 "$PROXMOX_HOST" &>/dev/null; then
    echo "[ERROR] Cannot reach ${PROXMOX_HOST}. Verify network connectivity."
    exit 1
fi
echo "[+] Host ${PROXMOX_HOST} is reachable"
echo "[+] Connecting..."
echo ""

SSH_OPTS=(
    -o "StrictHostKeyChecking=accept-new"
    -o "ServerAliveInterval=30"
    -o "ServerAliveCountMax=5"
    -o "ConnectTimeout=15"
)

# All remote commands run in a single SSH session (one password prompt).
# The quoted 'REMOTE_SCRIPT' heredoc delimiter prevents local shell expansion;
# all $VARIABLES inside evaluate on the remote Proxmox host.
ssh "${SSH_OPTS[@]}" "${PROXMOX_USER}@${PROXMOX_HOST}" 'bash -s' > "$OUTFILE" 2>&1 <<'REMOTE_SCRIPT'
#!/bin/bash

DIVIDER="================================================================"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
NODENAME=$(hostname -s 2>/dev/null || hostname)

echo "$DIVIDER"
echo " PROXMOX VE INVENTORY REPORT"
echo " Generated : $TIMESTAMP"
echo " Node      : $(hostname -f 2>/dev/null || hostname)"
echo "$DIVIDER"
echo ""

echo "=== PROXMOX VERSION ==="
pveversion --verbose 2>/dev/null || pveversion 2>/dev/null || echo "pveversion not found"
echo ""

echo "=== NODE STATUS ==="
pvesh get /nodes/${NODENAME}/status --output-format yaml 2>/dev/null \
    || pvesh get /nodes/${NODENAME}/status 2>/dev/null \
    || echo "pvesh node status unavailable"
echo ""

echo "=== CLUSTER RESOURCES ==="
pvesh get /cluster/resources --output-format yaml 2>/dev/null \
    || echo "Cluster resources unavailable (standalone node)"
echo ""

echo "=== VIRTUAL MACHINES ==="
qm list 2>/dev/null || echo "No VMs or qm not available"
echo ""

echo "=== VM CONFIGURATIONS ==="
if command -v qm &>/dev/null; then
    VM_IDS=$(qm list 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^[0-9]+$' || true)
    if [ -n "$VM_IDS" ]; then
        for VMID in $VM_IDS; do
            echo "--- VM ${VMID} config ---"
            qm config "$VMID" 2>/dev/null || echo "Failed to get config for VM $VMID"
            echo "--- VM ${VMID} status ---"
            qm status "$VMID" 2>/dev/null || true
            echo ""
        done
    else
        echo "No VMs found"
    fi
fi
echo ""

echo "=== LXC CONTAINERS ==="
pct list 2>/dev/null || echo "No containers or pct not available"
echo ""

echo "=== CONTAINER CONFIGURATIONS ==="
if command -v pct &>/dev/null; then
    CT_IDS=$(pct list 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^[0-9]+$' || true)
    if [ -n "$CT_IDS" ]; then
        for CTID in $CT_IDS; do
            echo "--- CT ${CTID} config ---"
            pct config "$CTID" 2>/dev/null || echo "Failed to get config for CT $CTID"
            echo "--- CT ${CTID} status ---"
            pct status "$CTID" 2>/dev/null || true
            echo ""
        done
    else
        echo "No containers found"
    fi
fi
echo ""

echo "=== STORAGE STATUS ==="
pvesm status 2>/dev/null || echo "pvesm not available"
echo ""

echo "=== STORAGE LISTING ==="
pvesm list 2>/dev/null || true
echo ""

echo "=== /etc/pve/storage.cfg ==="
cat /etc/pve/storage.cfg 2>/dev/null || echo "Cannot read storage.cfg"
echo ""

echo "=== NETWORK INTERFACES ==="
cat /etc/network/interfaces 2>/dev/null || ip addr show 2>/dev/null
echo ""

echo "=== DISK USAGE ==="
df -h 2>/dev/null
echo ""

echo "=== BLOCK DEVICES ==="
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || true
echo ""

echo "=== EXISTING BACKUP JOBS ==="
echo "-- /etc/cron.d/vzdump --"
cat /etc/cron.d/vzdump 2>/dev/null || echo "No vzdump cron found"
echo ""
echo "-- /etc/pve/vzdump.cron --"
cat /etc/pve/vzdump.cron 2>/dev/null || echo "No /etc/pve/vzdump.cron found"
echo ""
echo "-- /etc/vzdump.conf --"
cat /etc/vzdump.conf 2>/dev/null || echo "No /etc/vzdump.conf found"
echo ""
echo "-- /etc/pve/jobs.cfg (Proxmox 8 scheduler) --"
cat /etc/pve/jobs.cfg 2>/dev/null || echo "No /etc/pve/jobs.cfg found"
echo ""

echo "$DIVIDER"
echo " END OF INVENTORY REPORT"
echo "$DIVIDER"
REMOTE_SCRIPT

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[+] Inventory collected successfully!"
    echo "    Saved to: ${OUTFILE}"
    echo ""
    echo "=== Quick Summary ==="
    grep -E "^(=== |--- (VM|CT) [0-9])" "$OUTFILE" | head -40 || true
    echo ""
    echo "Full details: cat ${OUTFILE}"
    echo ""
    echo "Next step: review proxmox_inventory.txt, then fill in"
    echo "  <NAS_IP> in backup_plan.md and follow the steps there."
else
    echo ""
    echo "[ERROR] SSH failed with exit code ${EXIT_CODE}"
    echo "        Partial output (if any) saved to: ${OUTFILE}"
    exit $EXIT_CODE
fi
