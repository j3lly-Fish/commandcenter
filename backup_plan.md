# Proxmox Backup — Active Configuration

**Proxmox Host:** 192.168.40.77 (node: cloudhosted)  
**Backup Target:** Toshiba DT01ACA100 USB drive (`/dev/sda1`)  
**Mount Point:** `/mnt/pve/usb-toshiba`  
**Storage ID:** `usb-toshiba` (dir type, ext4)  
**Usable Space:** 916 GB  
**Retention:** 3 daily · 2 weekly · 1 monthly  
**Schedule:** Daily at 02:00  
**Notifications:** angelcerceda@gmail.com (on every run)  
**Deploy Key:** `/home/anti/.ssh/proxmox_deploy` (passphrase-free, for automation)

---

## What Is Backed Up

All 17 guests — 2 VMs + 15 containers. One full run is ~94 GB compressed.

| VMID | Name | Type | Disk | Backup Size |
|------|------|------|------|-------------|
| 100 | casaOS | LXC | 58 GB | 2.0 GB |
| 101 | microservices | LXC | 100 GB | 2.8 GB |
| 102 | CRM | LXC | 35 GB | 985 MB |
| 103 | DNS | LXC | 15 GB | 1.5 GB |
| 104 | clinic | LXC | 11 GB | 1.3 GB |
| 105 | candles | LXC | 20 GB | 1.4 GB |
| 106 | AI | VM | 150 GB | 25 GB |
| 107 | mail | LXC | 20 GB | 186 MB |
| 108 | photos | LXC | 30 GB | 19 GB |
| 109 | portainer | LXC | 12 GB | 446 MB |
| 110 | APIS | LXC | 30 GB | 1.6 GB |
| 111 | cloudhosted.pro | LXC | 12 GB | 739 MB |
| 112 | Template | LXC | 10 GB | 196 MB |
| 113 | apisApp | VM | 32 GB | 32 GB |
| 114 | pestleads | LXC | 40 GB | 1.1 GB |
| 115 | tenantlist | LXC | 20 GB | 4.1 GB |
| 116 | vananavan | LXC | 25 GB | 1.2 GB |

---

## Retention Policy

| Tier | Count | Max storage used |
|------|-------|-----------------|
| Daily | 3 | ~282 GB |
| Weekly | 2 | ~188 GB |
| Monthly | 1 | ~94 GB |

Worst case total: ~564 GB — well within the 916 GB drive.  
Oldest backups are pruned automatically after each nightly run.

---

## Storage Configuration

The Toshiba is auto-mounted via `/etc/fstab` using its UUID:

```
UUID=b13b6798-5157-46a8-abc3-b77565e1b13c  /mnt/pve/usb-toshiba  ext4  defaults,nofail,x-systemd.device-timeout=10  0  2
```

`nofail` ensures Proxmox boots normally even if the drive is unplugged.

Proxmox storage entry (in `/etc/pve/storage.cfg`):
```
dir: usb-toshiba
    path /mnt/pve/usb-toshiba
    content backup
```

---

## Scheduled Backup Job

Job ID: `daily-nas-backup` (in `/etc/pve/jobs.cfg`)

```
vzdump: daily-nas-backup
    all 1
    compress zstd
    enabled 1
    mailto angelcerceda@gmail.com
    mailnotification always
    mode snapshot
    prune-backups keep-daily=3,keep-weekly=2,keep-monthly=1
    schedule 02:00
    storage usb-toshiba
```

---

## Manual Operations

```bash
# SSH into Proxmox (uses passphrase-free deploy key)
ssh -i ~/.ssh/proxmox_deploy root@192.168.40.77

# Manual backup — all guests
pvesh create /nodes/cloudhosted/vzdump \
  --all 1 --storage usb-toshiba --mode snapshot --compress zstd \
  --mailnotification always --mailto angelcerceda@gmail.com

# Manual backup — specific guest
vzdump 106 --storage usb-toshiba --mode snapshot --compress zstd

# List all backups on Toshiba
pvesm list usb-toshiba

# Check storage status
pvesm status

# Preview what prune would delete (safe, no changes)
pvesm prune-backups usb-toshiba \
  --keep-daily 3 --keep-weekly 2 --keep-monthly 1 --dry-run

# View recent backup task history
pvesh get /nodes/cloudhosted/tasks --typefilter vzdump --limit 10
```

---

## Restore a VM

```bash
# Find the backup file
BACKUP=$(ls -t /mnt/pve/usb-toshiba/dump/vzdump-qemu-106-*.vma.zst | head -1)

# Verify integrity
zstd --test "$BACKUP" && echo "OK"

# Restore to a new test VMID (999) — does NOT touch the original
qmrestore "$BACKUP" 999 --storage local-lvm --unique
qm start 999
qm terminal 999    # Ctrl-O to exit
qm stop 999 && qm destroy 999 --purge
```

## Restore a Container

```bash
BACKUP=$(ls -t /mnt/pve/usb-toshiba/dump/vzdump-lxc-100-*.tar.zst | head -1)
zstd --test "$BACKUP" && echo "OK"
pct restore 999 "$BACKUP" --storage local-lvm --unique
pct start 999 && pct enter 999
pct stop 999 && pct destroy 999
```

---

## Restore Checklist

- [ ] Backup file exists with non-zero size (`ls -lh`)
- [ ] `zstd --test` integrity check passes
- [ ] Guest restores without errors
- [ ] Restored guest boots to login prompt
- [ ] Key services running inside restored guest
- [ ] `dmesg | grep -i error` shows no filesystem errors
