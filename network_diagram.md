# Network Diagram — 192.168.40.0/24

Updated: 2026-06-06  
Source: nmap scan + manual verification

> Render in VS Code (Markdown Preview), GitHub, or Obsidian.

```mermaid
graph LR

    classDef Router    fill:#ff9900,stroke:#cc7700,color:#000
    classDef NAS       fill:#0066cc,stroke:#004499,color:#fff
    classDef Proxmox   fill:#e5530a,stroke:#b33d00,color:#fff
    classDef Container fill:#10b981,stroke:#059669,color:#fff
    classDef Storage   fill:#8b5cf6,stroke:#6d28d9,color:#fff
    classDef IoT       fill:#f59e0b,stroke:#d97706,color:#000
    classDef ThisMachine fill:#ec4899,stroke:#be185d,color:#fff

    router["192.168.40.1
    Router
    Sagemcom / OpenWrt
    ports: 80, 443"]

    nas[("192.168.40.9
    Buffalo NAS
    hostname: BUFFALO
    Samba 4 · SSH · dnsmasq
    ports: 22, 53, 139, 445")]

    samsung["192.168.40.35
    Samsung Device
    port: 8080"]

    thishost["192.168.40.51
    This Machine
    Arch Linux / wlan0"]

    subgraph pve ["Proxmox VE — cloudhosted  (192.168.40.77)"]

        proxmox["192.168.40.77
        Proxmox VE 8.4
        Gigabyte · NVMe 1 TB
        17 guests: 2 VM · 15 LXC
        ports: 22, 139, 445, 2049"]

        toshiba[("Toshiba USB — /dev/sda1
        916 GB · ext4
        Backup storage
        nightly 02:00
        retention: 3d · 2w · 1m")]

        hitachi[("Hitachi USB — /dev/sdb1
        931 GB · vfat
        not in use")]

        ct100["192.168.40.100
        CT 100 — casaOS
        HTTP · SMB
        ports: 22, 80, 139, 445"]

        ct110["192.168.40.110
        CT 110 — APIS
        HTTP login
        ports: 22, 80"]

        ct111["192.168.40.125
        CT 111 — cloudhosted.pro
        nginx · CloudHosted Pro
        ports: 22, 80"]

        ct115["192.168.40.115
        CT 115 — tenantlist
        openresty · HTTPS
        ports: 22, 80, 443"]

        ct_67["192.168.40.67
        Container
        SSH only · port: 22"]

        ct_140["192.168.40.140
        Container
        SSH only · port: 22"]

        ct_147["192.168.40.147
        Container
        SSH only · port: 22"]

        ct_215["192.168.40.215
        Container
        SMB file sharing
        ports: 22, 139, 445"]

    end

    router --- nas
    router --- samsung
    router --- thishost
    router --- proxmox

    proxmox -.->|"backup · nightly 02:00"| toshiba
    proxmox --- hitachi
    proxmox --- ct100
    proxmox --- ct110
    proxmox --- ct111
    proxmox --- ct115
    proxmox --- ct_67
    proxmox --- ct_140
    proxmox --- ct_147
    proxmox --- ct_215

    class router Router
    class nas NAS
    class samsung IoT
    class thishost ThisMachine
    class proxmox Proxmox
    class toshiba,hitachi Storage
    class ct100,ct110,ct111,ct115,ct_67,ct_140,ct_147,ct_215 Container
```

---

## Device Summary

| IP | Hostname | Type | Vendor | Ports | Notes |
|----|----------|------|--------|-------|-------|
| 192.168.40.1 | — | Router | Sagemcom Broadband SAS | 80, 443 | OpenWrt gateway |
| 192.168.40.9 | BUFFALO | NAS | Buffalo Inc | 22, 53, 139, 445 | Samba 4 · dnsmasq · SSH |
| 192.168.40.35 | — | IoT | Samsung Electronics | 8080 | Smart TV or Android device |
| 192.168.40.51 | — | This machine | — | — | Arch Linux · wlan0 |
| 192.168.40.67 | — | LXC container | Proxmox | 22 | OpenSSH 10.0 (Debian trixie) |
| 192.168.40.77 | cloudhosted | Proxmox host | Gigabyte | 22, 139, 445, 2049 | PVE 8.4 · NVMe 1 TB · 17 guests |
| 192.168.40.100 | — | LXC container | Proxmox | 22, 80, 139, 445 | CT 100 · CasaOS |
| 192.168.40.110 | — | LXC container | Proxmox | 22, 80 | CT 110 · APIS |
| 192.168.40.115 | — | LXC container | Proxmox | 22, 80, 443 | CT 115 · openresty · HTTPS |
| 192.168.40.125 | — | LXC container | Proxmox | 22, 80 | CT 111 · cloudhosted.pro · nginx |
| 192.168.40.140 | — | LXC container | Proxmox | 22 | SSH only |
| 192.168.40.147 | — | LXC container | Proxmox | 22 | SSH only |
| 192.168.40.215 | — | LXC container | Proxmox | 22, 139, 445 | SMB file sharing (not the NAS) |

---

## Proxmox Guests Not Visible on This Subnet

Configured on Proxmox but did not appear in the scan (stopped, NAT'd, or bridged separately):

| VMID | Name | Type | Disk |
|------|------|------|------|
| 101 | microservices | LXC | 100 GB |
| 102 | CRM | LXC | 35 GB |
| 103 | DNS | LXC | 15 GB |
| 104 | clinic | LXC | 11 GB |
| 105 | candles | LXC | 20 GB |
| 106 | AI | VM | 150 GB |
| 107 | mail | LXC | 20 GB |
| 108 | photos | LXC | 30 GB |
| 109 | portainer | LXC | 12 GB |
| 112 | Template | LXC | 10 GB |
| 113 | apisApp | VM | 32 GB |
| 114 | pestleads | LXC | 40 GB |
| 116 | vananavan | LXC | 25 GB |

---

## Proxmox Backup

| Setting | Value |
|---------|-------|
| Storage | Toshiba USB `/dev/sda1` → `/mnt/pve/usb-toshiba` |
| Capacity | 916 GB ext4 |
| Schedule | Daily at 02:00 — all 17 guests |
| Compression | zstd · ~94 GB per full run |
| Retention | 3 daily · 2 weekly · 1 monthly |
| Notifications | angelcerceda@gmail.com |
