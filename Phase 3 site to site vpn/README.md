# Phase 3 — Hybrid Connectivity: Site-to-Site VPN

> **Objective:** Establish a secure IPsec IKEv2 site-to-site VPN tunnel between the on-premises Hyper-V lab (`192.168.1.0/24`) and the Azure pfSense NVA (`10.10.0.0/16`) — simulating a real MSP client hybrid connectivity scenario.

[← Phase 2: Sentinel Pipeline](phase-2-sentinel-pipeline.md) | [← Back to Lab Index](README.md)

---

## 📋 Table of Contents

- [Topology Overview](#topology-overview)
- [IP Address Plan](#ip-address-plan)
- [Prerequisites](#prerequisites)
- [Part A — pfSense Azure Side (Phase 1)](#part-a--pfsense-azure-side)
- [Part B — pfSense On-Premises Side (Hyper-V)](#part-b--pfsense-on-premises-side-hyper-v)
- [Step 1 — Configure Phase 1 (IKE) on Azure pfSense](#step-1--configure-phase-1-ike-on-azure-pfsense)
- [Step 2 — Configure Phase 2 (ESP) on Azure pfSense](#step-2--configure-phase-2-esp-on-azure-pfsense)
- [Step 3 — Configure Phase 1 (IKE) on Hyper-V pfSense](#step-3--configure-phase-1-ike-on-hyper-v-pfsense)
- [Step 4 — Configure Phase 2 (ESP) on Hyper-V pfSense](#step-4--configure-phase-2-esp-on-hyper-v-pfsense)
- [Step 5 — Add Firewall Rules on Both Sides](#step-5--add-firewall-rules-on-both-sides)
- [Step 6 — Update Azure Route Tables](#step-6--update-azure-route-tables)
- [Step 7 — Initiate and Verify the Tunnel](#step-7--initiate-and-verify-the-tunnel)
- [Step 8 — Test Hybrid Connectivity](#step-8--test-hybrid-connectivity)
- [Common Failure Modes](#common-failure-modes)
- [Verification Checklist](#verification-checklist)

---

## Topology Overview

```
On-Premises (Hyper-V)                        Azure (South Africa North)
─────────────────────                        ──────────────────────────
192.168.1.0/24                               10.10.0.0/16

  Hyper-V pfSense                              Azure pfSense NVA
  WAN: <your-home-public-ip>  ═══IPsec═══  WAN: <pfsense-pip>
  LAN: 192.168.1.1                             LAN: 10.10.2.1

  win-srv-01 (IIS)                             Workload VMs
  192.168.1.10                                 10.10.2.x

  kali-01
  192.168.1.20
```

---

## IP Address Plan

| Side | Role | IP |
|---|---|---|
| Azure pfSense | WAN (Public IP) | `<pfsense-pip>` — from `az network public-ip show` |
| Azure pfSense | LAN gateway | `10.10.2.1` |
| Azure | Protected LAN subnet | `10.10.2.0/24` |
| Azure | Full VNet | `10.10.0.0/16` |
| Hyper-V pfSense | WAN (your public IP) | `<your-home-public-ip>` |
| Hyper-V pfSense | LAN gateway | `192.168.1.1` |
| On-premises | Protected LAN subnet | `192.168.1.0/24` |
| Win Server (IIS) | Fixed LAN IP | `192.168.1.10` |
| Kali Linux | Fixed LAN IP | `192.168.1.20` |

---

## Prerequisites

Before starting Phase 3, confirm:

- ✅ Phase 1 complete — pfSense NVA running in Azure
- ✅ Phase 2 complete — Sentinel pipeline active
- ✅ Hyper-V pfSense deployed (see the [pfSense NVA guide](../../firewalls/azure-pfsense-nva.md) for the Hyper-V VHD method)
- ✅ Your home/lab public IP is known and static (or you have DDNS)
- ✅ UDP ports 500 and 4500 are open inbound on **both** firewalls
- ✅ Your ISP does not block UDP 500/4500 (check with `nc -vzu <azure-pip> 500`)

---

## Part A — pfSense Azure Side

All steps in Part A are performed in the **pfSense Web GUI** accessed from the MGMT jump host: `https://10.10.2.1`

---

## Step 1 — Configure Phase 1 (IKE) on Azure pfSense

**VPN → IPsec → Tunnels → + Add P1**

| Field | Value | Why |
|---|---|---|
| **Key Exchange version** | IKEv2 | More secure and faster than IKEv1. Supports MOBIKE for resilience |
| **Internet Protocol** | IPv4 | — |
| **Interface** | WAN | VPN terminates on the WAN interface |
| **Remote Gateway** | `<your-home-public-ip>` | The public IP of your Hyper-V pfSense WAN |
| **Description** | `HybridLab-OnPrem-P1` | — |
| **Authentication Method** | Mutual PSK | Pre-Shared Key — simpler for lab, cert-based for production |
| **Pre-Shared Key** | `<YourStrongPSK>` | Use 32+ random characters. Both sides must match exactly |
| **Encryption Algorithm** | AES 256 | Strong symmetric encryption |
| **Hash Algorithm** | SHA-256 | — |
| **DH Group** | 14 (2048 bit) | — |
| **Lifetime** | 28800 | 8 hours — standard IKE SA lifetime |
| **Dead Peer Detection** | ✅ Enabled | Detects dead peers and restarts tunnel |
| **DPD Delay** | 10 | Seconds between DPD probes |
| **DPD Max Failures** | 5 | — |

Click **Save**

> 💡 **IKEv2 vs IKEv1:** IKEv2 is the modern standard. It uses fewer messages to establish a tunnel (4 vs 6+), supports **MOBIKE** for mobile clients that change IP, and has better built-in NAT traversal. Always prefer IKEv2 unless the remote peer forces IKEv1.

---

## Step 2 — Configure Phase 2 (ESP) on Azure pfSense

Click the **Show Phase 2 Entries** button under the P1 entry you just created, then **+ Add P2**

| Field | Value | Why |
|---|---|---|
| **Mode** | Tunnel IPv4 | Full tunnel between two subnets |
| **Local Network** | `10.10.0.0/16` | The entire Azure VNet (covers all subnets) |
| **Remote Network** | `192.168.1.0/24` | The Hyper-V LAN subnet |
| **Description** | `HybridLab-OnPrem-P2` | — |
| **Protocol** | ESP | Encapsulating Security Payload — provides encryption |
| **Encryption Algorithms** | AES 256-GCM (128 bit) | AEAD — provides both encryption and integrity in one pass |
| **Hash Algorithms** | SHA-256 | Only used with non-AEAD — leave blank if using GCM |
| **PFS Key Group** | 14 (2048 bit) | **Perfect Forward Secrecy** — ensures session keys cannot be derived from the PSK even if compromised |
| **Lifetime** | 3600 | 1 hour — standard ESP SA lifetime |
| **Automatically ping host** | `192.168.1.1` | Keeps the tunnel alive with periodic pings to the Hyper-V pfSense LAN |

Click **Save**, then **Apply Changes**

> 💡 **Why AES-256-GCM?** GCM (Galois/Counter Mode) is an **AEAD cipher** — it simultaneously encrypts and authenticates in a single operation. This is faster and more secure than combining AES-CBC + HMAC separately. Modern Fortinet FortiGate and Cisco IOS-XE also prefer GCM for exactly this reason.

---

## Part B — pfSense On-Premises Side (Hyper-V)

All steps in Part B are performed in the **Hyper-V pfSense Web GUI**: `https://192.168.1.1`

The configuration mirrors Part A exactly — both sides must agree on all parameters. The only values that flip are the Local/Remote networks and gateway IPs.

---

## Step 3 — Configure Phase 1 (IKE) on Hyper-V pfSense

**VPN → IPsec → Tunnels → + Add P1**

| Field | Value |
|---|---|
| **Key Exchange version** | IKEv2 |
| **Interface** | WAN |
| **Remote Gateway** | `<pfsense-pip>` (Azure pfSense public IP) |
| **Description** | `HybridLab-Azure-P1` |
| **Authentication Method** | Mutual PSK |
| **Pre-Shared Key** | `<YourStrongPSK>` ← **must match exactly** |
| **Encryption Algorithm** | AES 256 |
| **Hash Algorithm** | SHA-256 |
| **DH Group** | 14 (2048 bit) |
| **Lifetime** | 28800 |
| **Dead Peer Detection** | ✅ Enabled |

Click **Save**

---

## Step 4 — Configure Phase 2 (ESP) on Hyper-V pfSense

Click **Show Phase 2 Entries → + Add P2**

| Field | Value |
|---|---|
| **Mode** | Tunnel IPv4 |
| **Local Network** | `192.168.1.0/24` ← flipped from Azure side |
| **Remote Network** | `10.10.0.0/16` ← flipped from Azure side |
| **Description** | `HybridLab-Azure-P2` |
| **Protocol** | ESP |
| **Encryption Algorithms** | AES 256-GCM (128 bit) |
| **PFS Key Group** | 14 (2048 bit) |
| **Lifetime** | 3600 |
| **Automatically ping host** | `10.10.2.1` |

Click **Save**, then **Apply Changes**

---

## Step 5 — Add Firewall Rules on Both Sides

### Azure pfSense — IPsec interface rules

**Firewall → Rules → IPsec** (this tab appears automatically once IPsec is configured)

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow on-prem to Azure | any | `192.168.1.0/24` | `10.10.0.0/16` | any | ✅ Allow |

> This rule allows traffic that arrives through the IPsec tunnel from the on-premises network.

### Azure pfSense — WAN rules (already done in Phase 1)

Confirm these exist under **Firewall → Rules → WAN:**

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow IPsec IKE | UDP | any | WAN address | 500 | ✅ Allow |
| Allow IPsec NAT-T | UDP | any | WAN address | 4500 | ✅ Allow |

### Hyper-V pfSense — IPsec interface rules

**Firewall → Rules → IPsec**

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow Azure to on-prem | any | `10.10.0.0/16` | `192.168.1.0/24` | any | ✅ Allow |

### Hyper-V pfSense — WAN rules

**Firewall → Rules → WAN**

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow IPsec IKE | UDP | any | WAN address | 500 | ✅ Allow |
| Allow IPsec NAT-T | UDP | any | WAN address | 4500 | ✅ Allow |

---

## Step 6 — Update Azure Route Tables

The on-premises subnet route was pre-created in Phase 1. Verify it exists:

```bash
az network route-table route show \
  --resource-group "rg-sec-hybrid-lab" \
  --route-table-name "rt-lan-to-pfsense" \
  --name "route-onprem-via-pfsense" \
  --output table
```

Expected output: `192.168.1.0/24` → `VirtualAppliance` → `10.10.2.1`

If it is missing, add it:

```bash
az network route-table route create \
  --resource-group "rg-sec-hybrid-lab" \
  --route-table-name "rt-lan-to-pfsense" \
  --name "route-onprem-via-pfsense" \
  --address-prefix "192.168.1.0/24" \
  --next-hop-type "VirtualAppliance" \
  --next-hop-ip-address "10.10.2.1"
```

> ⚠️ **Asymmetric routing warning:** Without this route, replies from Azure VMs to on-premises hosts take a different path than the request — causing connections to fail silently. This is one of the most common issues when adding VPN to an existing NVA setup. See the [Troubleshooting Ledger](troubleshooting-ledger.md) for details.

---

## Step 7 — Initiate and Verify the Tunnel

### Initiate from Hyper-V pfSense

**Status → IPsec → Overview**

Click the **Connect (▶)** button next to the `HybridLab-Azure-P1` entry.

Watch the status — it should progress through:

```
Connecting → IKE SA Established → CHILD SA Installed → ESTABLISHED
```

### Expected established state

**On Azure pfSense** (`https://10.10.2.1`): **Status → IPsec**

```
HybridLab-OnPrem-P1     ESTABLISHED     <your-home-public-ip>
  HybridLab-OnPrem-P2   INSTALLED       192.168.1.0/24 <> 10.10.0.0/16
```

**On Hyper-V pfSense** (`https://192.168.1.1`): **Status → IPsec**

```
HybridLab-Azure-P1      ESTABLISHED     <pfsense-pip>
  HybridLab-Azure-P2    INSTALLED       10.10.0.0/16 <> 192.168.1.0/24
```

### Check IKE logs for handshake details

**Status → System Logs → IPsec** on either pfSense:

```
charon: 09[IKE] IKE_SA HybridLab-OnPrem-P1[1] established between <azure-pip>[<azure-pip>]...<home-ip>[<home-ip>]
charon: 10[IKE] CHILD_SA HybridLab-OnPrem-P2{1} established with SPIs ...
```

---

## Step 8 — Test Hybrid Connectivity

### Ping from Azure LAN VM to Hyper-V IIS server

From a VM on `10.10.2.0/24`:

```bash
ping 192.168.1.10 -c 4
```

### Ping from Kali to Azure LAN VM

From Kali Linux (`192.168.1.20`):

```bash
ping 10.10.2.10 -c 4
```

### Test IIS web server is reachable from Azure

```bash
curl http://192.168.1.10
```

### Verify traffic is passing through the tunnel (not direct)

On Azure pfSense → **Diagnostics → Packet Capture**, capture on the IPsec interface and look for traffic between the two subnets.

### Run a Kali nmap scan across the tunnel (generates IDS alerts)

```bash
nmap -sS -p 1-1000 10.10.2.0/24
```

Then verify the scan generates Snort alerts in Sentinel using the Query 3 KQL from Phase 2.

---

## Common Failure Modes

| Symptom | Cause | Fix |
|---|---|---|
| Tunnel stuck at "Connecting" | PSK mismatch | Verify PSK is identical on both sides — copy/paste, don't retype |
| `NO_PROPOSAL_CHOSEN` in logs | Encryption/DH Group mismatch | Both sides must match on AES-256, SHA-256, DH14 exactly |
| Tunnel connects but no traffic passes | Missing firewall rule on IPsec interface | Add Allow rule under Firewall → Rules → IPsec on both sides |
| Traffic one-way only (asymmetric routing) | Missing UDR for on-premises subnet | Add `192.168.1.0/24 → 10.10.2.1` route in Azure route table |
| Tunnel drops and reconnects frequently | DPD timeout too aggressive | Increase DPD Delay to 30s or check NAT-T is enabled |
| `TS_UNACCEPTABLE` in logs | Phase 2 local/remote networks don't match | Azure P2 Local=`10.10.0.0/16` Remote=`192.168.1.0/24` and vice versa on Hyper-V |
| UDP 500/4500 blocked | ISP or NSG blocking | Check NSG allows UDP 500 and 4500 inbound on Azure WAN NIC |
| Tunnel works but Sentinel shows no VPN events | Snort/syslog not forwarding VPN logs | Ensure Authentication and VPN events are checked in pfSense remote syslog settings |

---

## Verification Checklist

| Check | Method | Pass? |
|---|---|---|
| Phase 1 SA ESTABLISHED on both sides | Status → IPsec on both pfSense | ☐ |
| Phase 2 CHILD_SA INSTALLED | Status → IPsec → Phase 2 entries | ☐ |
| Azure VM can ping Hyper-V host | `ping 192.168.1.10` from 10.10.2.x | ☐ |
| Kali can ping Azure VM | `ping 10.10.2.10` from 192.168.1.20 | ☐ |
| IIS web server reachable from Azure | `curl http://192.168.1.10` | ☐ |
| Nmap scan generates Snort alerts in Sentinel | Query 3 KQL returns results | ☐ |
| VPN auth events visible in Sentinel | Query 2 KQL (change to filter for established events) | ☐ |
| Route table has on-premises route | `az network route-table route show` | ☐ |

---

[← Phase 2: Sentinel Pipeline](phase-2-sentinel-pipeline.md) | [← Back to Lab Index](README.md)
