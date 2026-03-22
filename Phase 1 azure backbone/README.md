# Phase 1 — Azure Backbone

> **Objective:** Deploy the full Azure network foundation for the hybrid security lab — VNet, subnets, NSGs, pfSense NVA, IP Forwarding, and User Defined Routes (UDRs) to force all traffic through pfSense.

[← Back to Lab Index](README.md)

---

## 📋 Table of Contents

- [Subnet Design](#subnet-design)
- [Step 1 — Create the Resource Group](#step-1--create-the-resource-group)
- [Step 2 — Create the Virtual Network and Subnets](#step-2--create-the-virtual-network-and-subnets)
- [Step 3 — Create Network Security Groups](#step-3--create-network-security-groups)
- [Step 4 — Create the Static Public IP](#step-4--create-the-static-public-ip)
- [Step 5 — Create the pfSense NICs](#step-5--create-the-pfsense-nics)
- [Step 6 — Deploy the pfSense NVA](#step-6--deploy-the-pfsense-nva)
- [Step 7 — Enable IP Forwarding](#step-7--enable-ip-forwarding)
- [Step 8 — Create User Defined Routes (UDRs)](#step-8--create-user-defined-routes-udrs)
- [Step 9 — pfSense Initial Console Setup](#step-9--pfsense-initial-console-setup)
- [Step 10 — Deploy the Management Jump Host](#step-10--deploy-the-management-jump-host)
- [Verification Checklist](#verification-checklist)

---

## Subnet Design

```
hub-vnet — 10.10.0.0/16
│
├── MGMT Subnet    10.10.0.0/28    ← Jump host, management access only
├── WAN Subnet     10.10.1.0/24    ← pfSense WAN-facing NIC + Public IP
├── LAN Subnet     10.10.2.0/24    ← pfSense LAN gateway (10.10.2.1), workload VMs
└── SIEM Subnet    10.10.3.0/24    ← syslog-forwarder, Sentinel pipeline VMs
```

**Why this design?**

- **MGMT /28** is intentionally small — it hosts only the jump host and limits blast radius
- **WAN /24** is the only subnet with a Public IP. All inbound internet traffic arrives here
- **LAN /24** is where all workload VMs sit. They have no direct internet route — all traffic is forced through pfSense via UDR
- **SIEM /24** isolates monitoring infrastructure. The forwarder only needs outbound 443 to Azure — no internet exposure needed

---

## Step 1 — Create the Resource Group

```bash
az group create \
  --name "rg-sec-hybrid-lab" \
  --location "southafricanorth"
```

> 💡 All resources in this lab go into `rg-sec-hybrid-lab`. To tear down the entire lab, delete this one resource group.

---

## Step 2 — Create the Virtual Network and Subnets

```bash
# Create the VNet with the MGMT subnet in one command
az network vnet create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "hub-vnet" \
  --address-prefix "10.10.0.0/16" \
  --subnet-name "snet-mgmt" \
  --subnet-prefix "10.10.0.0/28" \
  --location "southafricanorth"

# Add the WAN subnet (pfSense outside-facing interface)
az network vnet subnet create \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-wan" \
  --address-prefix "10.10.1.0/24"

# Add the LAN subnet (protected workloads)
az network vnet subnet create \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-lan" \
  --address-prefix "10.10.2.0/24"

# Add the SIEM subnet (log forwarder)
az network vnet subnet create \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-siem" \
  --address-prefix "10.10.3.0/24"
```

**Verify subnets were created:**

```bash
az network vnet subnet list \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --output table
```

---

## Step 3 — Create Network Security Groups

Each subnet gets its own NSG. The principle is **default-deny** — only explicitly allowed traffic passes.

### WAN NSG (pfSense public-facing)

```bash
az network nsg create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nsg-wan"

# Allow HTTPS for pfSense Web GUI (lock down to your IP in production)
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-wan" \
  --name "Allow-HTTPS-WebGUI" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --destination-port-ranges 443

# Allow IPsec IKE for VPN (Phase 3)
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-wan" \
  --name "Allow-IPsec-IKE" \
  --priority 110 \
  --direction Inbound \
  --access Allow \
  --protocol Udp \
  --destination-port-ranges 500

# Allow IPsec NAT-T for VPN (Phase 3)
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-wan" \
  --name "Allow-IPsec-NATT" \
  --priority 120 \
  --direction Inbound \
  --access Allow \
  --protocol Udp \
  --destination-port-ranges 4500
```

### LAN NSG (workload subnet — controlled outbound via pfSense)

```bash
az network nsg create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nsg-lan"

# Allow inbound from MGMT subnet (for management access to workloads)
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-lan" \
  --name "Allow-MGMT-Inbound" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol "*" \
  --source-address-prefixes "10.10.0.0/28" \
  --destination-port-ranges "*"
```

### SIEM NSG (syslog forwarder)

```bash
az network nsg create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nsg-siem"

# Allow syslog inbound from pfSense (LAN IP)
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-siem" \
  --name "Allow-Syslog-UDP" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Udp \
  --source-address-prefixes "10.10.2.0/24" \
  --destination-port-ranges 514

az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-siem" \
  --name "Allow-Syslog-TCP" \
  --priority 110 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes "10.10.2.0/24" \
  --destination-port-ranges 514

# Allow SSH from MGMT only
az network nsg rule create \
  --resource-group "rg-sec-hybrid-lab" \
  --nsg-name "nsg-siem" \
  --name "Allow-SSH-MGMT" \
  --priority 120 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes "10.10.0.0/28" \
  --destination-port-ranges 22
```

### Associate NSGs to subnets

```bash
az network vnet subnet update \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-wan" \
  --network-security-group "nsg-wan"

az network vnet subnet update \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-lan" \
  --network-security-group "nsg-lan"

az network vnet subnet update \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-siem" \
  --network-security-group "nsg-siem"
```

---

## Step 4 — Create the Static Public IP

```bash
az network public-ip create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "pfsense-pip" \
  --allocation-method Static \
  --sku Standard \
  --zone 1 \
  --location "southafricanorth"

# Note the public IP address for later
az network public-ip show \
  --resource-group "rg-sec-hybrid-lab" \
  --name "pfsense-pip" \
  --query ipAddress \
  --output tsv
```

---

## Step 5 — Create the pfSense NICs

> ⚠️ **Critical:** pfSense with multiple NICs **cannot** be deployed via the Azure Portal. You must use the CLI. The WAN NIC must be created first and marked as primary.

```bash
# WAN NIC — connects to snet-wan, carries the public IP and WAN NSG
az network nic create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nic-pfsense-wan" \
  --vnet-name "hub-vnet" \
  --subnet "snet-wan" \
  --public-ip-address "pfsense-pip" \
  --network-security-group "nsg-wan" \
  --ip-forwarding true \
  --location "southafricanorth"

# LAN NIC — connects to snet-lan, private gateway IP for all internal VMs
az network nic create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nic-pfsense-lan" \
  --vnet-name "hub-vnet" \
  --subnet "snet-lan" \
  --private-ip-address "10.10.2.1" \
  --ip-forwarding true \
  --location "southafricanorth"
```

> 💡 `--private-ip-address "10.10.2.1"` statically assigns pfSense's LAN IP. This is the address you will configure as the **next-hop** in your UDR and as the **default gateway** in all LAN VMs.

---

## Step 6 — Deploy the pfSense NVA

```bash
# Accept Netgate Marketplace terms (required once per subscription)
az vm image terms accept \
  --publisher netgate \
  --offer netgate-pfsense-plus-fw-vpn-router \
  --plan netgate-pfsense-plus-fw-vpn-router

# Deploy pfSense with both NICs attached
az vm create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "pfsense-nva" \
  --image netgate:netgate-pfsense-plus-fw-vpn-router:netgate-pfsense-plus-fw-vpn-router:latest \
  --size "Standard_B2s" \
  --nics "nic-pfsense-wan" "nic-pfsense-lan" \
  --admin-username "pfadmin" \
  --generate-ssh-keys \
  --location "southafricanorth"
```

**NIC order matters:** Azure attaches NICs in the order they are listed. `nic-pfsense-wan` becomes `hn0` (WAN) and `nic-pfsense-lan` becomes `hn1` (LAN) inside pfSense.

---

## Step 7 — Enable IP Forwarding

**IP Forwarding** must be enabled at the **Azure platform level** on both NICs. Without this, Azure's hypervisor drops any packet whose destination IP does not match the NIC's own IP — which breaks all routing through pfSense.

```bash
# Enable IP Forwarding on the WAN NIC
az network nic update \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nic-pfsense-wan" \
  --ip-forwarding true

# Enable IP Forwarding on the LAN NIC
az network nic update \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nic-pfsense-lan" \
  --ip-forwarding true
```

> ⚠️ **This is the most commonly missed step.** IP Forwarding at the Azure NIC level is separate from pfSense's own forwarding — both must be enabled. If traffic is not flowing through pfSense even after UDRs are applied, this is the first thing to check.

**Verify IP Forwarding is enabled:**

```bash
az network nic show \
  --resource-group "rg-sec-hybrid-lab" \
  --name "nic-pfsense-lan" \
  --query "enableIpForwarding" \
  --output tsv
# Expected: true
```

---

## Step 8 — Create User Defined Routes (UDRs)

**UDRs** override Azure's default system routes. Without UDRs, VMs on `snet-lan` route directly to the internet via Azure's built-in default gateway — completely bypassing pfSense. UDRs force every packet through pfSense first.

### Why UDRs are necessary

```
Without UDR:
  LAN VM (10.10.2.10) → internet (direct via Azure SDN) ← pfSense never sees this traffic

With UDR:
  LAN VM (10.10.2.10) → pfSense (10.10.2.1) → pfSense inspects/filters → internet
```

### Create the Route Table

```bash
az network route-table create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "rt-lan-to-pfsense" \
  --location "southafricanorth"
```

### Add the default route via pfSense

```bash
# Force all internet-bound traffic (0.0.0.0/0) through pfSense
az network route-table route create \
  --resource-group "rg-sec-hybrid-lab" \
  --route-table-name "rt-lan-to-pfsense" \
  --name "route-all-via-pfsense" \
  --address-prefix "0.0.0.0/0" \
  --next-hop-type "VirtualAppliance" \
  --next-hop-ip-address "10.10.2.1"

# Force on-premises traffic (Hyper-V) through pfSense (Phase 3 — VPN)
az network route-table route create \
  --resource-group "rg-sec-hybrid-lab" \
  --route-table-name "rt-lan-to-pfsense" \
  --name "route-onprem-via-pfsense" \
  --address-prefix "192.168.1.0/24" \
  --next-hop-type "VirtualAppliance" \
  --next-hop-ip-address "10.10.2.1"
```

> 💡 `192.168.1.0/24` is the Hyper-V lab network address space. Adjust to match your actual on-premises subnet.

### Associate the Route Table to the LAN subnet

```bash
az network vnet subnet update \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-lan" \
  --route-table "rt-lan-to-pfsense"
```

### Also apply a UDR to the SIEM subnet

The syslog forwarder also needs its traffic to flow through pfSense for inspection:

```bash
az network route-table create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "rt-siem-to-pfsense" \
  --location "southafricanorth"

az network route-table route create \
  --resource-group "rg-sec-hybrid-lab" \
  --route-table-name "rt-siem-to-pfsense" \
  --name "route-all-via-pfsense" \
  --address-prefix "0.0.0.0/0" \
  --next-hop-type "VirtualAppliance" \
  --next-hop-ip-address "10.10.2.1"

az network vnet subnet update \
  --resource-group "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  --name "snet-siem" \
  --route-table "rt-siem-to-pfsense"
```

---

## Step 9 — pfSense Initial Console Setup

Use the **Azure Serial Console** to complete first-boot configuration without needing a network connection.

**In the Azure Portal:** `pfsense-nva → Support + Troubleshooting → Serial Console`

### Interface assignment

```
Should VLANs be set up now? → n

Enter the WAN interface name:  hn0
Enter the LAN interface name:  hn1
Proceed?                     → y
```

### Set LAN IP (Option 2)

```
Enter the new LAN IPv4 address:  10.10.2.1
Enter the new LAN IPv4 subnet bit count:  24
Enter the upstream gateway address for the LAN:  (blank — leave empty)
Do you want to enable the DHCP server on LAN?  n
```

### Enable SSH (Option 14)

```
SSHD is currently disabled.
Do you want to enable SSHD?  y
```

### pfSense firewall rules — initial LAN rule

Log into the pfSense Web GUI from the MGMT subnet (`https://10.10.2.1`) and add the minimum rules to allow traffic:

**Firewall → Rules → LAN:**

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow LAN to any | TCP/UDP | LAN net | any | any | ✅ Allow |
| Allow LAN to pfSense GUI | TCP | LAN net | This Firewall | 443 | ✅ Allow |
| Allow LAN to pfSense SSH | TCP | LAN net | This Firewall | 22 | ✅ Allow |

**Firewall → Rules → WAN:**

| Rule | Protocol | Source | Destination | Port | Action |
|---|---|---|---|---|---|
| Allow IPsec IKE | UDP | any | WAN address | 500 | ✅ Allow |
| Allow IPsec NAT-T | UDP | any | WAN address | 4500 | ✅ Allow |
| Block all else | any | any | any | any | 🚫 Block (default) |

---

## Step 10 — Deploy the Management Jump Host

The MGMT jump host provides a secure entry point for administering all other VMs without exposing them directly to the internet.

```bash
az vm create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "mgmt-vm" \
  --image Win2022Datacenter \
  --size "Standard_B1s" \
  --vnet-name "hub-vnet" \
  --subnet "snet-mgmt" \
  --admin-username "labadmin" \
  --admin-password "<YourStrongPassword>" \
  --public-ip-address "mgmt-pip" \
  --location "southafricanorth"
```

> 💰 Deallocate `mgmt-vm` when not in use — it is not needed for the log pipeline to run.

```bash
az vm deallocate --resource-group "rg-sec-hybrid-lab" --name "mgmt-vm"
```

---

## Verification Checklist

Run these checks after completing Phase 1 to confirm the foundation is solid before proceeding to Phase 2.

```bash
# 1. All resources exist in the resource group
az resource list --resource-group "rg-sec-hybrid-lab" --output table

# 2. IP Forwarding is enabled on both NICs
az network nic show -g "rg-sec-hybrid-lab" -n "nic-pfsense-wan" --query enableIpForwarding -o tsv
az network nic show -g "rg-sec-hybrid-lab" -n "nic-pfsense-lan" --query enableIpForwarding -o tsv
# Both should return: true

# 3. Route table is associated to snet-lan
az network vnet subnet show \
  -g "rg-sec-hybrid-lab" \
  --vnet-name "hub-vnet" \
  -n "snet-lan" \
  --query routeTable.id \
  -o tsv
# Should return a resource ID containing rt-lan-to-pfsense

# 4. pfSense VM is running
az vm show \
  --resource-group "rg-sec-hybrid-lab" \
  --name "pfsense-nva" \
  --show-details \
  --query powerState \
  --output tsv
# Expected: VM running
```

| Check | Expected Result | Pass? |
|---|---|---|
| All 4 subnets exist | Listed in `az network vnet subnet list` | ☐ |
| IP Forwarding on WAN NIC | `true` | ☐ |
| IP Forwarding on LAN NIC | `true` | ☐ |
| UDR associated to `snet-lan` | Route table ID shown | ☐ |
| pfSense VM power state | `VM running` | ☐ |
| pfSense Web GUI accessible | `https://10.10.2.1` loads from MGMT VM | ☐ |
| LAN VM can ping pfSense | `ping 10.10.2.1` succeeds | ☐ |

---

[← Back to Lab Index](README.md) | [→ Phase 2: Sentinel Pipeline](phase-2-sentinel-pipeline.md)
