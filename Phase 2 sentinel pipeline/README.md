# Phase 2 — The Sentinel Pipeline

> **Objective:** Deploy the syslog forwarder VM, install and configure rsyslog + Azure Monitor Agent (AMA) to bridge pfSense CEF logs into Microsoft Sentinel's `CommonSecurityLog` table — and build 3 KQL detection queries that demonstrate MSP-grade threat hunting.

[← Phase 1: Azure Backbone](phase-1-azure-backbone.md) | [← Back to Lab Index](README.md)

---

## 📋 Table of Contents

- [Architecture Recap](#architecture-recap)
- [Step 1 — Deploy the Syslog Forwarder VM](#step-1--deploy-the-syslog-forwarder-vm)
- [Step 2 — Create the Log Analytics Workspace](#step-2--create-the-log-analytics-workspace)
- [Step 3 — Enable Microsoft Sentinel](#step-3--enable-microsoft-sentinel)
- [Step 4 — Configure rsyslog on the Forwarder](#step-4--configure-rsyslog-on-the-forwarder)
- [Step 5 — Install Azure Monitor Agent (AMA)](#step-5--install-azure-monitor-agent-ama)
- [Step 6 — Run the CEF Installer](#step-6--run-the-cef-installer)
- [Step 7 — Create the Data Collection Rule (DCR)](#step-7--create-the-data-collection-rule-dcr)
- [Step 8 — Configure pfSense Remote Syslog](#step-8--configure-pfsense-remote-syslog)
- [Step 9 — Enable Snort Logging to Syslog](#step-9--enable-snort-logging-to-syslog)
- [Step 10 — Validate the Pipeline](#step-10--validate-the-pipeline)
- [KQL Queries — MSP Grade](#kql-queries--msp-grade)
- [Verification Checklist](#verification-checklist)

---

## Architecture Recap

```
pfSense NVA (pfsense-nva)
  │  filterlog + Snort alerts → UDP/TCP port 514
  ▼
syslog-forwarder (10.10.3.10 — snet-siem)
  │  rsyslog receives syslog on port 514
  │  51-pfsense-filterlog.conf parses filterlog → CEF
  │  CEF messages forwarded to AMA on TCP port 28330
  ▼
Azure Monitor Agent (AMA)
  │  Sends CEF to Sentinel over HTTPS outbound 443
  ▼
Microsoft Sentinel — CommonSecurityLog table
  │  DeviceVendor = "pfSense"
  │  DeviceProduct = "pfsense"
  ▼
KQL Analytics Rules → Alerts → Incidents
```

---

## Step 1 — Deploy the Syslog Forwarder VM

```bash
az vm create \
  --resource-group "rg-sec-hybrid-lab" \
  --name "syslog-forwarder" \
  --image Ubuntu2204 \
  --size "Standard_B2s" \
  --vnet-name "hub-vnet" \
  --subnet "snet-siem" \
  --private-ip-address "10.10.3.10" \
  --public-ip-address "" \
  --admin-username "azureuser" \
  --generate-ssh-keys \
  --location "southafricanorth"
```

> 💡 `--public-ip-address ""` means no public IP — the forwarder is only accessible from within the VNet via the MGMT jump host. This is correct — it should not be internet-exposed.

**Get the private IP to confirm:**

```bash
az vm show \
  --resource-group "rg-sec-hybrid-lab" \
  --name "syslog-forwarder" \
  --show-details \
  --query privateIps \
  --output tsv
# Expected: 10.10.3.10
```

---

## Step 2 — Create the Log Analytics Workspace

```bash
az monitor log-analytics workspace create \
  --resource-group "rg-sec-hybrid-lab" \
  --workspace-name "law-sec-hybrid-lab" \
  --location "southafricanorth" \
  --sku PerGB2018

# Save the workspace ID and key for later
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "rg-sec-hybrid-lab" \
  --workspace-name "law-sec-hybrid-lab" \
  --query customerId \
  --output tsv)

PRIMARY_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group "rg-sec-hybrid-lab" \
  --workspace-name "law-sec-hybrid-lab" \
  --query primarySharedKey \
  --output tsv)

echo "Workspace ID:  $WORKSPACE_ID"
echo "Primary Key:   $PRIMARY_KEY"
```

> 📝 Save both values — you will need them in Step 6.

---

## Step 3 — Enable Microsoft Sentinel

```bash
# Get the workspace resource ID
LAW_RESOURCE_ID=$(az monitor log-analytics workspace show \
  --resource-group "rg-sec-hybrid-lab" \
  --workspace-name "law-sec-hybrid-lab" \
  --query id \
  --output tsv)

# Enable Sentinel on the workspace
az sentinel onboarding-state create \
  --resource-group "rg-sec-hybrid-lab" \
  --workspace-name "law-sec-hybrid-lab" \
  --name "default"
```

---

## Step 4 — Configure rsyslog on the Forwarder

SSH into the forwarder from the MGMT jump host:

```bash
ssh azureuser@10.10.3.10
```

### Install rsyslog

```bash
sudo apt-get update && sudo apt-get install -y rsyslog
```

### Enable UDP and TCP reception on port 514

```bash
sudo sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
sudo sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
sudo sed -i 's/#module(load="imtcp")/module(load="imtcp")/' /etc/rsyslog.conf
sudo sed -i 's/#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' /etc/rsyslog.conf
```

### Download the pfSense CEF parser configs

```bash
# Firewall log parser — converts filterlog to CEF key=value format
sudo wget -q -O /etc/rsyslog.d/51-pfsense-filterlog.conf \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/pfsense/51-pfsense-filterlog.conf

# Nginx / web GUI log parser
sudo wget -q -O /etc/rsyslog.d/52-pfsense-nginx.conf \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/pfsense/52-pfsense-nginx.conf
```

**What 51-pfsense-filterlog.conf does:**

pfSense raw firewall log:
```
filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,52,203.0.113.5,10.10.2.10,54321,443,...
```

After parsing → CEF output:
```
CEF:0|pfSense|pfsense|1.0|firewall|firewall|3|act=block src=203.0.113.5 dst=10.10.2.10 dpt=443 proto=TCP deviceInboundInterface=em0
```

### Create the CEF → AMA forwarding rule

```bash
sudo tee /etc/rsyslog.d/10-cef-to-ama.conf > /dev/null <<'EOF'
# Forward all CEF messages to the Azure Monitor Agent (internal port 28330)
if $rawmsg contains "CEF:" then {
    action(
        type="omfwd"
        Target="127.0.0.1"
        Port="28330"
        Protocol="tcp"
        Template="RSYSLOG_SyslogProtocol23Format"
    )
    stop
}
EOF
```

### Write pfSense logs to a local debug file

```bash
sudo tee /etc/rsyslog.d/60-pfsense-local.conf > /dev/null <<'EOF'
# Capture pfSense syslog locally for debugging
if $fromhost-ip == '10.10.2.1' then /var/log/pfsense.log
& stop
EOF
```

### Restart and verify rsyslog

```bash
sudo systemctl restart rsyslog
sudo systemctl enable rsyslog

# Confirm listening on port 514
sudo ss -ulnp | grep 514
sudo ss -tlnp | grep 514
```

---

## Step 5 — Install Azure Monitor Agent (AMA)

Run from your **local machine or Azure Cloud Shell** — not on the forwarder VM:

```bash
az vm extension set \
  --resource-group "rg-sec-hybrid-lab" \
  --vm-name "syslog-forwarder" \
  --name AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --version 1.0 \
  --enable-auto-upgrade true
```

`--enable-auto-upgrade true` keeps AMA updated automatically — important for security patches.

**Verify AMA is running (on the forwarder VM):**

```bash
sudo systemctl status azuremonitoragent
sudo ss -tlnp | grep 28330   # AMA's internal CEF intake port
```

---

## Step 6 — Run the CEF Installer

This Microsoft script configures rsyslog to pipe CEF messages into AMA on port 28330.

On the **forwarder VM:**

```bash
# Use the Workspace ID and Primary Key from Step 2
sudo wget -q -O /tmp/cef_installer.py \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_installer.py

sudo python3 /tmp/cef_installer.py $WORKSPACE_ID $PRIMARY_KEY
```

---

## Step 7 — Create the Data Collection Rule (DCR)

In the **Azure Portal:**

1. Go to **Microsoft Sentinel** → `law-sec-hybrid-lab`
2. **Content management → Content hub** → Search "Common Event Format"
3. Install **Common Event Format (CEF) via AMA**
4. **Configuration → Data connectors** → **CEF via AMA** → **Open connector page**
5. Click **+ Create data collection rule**

| Field | Value |
|---|---|
| Rule name | `dcr-pfsense-cef` |
| Subscription | Your subscription |
| Resource Group | `rg-sec-hybrid-lab` |
| Region | South Africa North |

6. **Resources** tab → Add `syslog-forwarder`
7. **Collect** tab → Facility: `LOG_LOCAL0`, Severity: `LOG_DEBUG`
8. **Review + Create → Create**

> ⚠️ **Facility matching is critical.** The facility set here must match what pfSense sends. pfSense defaults to `local0`. If they do not match, no logs appear in Sentinel.

---

## Step 8 — Configure pfSense Remote Syslog

In the **pfSense Web GUI** (`https://10.10.2.1`):

1. **Status → System Logs → Settings**
2. Scroll to **Remote Logging Options**

| Setting | Value |
|---|---|
| Enable Remote Logging | ✅ |
| Remote Log Servers | `10.10.3.10:514` |
| IP Protocol | IPv4 |
| Remote Syslog Contents | ✅ Firewall Events |
| Remote Syslog Contents | ✅ System Events |
| Remote Syslog Contents | ✅ Authentication Events |
| Remote Syslog Contents | ✅ VPN Events |

3. Click **Save**

---

## Step 9 — Enable Snort Logging to Syslog

Snort IDS/IPS alerts must also be forwarded so they appear in Sentinel.

In the **pfSense Web GUI:**

1. **Services → Snort → Global Settings**
2. Enable: **Send Snort Alerts to System Log** ✅
3. Set: **Alert System Log Facility** → `LOG_LOCAL1`
4. Set: **Alert System Log Priority** → `LOG_ALERT`
5. Click **Save**

Back in **Status → System Logs → Settings**, ensure `LOG_LOCAL1` is also forwarded:

6. Add a second entry under Remote Log Servers: `10.10.3.10:514` with facility `local1`

**Update the DCR** to also collect `local1`:

In the Azure Portal, edit `dcr-pfsense-cef` → **Collect** tab → Add `LOG_LOCAL1` with `LOG_DEBUG` severity.

---

## Step 10 — Validate the Pipeline

Run these in order. Fix any failure before proceeding to the next.

```bash
# On the forwarder VM:

# 1. Confirm pfSense syslog is arriving
sudo tail -f /var/log/pfsense.log

# 2. Confirm CEF messages are being generated by the parser
sudo grep "CEF:" /var/log/syslog | tail -20

# 3. Confirm AMA is receiving CEF internally
sudo tcpdump -i lo -n port 28330 -A | grep -i CEF

# 4. Fire a manual test event and tag it
logger -p local4.warn -t CEF \
  "CEF:0|pfSense|pfsense|1.0|firewall|firewall|3|act=block src=1.2.3.4 dst=10.10.2.10 dpt=443 proto=TCP cs1Label=Rule cs1=PHASE2_TEST"

# 5. Run Microsoft's official validation script
sudo wget -q -O /tmp/cef_troubleshoot.py \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_troubleshoot.py
sudo python3 /tmp/cef_troubleshoot.py $WORKSPACE_ID
```

**In Sentinel (allow 5–10 minutes):**

```kql
CommonSecurityLog
| where DeviceProduct == "pfsense"
| where AdditionalExtensions contains "PHASE2_TEST"
| project TimeGenerated, DeviceAction, SourceIP, DestinationIP, DestinationPort
```

If the test event appears — the full pipeline is confirmed. ✅

---

## KQL Queries — MSP Grade

These three queries are designed to demonstrate real threat detection capability to an MSP interviewer. Each targets a specific attack scenario that pfSense generates evidence for.

---

### Query 1 — Blocked Traffic Analysis

**Scenario:** An MSP client reports their firewall is noisy. You need to show what is being blocked, from where, and whether there is a pattern indicating reconnaissance or targeted attack.

```kql
// ============================================================
// Blocked Traffic Analysis — pfSense firewall deny events
// Identifies top blocked sources, ports, and time patterns
// Table: CommonSecurityLog | DeviceProduct: pfsense
// ============================================================
let TimeRange = 24h;
let BlockThreshold = 5;

CommonSecurityLog
| where TimeGenerated > ago(TimeRange)
| where DeviceVendor == "pfSense"
| where DeviceAction == "block" or SimplifiedDeviceAction == "Deny"
| summarize
    TotalBlocks     = count(),
    UniquePorts     = dcount(DestinationPort),
    TargetedPorts   = make_set(DestinationPort, 10),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    TargetedHosts   = make_set(DestinationIP, 5)
  by SourceIP, Protocol
| where TotalBlocks >= BlockThreshold
| extend
    DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen),
    ThreatLevel     = case(
        TotalBlocks > 100 and UniquePorts > 10, "🔴 HIGH — Likely Port Scan",
        TotalBlocks > 50,                       "🟠 MEDIUM — Elevated Block Rate",
                                                "🟡 LOW — Monitor"
    )
| project
    SourceIP,
    Protocol,
    TotalBlocks,
    UniquePorts,
    TargetedPorts,
    DurationMinutes,
    ThreatLevel,
    FirstSeen,
    LastSeen
| order by TotalBlocks desc
```

**What this proves to an MSP:** You can identify port scanning, enumerate attacker IPs, assess severity programmatically, and present results in a format that feeds directly into an incident ticket.

---

### Query 2 — VPN Authentication Failures

**Scenario:** A client's remote access VPN is experiencing failures. You need to determine if this is a misconfiguration, expired credentials, or a credential stuffing attack against the VPN endpoint.

```kql
// ============================================================
// VPN Authentication Failure Detection
// Targets IPsec and OpenVPN auth failures from pfSense syslog
// Table: CommonSecurityLog | Syslog
// ============================================================
let TimeRange = 4h;
let FailureThreshold = 3;

let VPNFailureEvents =
    // Source 1: Structured CEF events
    CommonSecurityLog
    | where TimeGenerated > ago(TimeRange)
    | where DeviceVendor == "pfSense"
    | where Activity has_any ("vpn", "ipsec", "openvpn", "isakmp", "authentication")
    | where DeviceAction has_any ("failure", "reject", "deny", "error")
    | extend
        EventSource   = "CEF",
        FailureReason = tostring(AdditionalExtensions),
        ClientIP      = SourceIP,
        Username      = SourceUserName
    | project TimeGenerated, EventSource, ClientIP, Username, FailureReason, Activity
    ;

let SyslogVPNEvents =
    // Source 2: Raw syslog fallback (catches events not yet CEF-parsed)
    Syslog
    | where TimeGenerated > ago(TimeRange)
    | where Computer contains "pfsense" or HostName contains "forwarder"
    | where SyslogMessage has_any (
        "authentication failed", "AUTH_FAILED", "ISAKMP", "NO_PROPOSAL_CHOSEN",
        "invalid id information", "Login incorrect", "TLS handshake failed",
        "peer did not send certificate"
    )
    | extend
        EventSource   = "Syslog",
        ClientIP      = extract(@"from\s+([\d\.]+)", 1, SyslogMessage),
        Username      = extract(@"user\s+'([^']+)'", 1, SyslogMessage),
        FailureReason = SyslogMessage
    | project TimeGenerated, EventSource, ClientIP, Username, FailureReason, Activity = "VPN Auth Failure"
    ;

VPNFailureEvents
| union SyslogVPNEvents
| summarize
    FailureCount  = count(),
    Usernames     = make_set(Username, 5),
    Reasons       = make_set(FailureReason, 5),
    FirstAttempt  = min(TimeGenerated),
    LastAttempt   = max(TimeGenerated)
  by ClientIP, EventSource
| where FailureCount >= FailureThreshold
| extend
    AttackPattern = case(
        FailureCount > 20,                         "🔴 Credential Stuffing Likely",
        FailureCount > 10,                         "🟠 Brute Force Suspected",
        array_length(Usernames) > 3,               "🟠 Username Enumeration",
                                                   "🟡 Auth Misconfiguration"
    ),
    DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| project
    ClientIP,
    EventSource,
    FailureCount,
    DurationMinutes,
    Usernames,
    AttackPattern,
    FirstAttempt,
    LastAttempt
| order by FailureCount desc
```

**What this proves to an MSP:** You understand dual-source log correlation (CEF + raw Syslog fallback), can distinguish between misconfiguration and active attack, and can categorise attack patterns for escalation decisions.

---

### Query 3 — Snort IDS/IPS Alert Triage

**Scenario:** Snort is generating hundreds of alerts. You need to triage them by severity, identify which are genuine threats vs false positives, and surface the top priority incidents for an analyst to investigate.

```kql
// ============================================================
// Snort IDS/IPS Alert Triage Dashboard
// Classifies alerts by severity, maps to MITRE ATT&CK, and
// surfaces repeat offenders for analyst investigation
// Table: CommonSecurityLog | Syslog
// ============================================================
let TimeRange = 12h;

// Parse Snort alerts from syslog (Snort alert format varies by config)
let SnortAlerts =
    Syslog
    | where TimeGenerated > ago(TimeRange)
    | where SyslogMessage contains "snort" or Facility == "local1"
    | where SyslogMessage has_any ("[Priority:", "[Classification:", "ALERT")
    | extend
        // Extract Snort fields using regex
        Priority       = toint(extract(@"\[Priority:\s*(\d)\]", 1, SyslogMessage)),
        Classification = extract(@"\[Classification:\s*([^\]]+)\]", 1, SyslogMessage),
        SigID          = extract(@"\[(\d+:\d+:\d+)\]", 1, SyslogMessage),
        AlertMsg       = extract(@"\]\s+([^{]+)\s+\{", 1, SyslogMessage),
        SrcIP          = extract(@"\{[A-Z]+\}\s+([\d\.]+):\d+\s+->", 1, SyslogMessage),
        DstIP          = extract(@"->\s+([\d\.]+):\d+", 1, SyslogMessage),
        SrcPort        = toint(extract(@"([\d\.]+):(\d+)\s+->", 2, SyslogMessage)),
        DstPort        = toint(extract(@"->\s+[\d\.]+:(\d+)", 1, SyslogMessage)),
        Protocol       = extract(@"\{([A-Z]+)\}", 1, SyslogMessage)
    | where isnotempty(SrcIP)
    ;

SnortAlerts
| summarize
    AlertCount      = count(),
    Signatures      = make_set(AlertMsg, 5),
    Classifications = make_set(Classification, 3),
    TargetPorts     = make_set(DstPort, 5),
    TargetHosts     = make_set(DstIP, 5),
    FirstAlert      = min(TimeGenerated),
    LastAlert       = max(TimeGenerated),
    MinPriority     = min(Priority)
  by SrcIP, Protocol
| extend
    // Map to MITRE ATT&CK based on classification
    MitreTactic = case(
        Classifications has "Web Application Attack",        "T1190 — Exploit Public-Facing App",
        Classifications has "Attempted User Privilege Gain", "T1068 — Exploitation for Privilege Escalation",
        Classifications has "Attempted Denial of Service",   "T1498 — Network Denial of Service",
        Classifications has "Trojan Activity",               "T1071 — Application Layer Protocol (C2)",
        Classifications has "Network Scan",                  "T1046 — Network Service Discovery",
        Classifications has "Misc Attack",                   "T1059 — Command and Scripting Interpreter",
                                                             "Unclassified — Review Manually"
    ),
    SeverityLabel = case(
        MinPriority == 1, "🔴 CRITICAL",
        MinPriority == 2, "🟠 HIGH",
        MinPriority == 3, "🟡 MEDIUM",
                          "🔵 LOW"
    )
| project
    SrcIP,
    Protocol,
    AlertCount,
    SeverityLabel,
    MinPriority,
    MitreTactic,
    Classifications,
    Signatures,
    TargetPorts,
    FirstAlert,
    LastAlert
| order by MinPriority asc, AlertCount desc
```

**What this proves to an MSP:** You can parse raw IDS output, map detections to the MITRE ATT&CK framework, classify by severity, and output an analyst-ready triage view — the difference between raw logs and actionable intelligence.

---

## Verification Checklist

| Check | Command / Location | Pass? |
|---|---|---|
| Syslog forwarder VM running | `az vm show ... --query powerState` | ☐ |
| rsyslog listening on UDP 514 | `sudo ss -ulnp \| grep 514` | ☐ |
| rsyslog listening on TCP 514 | `sudo ss -tlnp \| grep 514` | ☐ |
| AMA service running | `sudo systemctl status azuremonitoragent` | ☐ |
| AMA listening on port 28330 | `sudo ss -tlnp \| grep 28330` | ☐ |
| pfSense logs arriving locally | `sudo tail /var/log/pfsense.log` | ☐ |
| CEF messages being generated | `sudo grep "CEF:" /var/log/syslog` | ☐ |
| Test event visible in Sentinel | KQL in Step 10 | ☐ |
| Snort alerts flowing | Syslog query in Query 3 returns results | ☐ |

---

[← Phase 1: Azure Backbone](phase-1-azure-backbone.md) | [← Back to Lab Index](README.md) | [→ Phase 3: Site-to-Site VPN](phase-3-site-to-site-vpn.md)
