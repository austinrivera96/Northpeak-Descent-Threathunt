<p align="center">
<img width="1402" height="1122" alt="image" src="https://github.com/user-attachments/assets/4d1f1b80-0f81-48fd-ad2d-da920c1fb9c2" />

</p>




# 🛡️ Threat Hunt Report – NorthPeak Descent

---

## 📌 Executive Summary

An attacker gained acces to the Northpeak Logistices enviornment using valid credentials over RDP, established persistence, pivoted between Windows and Linux systems, and ultimatley exfiltrated sensitive customer data without exploiting vulnerabilities or disabling security controls. This hunt demonstrates how legitimate credientials and living-off-the-land techniques can allow an attacker to evade detection while maintaining long-term access. 

The investigation reconstructs the complete attack chain, identigying the initial attack vector, internal pivoting with NetExec, persistence via a winows run registry key, an automated command-and-control beacon, and the exfiltration of a customer data export to a malicious domain. 

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:**
  -  Northpeak Logistics enterprise environment (Windows workstations and servers, Linux host, Microsoft Sentinel & Microsoft Defender for Endpoint)
  -  Scope: Northpeak Hosts
    -`npt-ws01`
    -`npt-srv01`
    -`npt-linux01`  
- **Data Sources:**
  -  Microsoft Defender XDR
    - `DeviceProcessEvents`
    - `DeviceLogonEvents`
    - `DeviceNetworkEvents`
    - `DeviceRegistryEvents`
    - `DeviceFileEvents`
    - `DeviceEvents`
   - Microsoft Sentinel Log Analytics
- **Timeframe:**
  - 2026-06-16 → 2026-06-17 (20:00 UTC on June 16 through 00:30 UTC on June 17)

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | <Placeholder> | <Placeholder> | <Placeholder> |
| 2 | <Placeholder> | <Placeholder> | <Placeholder> |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: The Real Foothold <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "They didn't exploit anything to get in. One external address got onto the Windows estate cleanly and worked it interactively. Give me that source and how they came through."`

### 📌 Finding
The attacker successfully authenticated to a Windows host from an external source using legitimate credentials. The activity did not indicate exploitation; instead, the attacker used a valid-account intrusion to gain interactive access and begin post-compromise activity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | `npt-ws01` |
| Timestamp | 2026-06-16T20:58:02.3673704Z  |
| Process | RDP / RemoteInteractive |

### ⚠️ Impact, Risk, and Relevance

The attacker obtained an initial foothold into the Windows environment by authenticating through Remote Desktop Protocol (RDP) using valid credentials. This allowed the attacker to establish an interactive session on the Windows system without exploiting a vulnerability, making the activity appear similar to legitimate administrative access.

The primary risk is that compromised credentials combined with RDP access provide an attacker with direct control of an internal endpoint. From this foothold, the attacker could perform reconnaissance, execute commands, move laterally across the network, escalate privileges, establish persistence, and access sensitive data.

This finding is significant because the intrusion relied on legitimate authentication mechanisms rather than malware or exploitation. Monitoring abnormal RDP authentication attempts, external RDP exposure, unusual source IP addresses, and privileged account usage is critical for detecting similar valid-account attacks.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where isnotempty( RemoteIP) 
| where LogonType contains "remote" or LogonType contains "interactive"
| project DeviceName, AccountName, TimeGenerated, LogonType, ActionType, Protocol
| order by TimeGenerated asc 
```

### 🖼️ Screenshot
<img width="1262" height="277" alt="image" src="https://github.com/user-attachments/assets/248d5efe-217c-40d8-bbb4-bf87a31007f2" />

**Answer:** 
`npt-ws01`, `148.64.103.173`

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: First Foothold, Ordering <Technique Name></strong> </summary>

### 🎯 Objective
`HUNT LEAD: "There's more than one foothold here, and the obvious story has the Linux box first. Don't take that on trust. Prove which one actually came first, and name it."` 

### 📌 Finding
During the investigation, the Linux workstation initially appeared to be the first foothold due to the amount of attacker activity observed on the system. Timeline analysis disproved this assumption. The Linux workstation's first successful logon occurred at `2026-06-16T22:01:38.373679Z`, while the Windows workstation had already been accessed at `2026-06-16T20:58:02.3673704Z` through authenticated RDP. This confirms that the Windows workstation was the attacker's true initial foothold. 

### 🔍 Evidence

| Field               | Value                        |
| ------------------- | ---------------------------- |
| Initial Foothold    | `npt-ws01`                    |
| Initial Access Time | 2026-06-16T20:58:02.3673704Z |
| Access Method       | RDP/RemoteInteractive        |
| Later Accessed Host | `npt-linux01`                  |
| Linux Access Time   | 2026-06-16T22:01:38.373679Z  |
| Access Method       | RDP/Network                  |


### 💡 Why it matters
Identifying the true initial foothold is critical for accurately reconstructing the attack timeline. Although the Linux workstation appeared suspicious due to the volume of attacker activity and post-compromise actions, timeline analysis confirmed that it was accessed after the Windows workstation.

The attacker first gained access to the Windows environment through authenticated RDP access at `2026-06-16T20:58:02.3673704Z`. The Linux workstation was accessed later at `2026-06-16T22:01:38.373679Z`, indicating it was not the initial entry point.

This finding demonstrates the importance of validating attack assumptions through authentication timelines rather than relying on the most visibly active system. Misidentifying the first compromised host could lead to incorrect containment actions, missed indicators of compromise, and an incomplete understanding of attacker movement throughout the environment.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ActionType == "LogonSuccess"
| where isnotempty( RemoteIP)
| project DeviceName, TimeGenerated, ActionType, LogonType, RemoteIP
| order by TimeGenerated asc 
```

### 🖼️ Screenshot
<img width="1162" height="325" alt="image" src="https://github.com/user-attachments/assets/db4c8bf8-dfdc-49a6-8ed7-e256b0f62709" />

**Answer:** 
`npt-ws01`, `148.64.103.173`

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Operator Workstation Name <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "They were sloppy. Something they connected with announced itself on every remote session into the estate. Name it."`
<What the attacker was trying to accomplish>

### 📌 Finding
Remote session telemetry consistently recorded the attacker's originating device name as `Loranse`. Every interactive remote session into the Windows estate exposed the same client device name, allowing the operator's system to be identified despite their use of legitimate credentials.

### 🔍 Evidence

| Field                          | Value                                               |
| ------------------------------ | --------------------------------------------------- |
| **Host**                       | `npt-ws01` (also observed on npt-srv01)               |
| **Timestamp**                  | `2026-06-16T20:58:02.3673704Z` (first observed)       |
| **Process**                    | Remote interactive session                          |
| **Parent Process**             | N/A (Remote Session Metadata)                       |
| **Command Line**               | N/A (Captured via `ProcessRemoteSessionDeviceName`) |
| **Remote Session Device Name** | **Loranse**                                         |


### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where IsProcessRemoteSession == true
| project DeviceName, TimeGenerated, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc 
```


### 🖼️ Screenshot
<img width="975" height="239" alt="image" src="https://github.com/user-attachments/assets/80ac474e-c7e4-42f8-835b-dad20ecb3760" />

**Answer:** `Loranse` 
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: SRV01 Access Vector <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "The server took its own way in, it wasn't reached from inside. Reconstruct it: the method, the source, the session type."`
 
<What the attacker was trying to accomplish>

### 📌 Finding
npt-srv01 was accessed with remote IP 148.64.103.173 with LogonType RemoteInteractive. Utilizing DeviceNetworkEvents we can see that the remote port used was port 3389 (RDP). 

### 🔍 Evidence

| Field              | Value                                                                |
| ------------------ | -------------------------------------------------------------------- |
| **Host**           | npt-srv01                                                            |
| **Timestamp**      | 2026-06-16T20:48:41.8686404Z *(first observed RDP network activity)* |
| **Process**        | Remote Desktop Session (LogonSuccess)                                |
| **Parent Process** | N/A (Interactive Logon Event)                                        |
| **Command Line**   | N/A (Authentication event captured through `DeviceLogonEvents`)      |


### 💡 Why it matters
This finding demonstrates that the attacker established a direct remote desktop session to npt-srv01 from an external IP address instead of laterally moving from another compromised internal system. Direct exposure of RDP services to the Internet significantly increases the risk of unauthorized access, particularly when attackers possess valid credentials. Correlating successful logon events with network telemetry confirms both the access method and source, providing high-confidence evidence of the initial server compromise and supporting accurate attack path reconstruction

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-srv01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ActionType == "LogonSuccess"
| where isnotempty( RemoteIP)
| project TimeGenerated, AccountName, DeviceName, RemoteIP, ActionType, LogonType
| order by TimeGenerated asc 
```

```kql
DeviceNetworkEvents
| where DeviceName has_any ("npt-srv01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where RemoteIP == "148.64.103.173"
| where isnotempty( RemoteIP)
| project TimeGenerated, DeviceName, RemoteIP, LocalPort, ActionType
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img width="975" height="291" alt="image" src="https://github.com/user-attachments/assets/8fb5926b-0bcd-4d34-83ee-22b3675b377d" />
<img width="975" height="193" alt="image" src="https://github.com/user-attachments/assets/339a0f5f-7df1-476e-b1ee-2c77e96daece" />



### 🛠️ Detection Recommendation

**Answer :** `RDP, 148.64.103.173, RemoteInteractive`  
<Actionable guidance for defenders>

</details>
---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Sudo Enumeration <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "First thing on the Linux box, they checked what they could escalate with. Give me the exact command. They fumbled it once before they got it right, that's how you'll spot the real one."`
 
<What the attacker was trying to accomplish>

### 📌 Finding
The attacker launched a Bash shell and executed the sudo -l command at 2026-06-16T22:16:52.687226Z to enumerate the current user's sudo permissions. Prior to the successful execution, they mistyped the command during an attempt at 2026-06-16T22:11:28.916766Z, providing a clear indicator of hands-on-keyboard activity rather than an automated process.

### 🔍 Evidence

| Field              | Value                       |
| ------------------ | --------------------------- |
| **Host**           | npt-linux01                 |
| **Timestamp**      | 2026-06-16T22:16:52.687226Z |
| **Process**        | bash                        |
| **Parent Process** | sshd                        |
| **Command Line**   | `sudo -l`                   |


### 💡 Why it matters
The `sudo -l` command is a common post-compromise reconnaissance technique used to determine which commands a user can execute with elevated privileges. By identifying misconfigured or passwordless sudo permissions, an attacker can quickly assess potential privilege escalation paths to root. The preceding failed attempt also indicates an interactive operator manually typing commands, helping distinguish human activity from automated malware or scripts. Detecting early privilege enumeration is valuable because it often precedes privilege escalation and broader compromise of Linux systems.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-linux01")
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ProcessCommandLine contains "sudo"
| project Timestamp, DeviceName, ProcessCommandLine
```
### 🖼️ Screenshot

<img width="975" height="480" alt="image" src="https://github.com/user-attachments/assets/53ac7634-81a4-4000-8294-3e47549fba61" />


### 🛠️ Detection Recommendation

**Answer :** `sudo -l` 

<Actionable guidance for defenders>
---
## Timeline
| Time (UTC)                   | Phase                  | Event                                                                                                                                                                                                                                                                             |
| ---------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **2026-06-16 20:57:21**      | Initial Access         | Attacker successfully authenticated to **npt-ws01** from external IP **148.64.103.173** via **RDP** using valid credentials. The remote client hostname was identified as **LORANSE**.                                                                                            |
| **2026-06-16 21:57:36**      | Initial Access         | A second successful **RDP** session was established to **npt-srv01** from the same external IP, confirming multiple externally accessible systems.                                                                                                                                |
| **2026-06-16 22:16:52**      | Linux Reconnaissance   | On **npt-linux01**, the attacker enumerated privileges using **`sudo -l`** to determine potential privilege escalation paths.                                                                                                                                                     |
| **2026-06-16 22:21**         | Internal Discovery     | The attacker verified Windows host reachability from Linux using **`/dev/tcp`** against **TCP/3389**, confirming RDP accessibility before pivoting.                                                                                                                               |
| **2026-06-16 22:31**         | Tooling                | The attacker installed **pipx** and **NetExec** to facilitate lateral movement and authenticated operations within the environment.                                                                                                                                               |
| **2026-06-16 22:32**         | Lateral Movement       | Using **NetExec** over **SMB (TCP/445)**, the attacker authenticated as **sancadmin** from **10.2.0.30** to **npt-ws01**, pivoting from Linux into the Windows environment.                                                                                                       |
| **2026-06-16 22:43**         | Privilege Verification | The attacker executed **`whoami.exe /groups`** to verify membership in privileged security groups before continuing operations.                                                                                                                                                   |
| **2026-06-16 23:04:16**      | Persistence            | Persistence was established by creating a **Windows Run Registry** key that launched **NorthpeakSyncTray.ps1** with hidden PowerShell execution whenever the user logged in.                                                                                                      |
| **2026-06-16 23:19:22**      | Command & Control      | The attacker deployed an encoded **PowerShell Invoke-WebRequest** beacon communicating with **cdn.sync-northpeak.com**. Beacon intervals showed a regular cadence consistent with an automated callback mechanism.                                                                |
| **2026-06-16 23:44:08**      | Data Exfiltration      | Sensitive file **customer_data_export_20260616.csv** was exfiltrated from **npt-srv01** to **cdn.sync-northpeak.com** during the attacker's second remote session using **Invoke-WebRequest**.                                                                                    |
| **Post-Incident Assessment** | Findings               | The investigation concluded the attacker relied on **valid credentials, built-in Windows utilities, and living-off-the-land techniques**, avoiding malware deployment or security-control tampering while maintaining persistent access and successfully stealing customer data.  |

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
