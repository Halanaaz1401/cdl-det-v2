# Indicators of Compromise (IOC) Research Notes

## Overview
This document consolidates indicators of compromise (IOCs) extracted during Threat Hunting (#001 & #002) and Incident Investigations (INC-2026-001 & INC-2026-002) across target datasets.

---

## 1. Process & Command Line Artifacts

| IOC Type | Indicator / Pattern | Context / Associated Threat | Source Dataset | Threat Level |
| :--- | :--- | :--- | :--- | :--- |
| **Command Line** | `securlsa::logonpasswords` | Mimikatz LSASS memory credential extraction | Mordor JSON | High |
| **Command Line** | `-e` / `-enc` (Encoded PS) | PowerShell Empire C2 agent initialization | Mordor JSON | High |
| **Command Line** | `ftp -s:script.txt` | Scripted command-line file exfiltration | Sysmon EVTX | High |
| **Process Path** | `C:\Windows\System32\ftp.exe` | Interactive CLI file exfiltration | Sysmon EVTX | Medium |
| **Target Image** | `C:\Windows\System32\lsass.exe` | Process memory access target for handle dumping | Mordor JSON | Critical |
| **Process Name** | `psexesvc.exe` | Remote service installation for lateral movement | Sysmon EVTX | High |

---

## 2. Network & System Artifacts

| IOC Type | Indicator / Value | Description | Defense / Action |
| :--- | :--- | :--- | :--- |
| **Handle Access** | `0x1010` / `0x1F0FFF` | Process handle request granted for reading LSASS memory | Alert on non-SYSTEM process handle requests |
| **Protocol** | Outbound FTP (Port 21) | Direct network connection established via script parameters | Enforce outbound egress filtering at firewall |
| **Registry Path** | `HKLM\...\CurrentVersion\Run` | Registry persistence key modification | Restrict user write access to startup keys |

---

## 3. Threat Intelligence & ATT&CK References
- **MITRE ATT&CK T1003.001:** [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- **MITRE ATT&CK T1041:** [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- **MITRE ATT&CK T1021.002:** [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)