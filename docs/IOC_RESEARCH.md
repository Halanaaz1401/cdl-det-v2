# Indicators of Compromise (IOC) Research Notes

## Overview
This document consolidates indicators of compromise (IOCs) extracted during Threat Hunting (#001 & #002) and Incident Investigation (INC-2026-001) across target datasets.

---

## 1. Process & Command Line Artifacts

| IOC Type | Indicator / Pattern | Context / Associated Threat | Source Dataset | Threat Level |
| :--- | :--- | :--- | :--- | :--- |
| **Command Line** | `securlsa::logonpasswords` | Mimikatz LSASS memory credential extraction | Mordor JSON | High |
| **Command Line** | `-e` / `-enc` (Encoded PS) | PowerShell Empire C2 agent initialization | Mordor JSON | High |
| **Process Path** | `C:\Windows\System32\ftp.exe` | Interactive CLI file exfiltration via script (`-s:`) | Sysmon EVTX | Medium |
| **Target Image** | `C:\Windows\System32\lsass.exe` | Process memory access target for handle dumping | Mordor JSON | Critical |

---

## 2. Network & System Artifacts

| IOC Type | Indicator / Value | Description | Defense / Action |
| :--- | :--- | :--- | :--- |
| **Handle Access** | `0x1010` / `0x1F0FFF` | Process handle request granted for reading LSASS memory | Alert on non-SYSTEM process handle requests |
| **Protocol** | Outbound FTP (Port 21) | Direct network connection established via script parameters | Enforce outbound egress filtering at firewall |

---

## 3. Enrichment & Threat Intelligence References
- **MITRE ATT&CK T1003.001:** [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- **MITRE ATT&CK T1041:** [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)