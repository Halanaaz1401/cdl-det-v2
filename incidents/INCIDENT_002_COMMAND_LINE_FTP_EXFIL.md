# Incident Case Report 002: Command-Line FTP Staging & Exfiltration (INC-2026-002)

## Executive Summary
- **Incident ID:** INC-2026-002
- **Severity:** Medium
- **Status:** Closed / Resolved
- **Incident Lead:** Cyberion Defense Labs
- **Date Identified:** 2026-08-10
- **Closure Date:** 2026-08-10
- **Closure Classification:** True Positive (Confirmed Compromise)
- **Affected Systems:** Internal host running Windows Sysmon logging (`exec_sysmon_1_ftp.evtx`)
- **Impacted Assets:** Local File System and Egress Network Traffic

---

## 1. Initial Discovery & Detection
The incident was identified via rule `sysmon_ftp_exfil.yml` and `sysmon_cmd_execution.yml` following anomalous execution of `cmd.exe` launching `ftp.exe` with command-line script parameters (`-s:`) targeting non-standard remote IP infrastructure.

---

## 2. Reconstructed Attack Timeline

| Timestamp (UTC) | Event Type | Image Path / Artifact | Command Line / Action | Relevance / Notes |
| :--- | :--- | :--- | :--- | :--- |
| `2026-08-01 14:10:00` | Process Creation (Sysmon Event ID 1) | `C:\Windows\System32\cmd.exe` | `cmd.exe /c ftp -s:script.txt` | Adversary initiated scripted command-line FTP execution. |
| `2026-08-01 14:10:02` | File Artifact / Script Creation | `C:\Users\Public\script.txt` | Open connection, send credentials, PUT file | Staged exfiltration instructions. |
| `2026-08-01 14:10:05` | Network Connection (Sysmon Event ID 3) | `C:\Windows\System32\ftp.exe` | Outbound socket connection on Port 21 | Direct network communication established with external server. |

---

## 3. MITRE ATT&CK Mapping & Root Cause Analysis
- **Primary Technique:** T1041 - Exfiltration Over C2 Channel / T1020 - Automated Exfiltration
- **Secondary Techniques:** T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- **Root Cause:** Unrestricted outbound egress traffic allowed standard command-line tools (`ftp.exe`) to establish raw socket connections to unverified external IP addresses.

---

## 4. Impact Assessment
- **Confidentiality:** High (Potential exfiltration of staged internal files).
- **Integrity:** Low (No system files or operating system configurations modified).
- **Availability:** Low (Operational capabilities remained intact).

---

## 5. Containment, Eradication & Closure
- **Remediation Actions:**
  1. Blocked destination IP at perimeter firewall.
  2. Restricted `ftp.exe` execution policies for non-administrative user profiles via AppLocker / Software Restriction Policies (SRP).
  3. Inspected staging directory (`C:\Users\Public\`) and purged exfiltration scripts.
- **Closure Classification:** **True Positive** — Malicious command-line exfiltration identified and remediated.