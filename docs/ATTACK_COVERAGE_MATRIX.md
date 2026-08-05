# MITRE ATT&CK Coverage Matrix (CDL-DET-V2)

## Overview
This matrix tracks the detection coverage across assessed MITRE ATT&CK techniques, mapping each technique to specific Sigma rule IDs and coverage statuses.

---

## Technique Coverage Summary Table

| Tactic | Technique ID | Technique Name | Status | Mapped Rule / Detection ID | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | T1110 | Brute Force | Covered | `f1a2b3c4-...` (`sysmon_ftp_brute_force.yml`) | Detects CLI FTP brute force / failed login activity. |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS Memory | Covered | `a2b3c4d5-...` (`sysmon_lsass_dump.yml`) | Detects Mimikatz memory read / LSASS dump commands. |
| **Execution** | T1059.001 | Command & Scripting Interpreter: PowerShell | Covered | `b3c4d5e6-...` (`sysmon_powershell_encoded.yml`) | Detects encoded PowerShell flags (`-e`, `-enc`). |
| **Execution** | T1059.003 | Command & Scripting Interpreter: Windows Command Shell | Covered | `c4d5e6f7-...` (`sysmon_cmd_execution.yml`) | Detects suspicious `cmd.exe` child processes. |
| **Lateral Movement** | T1021.002 | Remote Services: SMB/Windows Admin Shares | Covered | `d5e6f7a8-...` (`sysmon_psexec_lateral.yml`) | Detects PsExec execution over SMB shares. |
| **Persistence** | T1543.003 | Create/Modify System Process: Windows Service | Covered | `e6f7a8b9-...` (`sysmon_service_creation.yml`) | Detects service installation via `sc.exe`. |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Covered | `f7a8b9c0-...` (`sysmon_ftp_exfil.yml`) | Detects outbound FTP transfer scripts (`-s:`). |
| **Defense Evasion** | T1078 | Valid Accounts | Partially Covered | `a8b9c0d1-...` (`sysmon_valid_accounts.yml`) | Detects local admin account usage; needs domain logon telemetry for full coverage. |
| **Discovery** | T1033 | System Owner/User Discovery | Covered | `b9c0d1e2-...` (`sysmon_whoami_recon.yml`) | Detects post-compromise `whoami` execution. |
| **Correlation** | T1003.001 / T1059.001 | PowerShell Spawning LSASS Dump | Covered | `c0d1e2f3-...` (`correlation_ps_lsass_dump.yml`) | Correlation rule linking parent PS process with child LSASS access. |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Not Covered | N/A | No web application / exploit telemetry available in present datasets. |
| **Command and Control**| T1071.001 | Web Protocols (HTTP/HTTPS Beaconing) | Not Covered | N/A | Requires Zeek / Proxy log coverage (planned for future hunt). |

---

## Coverage Statistics
- **Total Techniques Assessed:** 12
- **Covered:** 9 (75%)
- **Partially Covered:** 1 (8.3%)
- **Not Covered:** 2 (16.7%)