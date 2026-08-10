# MITRE ATT&CK Coverage Matrix

## Overview
This document tracks detection coverage provided by the 15 Sigma rules authored in `rules/` mapped directly to the MITRE ATT&CK Enterprise Framework.

---

## Detection Coverage Mapping

| Tactic | Technique ID | Technique Name | Status | Rule ID Mapping | Rule File Name |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS | Covered | `a2b3c4d5-6789-01ab-cdef-222222222222` | `sysmon_lsass_dump.yml` |
| **Credential Access** | T1003.001 | Multi-Event LSASS Access Correlation | Covered | `c0d1e2f3-4567-89ab-cdef-101010101010` | `correlation_ps_lsass_dump.yml` |
| **Credential Access** | T1110 | Brute Force | Covered | `a4b5c6d7-8901-23ab-cdef-444444444444` | `sysmon_ftp_brute_force.yml` |
| **Defense Evasion** | T1027 | Encoded PowerShell Command | Covered | `a1b2c3d4-5678-90ab-cdef-111111111111` | `sysmon_powershell_encoded.yml` |
| **Defense Evasion** | T1078 | Valid Accounts Abuse | Covered | `a8b9c0d1-2345-67ab-cdef-888888888888` | `sysmon_valid_accounts.yml` |
| **Execution** | T1059.001 | PowerShell Execution | Covered | `a7b8c9d0-1234-56ab-cdef-777777777777` | `sysmon_cmd_execution.yml` |
| **Execution** | T1059.001 | Outbound PowerShell Network Socket | Covered | `f5a6b7c8-9012-34ab-cdef-555555555555` | `sysmon_net_powershell_conn.yml` |
| **Lateral Movement**| T1021.002 | SMB/Windows Admin Shares (PsExec) | Covered | `a3b4c5d6-7890-12ab-cdef-333333333333` | `sysmon_psexec_lateral.yml` |
| **Persistence** | T1543.003 | Windows Service Creation | Covered | `a5b6c7d8-9012-34ab-cdef-555555555555` | `sysmon_service_creation.yml` |
| **Persistence** | T1543.003 | Service Manager SC.exe Creation | Covered | `f3a4b5c6-7890-12ab-cdef-333333333333` | `sysmon_persistence_service.yml` |
| **Persistence** | T1547.001 | Registry Run Keys Modification | Covered | `f4a5b6c7-8901-23ab-cdef-444444444444` | `sysmon_reg_run_persistence.yml` |
| **Discovery** | T1033 | System Owner/User Discovery | Covered | `a6b7c8d9-0123-45ab-cdef-666666666666` | `sysmon_whoami_recon.yml` |
| **Discovery** | T1033 | System Discovery via Whoami | Covered | `f2a3b4c5-6789-01ab-cdef-222222222222` | `sysmon_recon_whoami.yml` |
| **Exfiltration** | T1041 | Exfiltration Over C2 / FTP Script | Covered | `a9b0c1d2-3456-78ab-cdef-999999999999` | `sysmon_ftp_exfil.yml` |
| **Exfiltration** | T1041 | Outbound Network Connection via FTP| Covered | `f1a2b3c4-5678-90ab-cdef-111111111111` | `sysmon_net_ftp_exfil.yml` |
| **Command & Control**| T1071.001 | C2 Web Protocols (Beaconing) | Not Covered | N/A | Hunted in `HUNT_001_C2_BEACONING.md` |

---

## Summary Metrics
- **Total MITRE ATT&CK Techniques Mapped:** 11 Techniques across 7 Tactics.
- **Total Rules Traced:** 15 Active Sigma Rules.
- **Coverage Percentage:** 100% of authored rules traced to Rule IDs and validated against test telemetry.