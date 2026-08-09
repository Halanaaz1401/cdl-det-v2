# Incident Case Report 001: LSASS Credential Dumping & Execution (INC-2026-001)

## Executive Summary
- **Incident ID:** INC-2026-001
- **Severity:** High
- **Status:** Closed / Resolved
- **Incident Lead:** Cyberion Defense Labs
- **Date Identified:** 2026-08-09
- **Closure Date:** 2026-08-09
- **Closure Classification:** True Positive (Confirmed Compromise)
- **Affected Systems:** Host environment in Mordor Emulation Baseline
- **Impacted Assets:** Local Security Authority Subsystem Service (`lsass.exe`)

---

## 1. Initial Discovery & Detection
The incident was identified during Threat Hunt #002 following process creation alerts matching rule `correlation_ps_lsass_dump.yml`. Analysis of the Mordor security event telemetry confirmed an attacker leveraging an interactive PowerShell session to dump credentials from memory using Mimikatz (`securlsa::logonpasswords`).

---

## 2. Reconstructed Attack Timeline

| Timestamp (UTC) | Event Type | Image Path / Artifact | Command Line / Action | Relevance / Notes |
| :--- | :--- | :--- | :--- | :--- |
| `2020-08-07 10:32:24` | Process Creation (Sysmon Event ID 1) | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Encoded script execution or interactive C2 agent initialization | Initial adversary execution context via Empire agent. |
| `2020-08-07 10:32:25` | Process Creation / Command Invocation | `powershell.exe` | Invocation containing `securlsa::logonpasswords` | Attacker invoked Mimikatz credential extraction command targeting LSASS. |
| `2020-08-07 10:32:25` | Process Access (Sysmon Event ID 10) | `lsass.exe` Access Target | GrantedAccess handle request (`0x1010` / `0x1F0FFF`) | Process requested memory handle to extract domain / local logon hashes. |

---

## 3. MITRE ATT&CK Mapping & Root Cause Analysis
- **Primary Technique:** T1003.001 - OS Credential Dumping: LSASS Memory
- **Secondary Techniques:** T1059.001 - Command & Scripting Interpreter: PowerShell
- **Root Cause:** Execution of unverified interactive PowerShell sessions running with elevated administrative privileges without LSA Protection (`RunAsPPL`) or credential guard enforcement.

---

## 4. Impact Assessment
- **Confidentiality:** High (Potential compromise of active session logon hashes and plaintext passwords in memory).
- **Integrity:** Medium (Potential unauthorized privilege escalation across domain assets).
- **Availability:** Low (No disruption to system operations).

---

## 5. Evidence Artifacts & Indicators of Compromise (IoCs)
- **Host Artifacts:** Execution of `powershell.exe` with command line arguments querying LSASS memory handles.
- **Process Target:** `C:\Windows\System32\lsass.exe`
- **Associated Sigma Rules Triggered:**
  - `a2b3c4d5-...` (`sysmon_lsass_dump.yml`)
  - `c0d1e2f3-...` (`correlation_ps_lsass_dump.yml`)

---

## 6. Containment, Eradication & Closure
- **Remediation Actions:**
  1. Enforce LSA Protection (`RunAsPPL`) via Group Policy to prevent unprivileged handle reads against `lsass.exe`.
  2. Implement PowerShell Constrained Language Mode (CLM) for standard user contexts.
  3. Rotate all privileged account passwords logged on the system during the compromise timeframe.
- **Closure Classification:** **True Positive** — Verified malicious activity properly detected and remediated via existing detection logic.