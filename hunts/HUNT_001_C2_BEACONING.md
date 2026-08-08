# Threat Hunt 001: C2 Web Protocol Beaconing (T1071.001)

## Hunt Metadata
- **Hunt ID:** HUNT-001
- **Target Technique:** T1071.001 - Application Layer Protocol: Web Protocols
- **Status:** Completed
- **Author:** Cyberion Defense Labs
- **Date Initiated:** 2026-08-07
- **Date Completed:** 2026-08-08

---

## 1. Hypothesis Statement
Adversaries are utilizing HTTP/HTTPS web protocols to establish C2 communication channels, bypassing perimeter defenses by blending in with legitimate outbound web traffic.

---

## 2. Telemetry & Data Requirements
- **Required Datasets:** Web Proxy Logs, DNS Logs, Network Flow Telemetry, and Process Creation Events (Sysmon Event ID 1).
- **Target Data Fields:** `c-ip`, `cs-host`, `cs-uri-stem`, `sc-status`, `user_agent`, `ProcessName`, `CommandLine`.

---

## 3. Analytic Approach & Execution
1. **User-Agent Anomaly Filtering:** Analyzed process execution and network connection events to locate non-standard or hardcoded C2 User-Agents.
2. **Frequency & Jitter Inspection:** Examined connection timestamps for regular periodic time deltas indicative of automated beaconing scripts.
3. **Process Execution Analysis:** Cross-referenced outbound network connection initiations against binary parents (`powershell.exe`, `cmd.exe`, `ftp.exe`).

---

## 4. Hunt Findings & Analysis Output
- **Dataset Evaluated:** `exec_sysmon_1_ftp.evtx` and Mordor JSON datasets (`empire_mimikatz_logonpasswords_2020-08-07103224.json`).
- **Observed Network Activity:** Telemetry confirmed interactive command-line FTP activity (`ftp.exe`), but **no direct HTTP/HTTPS C2 beaconing sessions or custom User-Agents** were identified within the target dataset scope.
- **Outcome:** **Inconclusive / Negative Finding.** No HTTP web C2 beaconing activity detected in the available dataset baseline.

---

## 5. Security Recommendations & Defensive Action
- **Telemetry Enhancement:** Deploy dedicated Web Proxy / Zeek Network Security Monitoring logs to capture full HTTP request headers (`User-Agent`, `URI`) for future hunting cycles.
- **Rule Development:** Retain process-level rules (such as `sysmon_ftp_exfil.yml`) while drafting proxy-level detection logic when web proxy logs are ingested.