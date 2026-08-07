# Threat Hunt 001: C2 Web Protocol Beaconing (T1071.001)

## Hunt Metadata
- **Hunt ID:** HUNT-001
- **Target Technique:** T1071.001 - Application Layer Protocol: Web Protocols
- **Status:** In Progress
- **Author:** Cyberion Defense Labs
- **Date Initiated:** 2026-08-07

---

## 1. Hypothesis Statement
Adversaries are utilizing HTTP/HTTPS web protocols to establish C2 communication channels, bypassing perimeter defenses by blending in with legitimate outbound web traffic.

---

## 2. Telemetry & Data Requirements
- **Required Datasets:** Web Proxy Logs, DNS Logs, Network Flow Telemetry, and Process Creation Events (Sysmon Event ID 1).
- **Target Data Fields:** `c-ip`, `cs-host`, `cs-uri-stem`, `sc-status`, `user_agent`, `ProcessName`, `CommandLine`.

---

## 3. Analytic Approach & Hunting Plan
1. **Outbound User-Agent Anomaly Detection:** Filter HTTP requests for missing, uncommon, or hardcoded malicious User-Agent strings (e.g., Empire, Cobalt Strike defaults).
2. **Beaconing Frequency Analysis:** Group outbound web requests by destination IP/host and calculate time intervals (delta between connections) to detect jitter/regular periodic communication.
3. **Process-to-Network Correlation:** Cross-examine processes initiating outbound HTTP requests (e.g., `powershell.exe`, `cmd.exe`, or un-signed binaries making direct network sockets).

---

## 4. Preliminary Findings & Next Steps
- Hypothesis formulated and hunt scope defined.
- Next step: Execute log queries against telemetry to identify anomalous network activity patterns and document evidence.