# Project Methodology & Analysis Approach (CDL-DET-V2)

## Overview
This document outlines the complete engineering approach, tooling, threat hunting, and incident response framework applied throughout the Cyberion Defense Labs Engagement.

---

## 1. Datasets & Telemetry Sources
- **Mordor Project Dataset (`empire_mimikatz_logonpasswords_2020-08-07103224.json`):** Pre-recorded JSON security events capturing adversary emulation involving PowerShell Empire and Mimikatz credential dumping.
- **Sysmon EVTX Logs (`exec_sysmon_1_ftp.evtx`):** Captured Windows Sysmon event logs covering command execution (`cmd.exe`) and network transfers via command-line FTP.

---

## 2. Detection Engineering & Rule Lifecycle
All detection rules are authored in standard **Sigma format**:
1. **Technique Identification:** Mapped against MITRE ATT&CK Enterprise Matrix.
2. **Log Correlation:** Dataset parsing using Python (`pandas`, `json`, Jupyter Notebooks) to isolate event identifiers and process attributes.
3. **Rule Authoring & Validation:** Drafted in YAML and validated via `sigma-cli` (`sigma check`) to guarantee zero schema and identifier collisions.
4. **False Positive Tuning:** Applied 3 iterative tuning cycles to minimize operational noise.

---

## 3. Threat Hunting & Incident Response Framework
- **Proactive Hunting:** Formulated hypotheses based on non-covered techniques, queried telemetry baselines, and documented positive/negative findings.
- **Incident Investigation:** Reconstructed timeline evidence, identified root causes, determined confidentiality/integrity impact, and classified incident outcomes.
- **Operational Playbooks:** Authored structured Incident Response Playbooks detailing Triage, Containment, Eradication, and Lessons Learned phases.

---

## 4. Final Engagement Status
- **Sigma Rules:** 15 Authored & Validated Rules.
- **Threat Hunts:** 2 Completed Hunts (`HUNT_001` & `HUNT_002`).
- **Incident Reports:** 2 Case Reports Finalized (`INCIDENT_001` & `INCIDENT_002`).
- **Playbooks & IOCs:** 3 Response Playbooks and Consolidated IOC Research documentation completed.