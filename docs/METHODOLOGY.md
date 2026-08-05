# Project Methodology & Analysis Approach (CDL-DET-V2)

## Overview
This document outlines the engineering approach, tooling, and validation framework used throughout the Cyberion Defense Labs Detection Engineering & Threat Hunting Engagement.

---

## 1. Datasets & Telemetry Sources
The detection logic and threat hunts in this project are built upon real-world attack telemetry:
- **Mordor Project Dataset (`empire_mimikatz_logonpasswords_2020-08-07103224.json`):** Pre-recorded JSON security events capturing adversary emulation involving PowerShell Empire and Mimikatz credential dumping.
- **Sysmon EVTX Logs (`exec_sysmon_1_ftp.evtx`):** Captured Windows Sysmon event logs covering command execution (`cmd.exe`) and network transfers via command-line FTP.

---

## 2. Detection Rule Engineering Workflow
All detection rules are developed using the generic **Sigma format** to ensure portability across SIEM platforms:
1. **Target Behavior Identification:** Identify specific adversary techniques mapped to the MITRE ATT&CK framework.
2. **Log Analysis & Telemetry Correlation:** Inspect target datasets using Python (`pandas` / Jupyter Notebooks) to find specific telemetry markers (e.g., Event IDs, process images, command-line arguments).
3. **Rule Authoring:** Draft generic detection logic in YAML using standard Sigma specification schema.
4. **Validation & Quality Control:** Validate syntax and ATT&CK tag compliance using `sigma-cli` (`sigma check`).
5. **False Positive Tuning:** Document operational noise considerations and refine selection criteria to minimize alert fatigue.

---

## 3. Tooling & Environment
- **Environment:** VS Code with Python 3.14 & Jupyter Notebook extension.
- **Data Analysis:** Python 3 (`pandas`, `json`).
- **Rule Syntax Engine:** `sigma-cli` / `pySigma`.
- **Version Control:** Git & GitHub (`Halanaaz1401/cdl-det-v2`).