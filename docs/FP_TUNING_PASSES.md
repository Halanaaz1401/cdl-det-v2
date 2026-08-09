# False-Positive Tuning Passes & Noise Reduction Documentation

## Overview
This document logs the tuning cycles applied across the Sigma detection rules in `rules/` to minimize alert fatigue, eliminate false positives, and refine selection criteria.

---

## Pass 1: Local Network Exclusion for Network Rules (`sysmon_net_ftp_exfil.yml`)
- **Issue Identified:** Baseline telemetry generated benign alerts when `ftp.exe` connected to internal staging servers (`10.x.x.x` / `192.168.x.x`).
- **Tuning Action:** Added `filter_local` block excluding RFC1918 private IP ranges from triggering exfiltration alerts.
- **Impact:** Reduced internal administrative alert noise by 100% while retaining egress external tracking.

---

## Pass 2: Parent Process Exclusion for Admin Scripts (`sysmon_recon_whoami.yml`)
- **Issue Identified:** Administrative logon scripts calling `whoami.exe` raised low-level alerts during routine user logons.
- **Tuning Action:** Documented parent process exceptions (`C:\Windows\System32\UserInit.exe`) and updated rule metadata false-positive guidelines.
- **Impact:** Contextualized discovery alerts to prioritize interactive command prompt shells over startup automation.

---

## Pass 3: External IP Filtering for PowerShell Network Sockets (`sysmon_net_powershell_conn.yml`)
- **Issue Identified:** PowerShell scripts performing internal API requests generated redundant alerts.
- **Tuning Action:** Introduced `filter_internal` block filtering internal subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Impact:** Isolated alerting exclusively to external outbound connections indicative of potential C2 or reverse shell activity.