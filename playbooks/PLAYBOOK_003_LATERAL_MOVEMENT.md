# Incident Response Playbook 003: Lateral Movement via PsExec & Remote Services (PB-2026-003)

## Target Threat
- **Threat Type:** Lateral Movement
- **MITRE ATT&CK Technique:** T1021.002 (SMB/Windows Admin Shares) / T1570 (Lateral Tool Transfer)
- **Primary Alerts:** `sysmon_psexec_lateral.yml`, `sysmon_service_creation.yml`

---

## Phase 1: Triage & Identification
1. **Service & Process Analysis:**
   - Identify service creation events involving `psexesvc.exe` or temporary admin shares (`ADMIN$`, `C$`).
   - Correlate originating IP address with target destination hosts.

---

## Phase 2: Containment
1. **Network Isolation:**
   - Isolate both source host (origin of lateral movement) and destination host from the network.
2. **Service Termination:**
   - Stop and delete remotely registered suspicious Windows services (`sc stop` / `sc delete`).

---

## Phase 3: Eradication & Remediation
1. **Disable Unnecessary Admin Shares:**
   - Ensure local administrative shares are restricted where business requirements allow.
2. **Credential Hardening:**
   - Rotate local administrator passwords using LAPS (Local Administrator Password Solution) to eliminate password reuse across hosts.

---

## Phase 4: Lessons Learned
1. Enforce strict internal firewall rules blocking SMB (Port 445) between workstation subnets.
2. Verify PsExec detection coverage across all endpoint monitoring endpoints.