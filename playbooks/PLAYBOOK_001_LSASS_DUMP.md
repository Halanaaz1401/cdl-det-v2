# Incident Response Playbook 001: LSASS Memory Credential Dumping (PB-2026-001)

## Target Threat
- **Threat Type:** Credential Access / Memory Dumping
- **MITRE ATT&CK Technique:** T1003.001
- **Primary Alerts:** `sysmon_lsass_dump.yml`, `correlation_ps_lsass_dump.yml`

---

## Phase 1: Triage & Identification
1. **Verify Alert Authenticity:**
   - Confirm if the initiating process is a legitimate administrative tool (e.g., ProcDump, Process Explorer used by authorized admins).
   - Check if command line contains Mimikatz strings (`securlsa::`, `lsadump::`) or suspicious encoded flags.
2. **Determine Access Scope:**
   - Identify the user context executing the process (Local Admin vs Domain Admin).
   - Check Sysmon Event ID 10 for granted memory handle rights against `lsass.exe`.

---

## Phase 2: Containment
1. **Isolate Affected Host:**
   - Disconnect system from network (EDR isolation or physical link disablement) to prevent lateral movement.
2. **Terminate Malicious Process:**
   - Terminate the parent PowerShell or command interpreter process executing the extraction script.

---

## Phase 3: Eradication & Remediation
1. **Credential Invalidation:**
   - Immediately force password resets and revoke active Kerberos TGT tokens for all accounts logged into the host.
2. **System Hardening:**
   - Enforce LSA Protection (`RunAsPPL`) via Registry / GPO:
     `HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL = dword:00000001`
   - Enable Windows Defender Credential Guard if hardware virtualization supports it.

---

## Phase 4: Lessons Learned & Recovery
1. Confirm zero active sessions using stale credentials.
2. Re-admit system to production network following full AV/EDR scan.
3. Update Sigma detection rules if new bypass techniques were observed.