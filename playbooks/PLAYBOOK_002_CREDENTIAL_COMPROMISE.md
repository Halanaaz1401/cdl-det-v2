# Incident Response Playbook 002: Credential Compromise & Abuse (PB-2026-002)

## Target Threat
- **Threat Type:** Credential Access & Valid Accounts Abuse
- **MITRE ATT&CK Technique:** T1078 (Valid Accounts) / T1110 (Brute Force)
- **Primary Alerts:** `sysmon_valid_accounts.yml`, `sysmon_ftp_brute_force.yml`

---

## Phase 1: Triage & Identification
1. **Source & Account Verification:**
   - Identify affected account context (Domain vs Local Administrator).
   - Check authentication sources for anomalous geolocation or timing spikes.
2. **Impact Assessment:**
   - Review recent logon events across the network to identify concurrent sessions initiated by the compromised user ID.

---

## Phase 2: Containment
1. **Account Suspension:**
   - Disable or temporarily lock out compromised user accounts in Active Directory / Azure AD.
2. **Session Revocation:**
   - Terminate active Kerberos / OAuth tokens and interactive RDP/WinRM sessions.

---

## Phase 3: Eradication & Remediation
1. **Password & Credential Reset:**
   - Perform force password resets across primary and secondary linked accounts.
2. **Multi-Factor Authentication (MFA):**
   - Require immediate MFA re-enrollment and revoke remembered device tokens.

---

## Phase 4: Lessons Learned
1. Audit account privilege levels and implement Just-In-Time (JIT) access controls.
2. Update detection logic to flag concurrent logons from geographically impossible locations.