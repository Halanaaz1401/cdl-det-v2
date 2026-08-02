# Data Dictionary — CDL-DET-V2

**Project:** Cyberion Defense Labs — Detection Engineering & Threat Hunting Engagement
**Author:** Hala Naaz
**Last Updated:** August 2, 2026
**Status:** Living document — updated as new log sources are added

## 1. Purpose

This document catalogs the log/telemetry sources used in this engagement, the fields available in each,
and what each field means from a detection standpoint. It exists so that any analyst picking up this
repo later — including future me — can understand a rule's logic without needing to ask what a field means.

Sources documented (per Section 4.1 of the PRD, minimum of three):

1. Windows Security Event Log
2. Sysmon (System Monitor) Event Log
3. [Third source — add once selected, e.g. Zeek network logs or authentication logs]

## 2. Windows Security Event Log

Native Windows auditing. Populated when the relevant Audit Policy subcategories are enabled.
Channel: `Security`. Provider: `Microsoft-Windows-Security-Auditing`.

| Event ID | Name | What It Means (Detection Standpoint) | Key Fields |
|---|---|---|---|
| 4624 | An account was successfully logged on | Confirms successful authentication. Logon Type field tells you *how* (interactive, network, RDP, service, etc.) — critical for distinguishing normal logons from lateral movement. | `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `WorkstationName`, `AuthenticationPackageName` |
| 4625 | An account failed to log on | Core signal for brute-force / password-spray detection. `Status`/`SubStatus` codes distinguish bad password vs. disabled account vs. expired password. | `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`, `FailureReason` |
| 4634 / 4647 | An account was logged off / user initiated logoff | Used to bound a session's duration when reconstructing a timeline. | `TargetUserName`, `LogonType` |
| 4648 | A logon was attempted using explicit credentials | Strong signal — indicates a process used credentials different from the logged-on user's (e.g. `runas`, pass-the-hash tooling). High detection value for lateral movement / credential misuse. | `SubjectUserName`, `TargetUserName`, `TargetServerName`, `ProcessName` |
| 4672 | Special privileges assigned to new logon | Fires when a logon is granted admin-equivalent privileges (e.g. `SeDebugPrivilege`). Useful for flagging privileged logons worth extra scrutiny. | `SubjectUserName`, `PrivilegeList` |
| 4688 | A new process has been created | Process creation audit (native Windows equivalent of Sysmon Event ID 1, if enabled). Foundational for detecting suspicious command lines / LOLBins. | `NewProcessName`, `CommandLine` (if enabled), `ParentProcessName`, `SubjectUserName` |
| 4697 | A service was installed in the system | Service creation is a common persistence technique. | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType` |
| 4698 | A scheduled task was created | Common persistence / execution technique (T1053.005). | `TaskName`, `TaskContent` (contains the command/action), `SubjectUserName` |
| 4720 | A user account was created | Account creation — relevant to persistence and privilege escalation investigations. | `TargetUserName`, `SubjectUserName`, `SamAccountName` |
| 4732 / 4728 | A member was added to a security-enabled local/global group | Privilege escalation signal — especially additions to Administrators or Domain Admins. | `TargetUserName` (group), `MemberName`, `SubjectUserName` |
| 4776 | The domain controller attempted to validate credentials (NTLM) | Useful for spotting NTLM auth in environments that should be using Kerberos, and for brute-force detection at the DC. | `TargetUserName`, `Workstation`, `Status` |

### Logon Type reference (used across 4624/4625/4634)

| Value | Meaning |
|---|---|
| 2 | Interactive (console logon) |
| 3 | Network (e.g. accessing a share) |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials (e.g. `runas /netonly`) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

## 3. Sysmon Event Log

Requires Sysmon to be installed and configured with a logging config (e.g. SwiftOnSecurity's or Olaf Hartong's
configs are common starting points). Channel: `Microsoft-Windows-Sysmon/Operational`. Provides far richer
process, network, and file telemetry than native Windows auditing.

| Event ID | Name | What It Means (Detection Standpoint) | Key Fields |
|---|---|---|---|
| 1 | Process creation | The single highest-value Sysmon event. Full command line, parent/child relationship, and hashes for every process launched. Core to detecting LOLBins, suspicious parent-child chains (e.g. `winword.exe` spawning `powershell.exe`), and encoded commands. | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `IntegrityLevel` |
| 2 | A process changed a file creation time | Timestomping — anti-forensic technique. | `TargetFilename`, `PreviousCreationUtcTime`, `NewCreationUtcTime` |
| 3 | Network connection | Process-level network connections. Key for detecting C2 beaconing, unusual outbound ports/destinations. | `Image`, `DestinationIp`, `DestinationPort`, `SourceIp`, `Protocol` |
| 5 | Process terminated | Bounds a process's lifetime; useful in timeline reconstruction. | `Image`, `ProcessGuid` |
| 6 | Driver loaded | Kernel driver loads — relevant for rootkit/EDR-evasion detection. | `ImageLoaded`, `Signed`, `Hashes` |
| 7 | Image loaded (DLL load) | DLL sideloading / injection detection. Very high volume — usually filtered to unsigned or non-standard-path loads only. | `Image`, `ImageLoaded`, `Signed`, `Hashes` |
| 8 | CreateRemoteThread | Classic process injection indicator. | `SourceImage`, `TargetImage`, `StartAddress` |
| 10 | ProcessAccess | One process opening a handle to another — relevant to credential dumping (e.g. access to `lsass.exe`). | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` |
| 11 | FileCreate | File writes — useful for detecting dropped payloads, staged exfil archives, ransomware note drops. | `Image`, `TargetFilename` |
| 12/13/14 | Registry event (object create/delete, value set, object rename) | Registry-based persistence (Run keys, services) and defense-evasion detection. | `Image`, `TargetObject`, `Details` |
| 15 | FileCreateStreamHash | Alternate Data Stream creation — often tied to files downloaded from the internet (Mark-of-the-Web) or staging. | `TargetFilename`, `Hash` |
| 22 | DNS query | Process-level DNS resolution — pairs with Event ID 3 for C2 domain detection. | `Image`, `QueryName`, `QueryResults` |
| 23 | FileDelete | Anti-forensic cleanup / ransomware behavior. | `Image`, `TargetFilename` |

## 4. Common Field Glossary

Fields that appear across multiple sources above and are worth defining once:

- **Image / ProcessName** — full path to the executable that performed the action.
- **CommandLine** — the full command-line arguments a process was launched with. Frequently the single most
  useful field for detection (encoded PowerShell, suspicious flags, LOLBin abuse).
- **ParentImage / ParentProcessName** — the process that launched the process in question. Parent-child
  mismatches (e.g. `outlook.exe` → `cmd.exe`) are a common detection pattern.
- **Hashes** — file hashes (SHA1/MD5/IMPHASH depending on Sysmon config) — used for IOC matching.
- **User / SubjectUserName / TargetUserName** — the account context. "Subject" is who performed the action,
  "Target" is who/what it was performed on/as.
- **IntegrityLevel** — Windows process integrity level (Low/Medium/High/System) — useful for detecting
  privilege escalation.

## 5. Dataset Mapping Notes

Notes on where these fields actually appear in the datasets used for this engagement (Section 9 of the PRD).
Fill in as datasets are explored:

- **EVTX-ATTACK-SAMPLES:** [Note which subfolders map to which technique/event types once reviewed]
- **Mordor / Security-Datasets:** [Note which datasets were selected and why]
- **[Third source, if used]:** [Notes]

## 6. Change Log

| Date | Change |
|---|---|
| August 2, 2026 | Initial version — Windows Security + Sysmon sections drafted (Day 1) |