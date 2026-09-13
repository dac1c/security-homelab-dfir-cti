# DFIR Writeup #03: Lateral Movement via SMB Admin Shares to SYSTEM-Level Code Execution (Purple Team Exercise)

## Executive Summary

Writeup #01 identified that authenticated SMB access to a Windows host's `ADMIN$`/`C$` administrative shares represents a potential remote code execution vector, but stopped short of exploiting it. This exercise closes that gap: using Impacket's `impacket-psexec`, a simulated attacker leveraged local administrator credentials on `Windows-Victim-01` to drop a service binary via the `ADMIN$` share, register it as a Windows service, and obtain an interactive command shell running with **SYSTEM**-level privileges — the highest privilege tier available on Windows, exceeding even the Administrator account used to authenticate.

**Result:** The attack succeeded end-to-end. Wazuh's built-in ruleset detected the service installation with a high-severity, MITRE-mapped alert configured to notify an analyst by email. However, the actual moment of SYSTEM-level command execution triggered only a low-severity, non-mailed rule — a meaningful gap in alert prioritization that is discussed in detail below.

---

## Scope & Objective

**Objective:** Simulate lateral movement / remote code execution against a Windows host using previously-established SMB access, and validate what the SIEM detects at each stage of the technique — service installation, process execution, and the resulting privilege level.

**In scope:**
- `Windows-Victim-01` (target)
- `pfSense-Firewall` (perimeter firewall/NAT, reusing the SMB port-forward rule from Writeup #01)
- Kali Linux (attacker box, running Impacket)
- Wazuh Manager (SIEM/detection)

**Out of scope:** Persistence, further pivoting to `Linux-Victim-01`, data exfiltration, and any actions taken after the initial interactive shell was obtained. The privilege escalation step performed here (enabling a disabled built-in account) was researcher-controlled lab setup rather than an exploited vulnerability — this distinction is discussed in the Technical Findings.

---

## Environment / Network Topology

| Host             | Role               | Network             | IP                                    |
|------------------|--------------------|---------------------|---------------------------------------|
| Kali Linux       | Attacker           | External (home LAN) | 192.168.1.234                         |
| pfSense-Firewall | Perimeter FW / NAT | WAN / LAN           | WAN: 192.168.1.152 · LAN: 10.10.10.1 |
| Windows-Victim-01| Target             | Internal LAN        | 10.10.10.100                          |
| Wazuh-Manager    | SIEM               | Internal LAN        | 10.10.10.102                          |

Network path and NAT configuration (WAN:445 → Windows-Victim-01:445) are unchanged from Writeup #01.

---

## Timeline

| Time (local)          | Event                                                                                                                          |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------|
| T+0                   | `nmap -sV -p 445 -Pn 192.168.1.152` confirms `445/tcp open` — reused NAT path from Writeup #01                                |
| T+1                   | First `impacket-psexec` attempt using `victim` credentials succeeds authentication but reports `ADMIN$`/`C$` as not writable  |
| T+2                   | `net localgroup Administrators` on Windows-Victim-01 reveals a disabled built-in `Administrator` account alongside `victim`   |
| T+3                   | `Administrator` account enabled and assigned a password (`net user Administrator /active:yes`, then password set)             |
| 15:11:59–15:12:04     | Second `impacket-psexec` attempt using `Administrator` credentials — `ADMIN$` writable, binary `XsHOJQPc.exe` uploaded, service `cAzZ` created and started |
| 15:12:04.392          | **Wazuh rule 92650 fires** — new Windows service installed from Windows root path (level 12, mail: true)                      |
| 15:12:05.175          | Interactive shell returned; **Wazuh rule 92052 fires** — abnormal process spawned `cmd.exe` (level 4, mail: false)            |
| —                     | `whoami` confirms shell is running as `nt authority\system`                                                                   |
| —                     | Session closed via `exit`; Impacket removes the dropped service and binary from the target                                     |

---

## Technical Findings

### Initial Attempt — UAC Remote Token Filtering

```
impacket-psexec 'victim:[REDACTED]@192.168.1.152'
```
```
[*] Requesting shares on 192.168.1.152.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
```

> **Analyst note:** The `victim` account is a member of the local Administrators group, yet write access to `ADMIN$`/`C$` was still denied. This is the expected behaviour of **Windows UAC remote token filtering**: when any local account (other than the built-in RID-500 `Administrator`) connects over the network, Windows strips the elevated Administrators token from the session, leaving only a standard user context. The result is that `victim` can *enumerate* shares — as demonstrated in Writeup #01 via `smbclient -L` — but cannot *write* to them remotely, because write access to `ADMIN$` (which maps directly to `%SystemRoot%`) requires an unfiltered administrative token. The built-in `Administrator` account (RID-500) is explicitly exempt from this filtering, which is why the second attempt below succeeded with that account. This behaviour can be modified via the `LocalAccountTokenFilterPolicy` registry key, which is itself a common misconfiguration finding in penetration tests.

### Privilege Discovery — Built-in Administrator Account

```
net localgroup Administrators
```
```
Administrator
victim
The command completed successfully.
```

```
net user Administrator
```
```
Account active               No
```

The built-in `Administrator` account was present in the local Administrators group but disabled — the Windows 11 default. It was enabled and assigned a known password for this exercise:

```
net user Administrator /active:yes
net user Administrator [REDACTED]
```

> **Analyst note:** This step is lab setup, not an exploited vulnerability — enabling the account required an already-elevated local session on the target. In a real-world engagement, an attacker would need to reach this same state through credential theft, a separate privilege escalation exploit, discovery of an already-enabled admin account with a weak or default password, or abuse of `LocalAccountTokenFilterPolicy` on a misconfigured host. This writeup documents the execution technique that becomes available *once* that access exists, not a method for obtaining it.

### Successful Exploitation

```
impacket-psexec 'Administrator:[REDACTED]@192.168.1.152'
```
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 192.168.1.152.....
[*] Found writable share ADMIN$
[*] Uploading file XsHOJQPc.exe
[*] Opening SVCManager on 192.168.1.152.....
[*] Creating service cAzZ on 192.168.1.152.....
[*] Starting service cAzZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.26200.9168]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32> whoami
nt authority\system
```

> **Analyst note:** The session authenticated as `Administrator` but the resulting shell runs as `SYSTEM` — a strictly higher privilege tier. This happens because Windows services execute under whatever account the service definition specifies, and Impacket's default service configuration runs as `LocalSystem`. An attacker needs only *local admin rights* to install such a service, not the SYSTEM account itself, yet ends up with a SYSTEM-level interactive shell as the outcome. The implication is that any local administrator account credential — however it was obtained — represents a direct path to full SYSTEM access on that host via this technique.

### Wazuh Detection — Service Installation (Windows Event ID 7045)

| Field                              | Value                                                                                                                              |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `rule.id`                          | 92650                                                                                                                              |
| `rule.level`                       | 12                                                                                                                                 |
| `rule.description`                 | New Windows Service Created to start from windows root path. Suspicious event as the binary may have been dropped using Windows Admin Shares. |
| `rule.mitre.id`                    | T1021.002, T1569.002                                                                                                               |
| `rule.mitre.tactic`                | Lateral Movement, Execution                                                                                                        |
| `rule.mitre.technique`             | SMB/Windows Admin Shares, Service Execution                                                                                        |
| `rule.mail`                        | true                                                                                                                               |
| `data.win.eventdata.serviceName`   | cAzZ                                                                                                                               |
| `data.win.eventdata.imagePath`     | `%systemroot%\XsHOJQPc.exe`                                                                                                        |
| `data.win.eventdata.accountName`   | LocalSystem                                                                                                                        |
| `data.win.eventdata.startType`     | demand start                                                                                                                       |
| `data.win.system.eventSourceName`  | Service Control Manager                                                                                                            |
| `timestamp`                        | 2026-09-13 @ 15:12:04.392                                                                                                          |

> **Analyst note:** This built-in rule is notably more specific than the generic NTLM logon alert seen in Writeup #01 — its description explicitly names "Windows Admin Shares" as the likely delivery mechanism, which is exactly what occurred here. The randomised service name (`cAzZ`) and binary name (`XsHOJQPc.exe`) are characteristic Impacket-generated artefacts; a detection tuned to flag services whose `imagePath` resolves directly to `%systemroot%` (rather than a subdirectory like `System32`) is a reliable heuristic, since legitimate Windows services almost never install binaries directly into the Windows root.

### Wazuh Detection — Process Execution (Sysmon Event ID 1)

| Field                                   | Value                                                   |
|-----------------------------------------|---------------------------------------------------------|
| `rule.id`                               | 92052                                                   |
| `rule.level`                            | 4                                                       |
| `rule.description`                      | Windows command prompt started by an abnormal process   |
| `rule.mitre.id`                         | T1059.003                                               |
| `rule.mitre.tactic`                     | Execution                                               |
| `rule.mitre.technique`                  | Windows Command Shell                                   |
| `rule.mail`                             | false                                                   |
| `data.win.eventdata.image`              | `C:\Windows\SysWOW64\cmd.exe`                           |
| `data.win.eventdata.parentImage`        | `C:\Windows\XsHOJQPc.exe`                               |
| `data.win.eventdata.user`              | NT AUTHORITY\SYSTEM                                     |
| `data.win.eventdata.parentUser`         | NT AUTHORITY\SYSTEM                                     |
| `data.win.eventdata.integrityLevel`     | System                                                  |
| `data.win.eventdata.currentDirectory`   | `C:\Windows\system32\`                                  |
| `timestamp`                             | 2026-09-13 @ 15:12:05.175                               |

### Detection Gap — Missing Process Creation Event for the Dropped Binary

A Sysmon Event ID 1 record for `XsHOJQPc.exe` itself — the process that would sit between the Service Control Manager and `cmd.exe` in the full execution chain — could not be located in the log, despite targeted searches by filename wildcard and by the exact `processGuid` referenced in the `cmd.exe` parent metadata (`{3f9566c4-af30-6aa6-4302-000000001100}`). Sysmon captured the *result* of that process running (its child `cmd.exe`, with correct parent metadata inherited) but not its own creation event.

The full expected chain was:
```
services.exe → XsHOJQPc.exe → cmd.exe (nt authority\system)
```

Only the final link (`cmd.exe`) was present in the Sysmon log. The cause was not confirmed in this exercise; plausible explanations include the binary's extremely short lifetime before Impacket's automatic cleanup removed it from disk, or a gap in Sysmon configuration coverage for processes spawned directly from `%SystemRoot%`. This is flagged as an open item for follow-up investigation rather than a diagnosed root cause.

---

## Detection Analysis — Analyst Interpretation

The two rules that fired tell a two-stage story with an important prioritization gap.

Rule 92650 (service installation, level 12, `mail: true`) fires at the moment the malicious service is registered — before a single command is executed. This is a well-placed, actionable alert: it gives an analyst an opportunity to respond before the attacker has fully established their foothold. In a live SOC, this event would generate an immediate email notification.

Rule 92052 (abnormal `cmd.exe` parent, level 4, `mail: false`) fires one second later, at the moment the attacker actually receives their interactive SYSTEM shell — which is arguably the more consequential event. Yet it carries a severity more than three times lower, and would not trigger any notification. An analyst relying solely on mailed alerts would learn about the service installation but not be automatically informed that a SYSTEM-level command shell was opened as a direct consequence.

The two rules firing within one second of each other from the same agent is itself a high-confidence composite indicator that no single default rule currently correlates. A custom Wazuh rule correlating rule 92650 followed by rule 92052 within a short time window on the same agent would surface this as a unified, higher-severity alert — this is flagged in the recommendations below.

This mirrors the analytical judgment discussed in Writeup #01: default rule severities reflect general risk patterns, but an analyst reviewing this specific two-event sequence in context would reasonably treat it as a single, high-severity incident rather than one high and one low finding.

---

## Root Cause / Lessons Learned

1. **UAC remote token filtering is a frequently misunderstood boundary.** Being in the local Administrators group does not grant remote administrative access by default — the built-in RID-500 `Administrator` account is the only local account exempt from token filtering on network connections. This is the precise mechanism that separated `victim` (blocked) from `Administrator` (successful) in this exercise, despite both being Administrators group members.

2. **A disabled built-in Administrator account is a latent escalation path.** It requires only one command to enable and is present on every Windows installation. If enabled with any discoverable or weak password, it immediately provides the UAC-exempt administrative token that makes this class of attack possible.

3. **Service-based remote execution elevates to SYSTEM regardless of the authenticating account's own privilege level.** Administrator-level access is sufficient input to produce a SYSTEM-level output via this technique — which is a meaningfully higher outcome than the input credential alone would suggest.

4. **Sysmon Event ID 1 coverage should not be assumed complete for short-lived, self-cleaning tooling.** This exercise surfaced a real gap: the binary that bridged service execution and shell delivery was not captured as a process creation event, despite its child process being logged. Defensive coverage for this class of technique should be validated against actual tool behaviour, not assumed from telemetry design alone.

---

## Recommendations

1. Keep the built-in `Administrator` account disabled in production. If it must be enabled for a specific task, rotate its password immediately before enabling it and re-disable it as soon as the task is complete.
2. Restrict remote write access to `ADMIN$`/`C$` via Group Policy or host firewall rules to only the specific management hosts and accounts that require it, rather than leaving these shares accessible to any authenticated local administrator over the network.
3. Evaluate setting `LocalAccountTokenFilterPolicy` = 0 (the default) and verify it is not set to 1 on any host, as that setting disables UAC remote filtering and would have allowed the initial `victim` attempt to succeed without requiring the built-in Administrator account at all.
4. Author a custom Wazuh correlation rule to detect rule 92650 followed by rule 92052 within a short time window on the same agent, and assign it level 12 or above with `mail: true` — the combination is a reliable composite indicator for this exact attack chain.
5. Investigate Sysmon configuration to determine why the dropped binary's own process creation event was not captured, and consider whether additional telemetry sources (e.g., Windows Security audit process creation, Event ID 4688) would provide redundant coverage for this gap.
6. Apply the NTLMv1 deprecation and SMB exposure hardening recommended in Writeup #01 — this exercise reused the same exposed service and reinforces that those recommendations remain unaddressed.

---

## Appendix

- Attack tool: Impacket `impacket-psexec` (Impacket v0.14.0.dev0, Fortra)
- Detection platform: Wazuh 4.14.7 (Manager + Indexer + Dashboard, all-in-one)
- Relevant Wazuh rule IDs: `92650`, `92052` (both built-in, default ruleset — no custom rule authored for this exercise)
- MITRE ATT&CK techniques observed: T1021.002 (Remote Services: SMB/Windows Admin Shares), T1569.002 (System Services: Service Execution), T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
- Related writeups: [Writeup #01 — External SMB Exposure](../dfir-writeups/01-external-smb-exposure-purple-team-exercise.md), [Writeup #02 — SSH Brute-Force](../dfir-writeups/02-ssh-bruteforce-linux-victim.md)
