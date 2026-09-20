# DFIR Writeup #04: Credential Dumping via Impacket secretsdump.py

## Executive Summary

Following the lateral movement exercise documented in
[`03-smb-admin-shares-lateral-movement.md`](03-smb-admin-shares-lateral-movement.md),
this exercise simulates the next stage of a realistic attack chain: an
attacker who has already obtained valid Administrator credentials uses them
to remotely dump local credential material (SAM hashes and LSA secrets) from
the compromised host, using Impacket's `secretsdump.py`.

Unlike Writeup #03 — where a real detection gap was identified and closed
with a custom correlation rule — this exercise found the opposite result:
**standard Windows Security auditing, with no custom Sysmon rule required,
already produced a strong, correlatable signal** for this technique. The
finding here is not a gap to close, but a set of existing events (a network
logon, a privilege assignment, and a service state change) that are individually
unremarkable but form a clear pattern when correlated in a short time window.

> **Analyst note:** This is a useful counter-example to Writeup #03. Not every
> detection gap requires new Sysmon configuration or custom parsing — sometimes
> the raw ingredients for detection already exist in default Windows auditing,
> and the actual engineering work is building the *correlation logic* on top
> of them, not capturing new raw data.

---

## Scope & Objective

**Objective:** Simulate MITRE ATT&CK technique **T1003 (OS Credential
Dumping)** against Windows-Victim-01 using previously obtained Administrator
credentials, and assess whether existing Wazuh/Windows auditing provides
sufficient visibility to detect it without additional instrumentation.

**In scope:**
- Execution of `secretsdump.py` from the Kali attacker host against
  Windows-Victim-01 via the pfSense NAT path established in
  [`01-external-smb-exposure-purple-team-exercise.md`](01-external-smb-exposure-purple-team-exercise.md)
- Analysis of resulting Windows Security and System event logs as ingested
  by Wazuh
- Identification of a correlation opportunity for a future custom detection
  rule (design proposed in Recommendations; implementation deferred to a
  follow-up session)

**Out of scope:** Direct LSASS memory dumping (e.g. via `procdump` +
Mimikatz offline parsing) was deliberately not used for this exercise —
`secretsdump.py`'s remote registry/SAM-based approach was chosen instead, as
it better reflects how a real attacker would minimize on-disk forensic
artifacts and avoid triggering AV/EDR memory-access heuristics.

---

## Environment

See [`01-external-smb-exposure-purple-team-exercise.md`](01-external-smb-exposure-purple-team-exercise.md)
and [`03-smb-admin-shares-lateral-movement.md`](03-smb-admin-shares-lateral-movement.md)
for full network topology. Relevant hosts for this exercise:

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker (VirtualBox, laptop) | 192.168.1.105 (Bridged) |
| pfSense-Firewall | Perimeter FW / NAT | WAN: 192.168.1.152 |
| Windows-Victim-01 | Target | LAN: 10.10.10.100 |
| Wazuh-Manager | SIEM | 10.10.10.102 |

**Credentials used:** Local Administrator (RID-500) account on
Windows-Victim-01, enabled during Writeup #03, password `[REDACTED]`.

**Attack path:** Kali → pfSense WAN (192.168.1.152) → NAT → Windows-Victim-01
(10.10.10.100:445), identical to the path used for the Writeup #03 psexec
attack.

---

## Timeline

All times approximate, from Wazuh-ingested Windows Event Logs
(`agent.name: windows-victim-01`), September 18, 2026:

| Time | EventID | Source | Description |
|---|---|---|---|
| 18:40:27 | 4624 | Security | Logon, Type 3 (Network), Auth Package NTLM, `IpAddress: 192.168.1.105` (Kali), `TargetUserName: Administrator` |
| 18:40:27 | 4672 | Security | Special privileges assigned to new logon: `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege` |
| 18:40:27 | 7040 | System (Service Control Manager) | Remote Registry service start type changed: demand start → disabled |
| 18:40:40 | 7040 | System (Service Control Manager) | Remote Registry service start type changed: disabled → demand start |
| 18:40:40 | 4634 | Security | Logoff |

---

## Technical Findings

**Command executed (Kali):**

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py Administrator:'[REDACTED]'@192.168.1.152
```

**Attack sequence, as reported by `secretsdump.py`:**

1. Detected that the `RemoteRegistry` service was in a stopped/disabled
   state, and automatically enabled it (required to remotely read SAM/LSA
   registry hives)
2. Retrieved the target's boot key (`bootKey`)
3. Dumped local SAM hashes for all local accounts (uid:rid:lmhash:nthash):
   `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `victim`
   — all values `[REDACTED]` in this document
4. Dumped cached domain logon information (none present — standalone host)
5. Dumped LSA Secrets, including `DPAPI_SYSTEM` (machine key, user key) and
   `NL$KM` (cached logon key material)
6. Cleaned up: stopped `RemoteRegistry` and restored its original (disabled)
   start type

> **Analyst note:** Step 6 — the tool restoring the service to its original
> state after use — is itself a forensically significant artifact. A single
> service-state change might be routine administration; a service being
> toggled on and back off again within ~13 seconds is a much more specific
> and unusual pattern, and is the strongest single indicator in this dataset.

**Result:** Full SAM and LSA secret extraction succeeded. No AV/EDR
interference was observed (consistent with the Windows Defender exclusion on
`C:\Windows` documented in Writeup #03, still in effect for this exercise).

---

## Detection Analysis

Unlike Writeup #03, no Sysmon-level gap was found here. The combination of
three standard Windows Security/System events, all within a 13-second
window and on the same agent, is sufficient to build high-confidence
detection logic:

1. **EventID 4624** — a network logon (Type 3) using NTLM authentication for
   the built-in Administrator account is not inherently malicious (this
   account is used for legitimate lab administration), but combined with...
2. **EventID 4672** — ...the simultaneous assignment of `SeDebugPrivilege`,
   `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeTakeOwnershipPrivilege`
   — the exact privilege set required to read protected registry hives and
   process memory — narrows this significantly to credential-access-style
   tooling rather than routine interactive administration.
3. **EventID 7040** (×2) — the Remote Registry service being toggled through
   a full disable→enable→disable (or enable→disable→enable) cycle in the
   same short window is the pattern most specific to SAM/LSA remote dumping
   tools (Impacket's `secretsdump.py`, and similar tools) that need the
   service temporarily available and prefer to leave the host's
   configuration looking untouched afterward.

No single event above should trigger a high-severity alert on its own —
each has legitimate, everyday explanations in isolation. The detection value
is entirely in the **correlation** of all three within a short timeframe on
the same host.

*(Specific Wazuh `rule.id` values for the underlying 4672 and 7040 base
rules were not yet recorded during this session and are noted as a
follow-up item before the correlation rule below can be implemented.)*

---

## Root Cause & Lessons Learned

- **Standard Windows auditing can be sufficient.** Writeup #03 required a
  Sysmon-level correlation to close a real gap; this exercise shows that not
  every credential-access technique needs new instrumentation — sometimes
  the raw signal already exists in default Security/System event categories,
  and the missing piece is purely analytical (correlation logic), not
  collection.
- **Service state changes are an under-used detection surface.** RemoteRegistry
  toggling is a narrow, specific, and rarely-legitimate-in-isolation signal
  that is easy to miss if log review focuses only on logon events.
- **Tool "cleanup" behavior is itself a forensic artifact.** Attackers (and
  their tooling) that try to leave a system looking unchanged often
  introduce a *second* anomalous event (the revert) that a single-event
  detection strategy would miss entirely.

---

## Recommendations

**Proposed correlation rule (design; implementation deferred to next
session):**

- **Base rule:** EventID 4672 for `TargetUserName: Administrator` (or any
  privileged account) combined with Type 3 (network) logon context from the
  associated 4624
- **Correlated rule:** `if_matched_sid` referencing the base rule, matched
  against EventID 7040 for the `RemoteRegistry` service, within a
  `timeframe` of 60–120 seconds, same agent (same-agent scoping is default
  behavior for `if_matched_sid` and does not require an explicit
  `<same_field>agent.id</same_field>` element — see the Bug #2 lesson from
  the Writeup #03 Update section on rule 100011, which applies identically
  here)
- **Level:** 12 (matching the severity used for rule 100011)
- **MITRE mapping:** T1003 (OS Credential Dumping), T1003.002 (Security
  Account Manager), T1078 (Valid Accounts)

**Additional recommendation:** Consider adding Sysmon Registry Event
monitoring (Event ID 12/13/14) for `HKLM\SAM` and `HKLM\SECURITY` hive
access as a second, independent detection layer — this would catch
LSASS-memory-based dumping tools that don't rely on the RemoteRegistry
service at all, closing a gap that this specific correlation rule would
not cover.

---

## Appendix

**Full `secretsdump.py` output** (credential material redacted):

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: [REDACTED]
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:[REDACTED]:[REDACTED]:::
Guest:501:[REDACTED]:[REDACTED]:::
DefaultAccount:503:[REDACTED]:[REDACTED]:::
WDAGUtilityAccount:504:[REDACTED]:[REDACTED]:::
victim:1001:[REDACTED]:[REDACTED]:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
dpapi_machinekey:[REDACTED]
dpapi_userkey:[REDACTED]
[*] NL$KM
NL$KM:[REDACTED]
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
