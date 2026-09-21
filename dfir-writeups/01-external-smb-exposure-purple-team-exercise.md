# Purple Team Exercise #1: Simulated External SMB Exposure & Detection

---

## 1. Executive Summary

This exercise simulated an external attacker discovering and accessing an exposed
SMB (file sharing) service on a Windows 11 host sitting behind a segmented,
firewalled network. The goal was twofold: (1) validate that a purposely exposed
service could be discovered and accessed the way a real external attacker would,
and (2) confirm that the defensive stack (Sysmon + Wazuh SIEM) correctly logged
and flagged the activity for a SOC analyst to review.

**Result:** The service was successfully discovered, authenticated against, and
enumerated. The SIEM detected the authentication event in real time and
automatically raised an alert consistent with a possible credential-based lateral
movement technique (NTLM network logon), demonstrating that the detection layer
functions as intended even in a fully self-built, non-commercial lab.

---

## 2. Scope & Objective

| Item | Detail |
|---|---|
| Attacker system | Kali Linux (VirtualBox, physical laptop, bridged to home LAN) |
| Target system | Windows 11 Pro, standalone workgroup member (VMware, physical desktop) |
| Perimeter | pfSense CE 2.8.1 (WAN bridged to home network, LAN on isolated `10.10.10.0/24`) |
| Exposed service | SMB / TCP 445, NAT port-forwarded from pfSense WAN to target |
| Monitoring | Sysmon (SwiftOnSecurity config) + Wazuh 4.14 agent, forwarding to Wazuh Manager |
| Objective | Simulate external discovery + authenticated access to a file-sharing service, and validate detection coverage |

**Network Topology**

```
Kali (Attacker)                 Home Router                pfSense (Firewall)              Windows 11 (Target)
192.168.1.234        ⇄        192.168.1.0/24        ⇄     WAN 192.168.1.152                10.10.10.100
(laptop, WiFi bridged)                                     LAN 10.10.10.1/24    ⇄           (Sysmon + Wazuh agent)
                                                             NAT: WAN:445 → 10.10.10.100:445
```

---

## 3. Timeline

| Time (UTC+2) | Event | Source |
|---|---|---|
| T+0 | Port scan against pfSense WAN address, port 445 | Kali / nmap |
| T+0 | Initial scan reports `filtered` — no ping response received before scan | Kali / nmap |
| T+1 | Root cause identified: nmap's default host-discovery (ICMP ping) is not permitted to the target through NAT; rescanned with `-Pn` | Kali / nmap |
| T+2 | Port confirmed `open` — `445/tcp open microsoft-ds` | Kali / nmap |
| T+3 | `smbclient -L` attempted with valid local credentials | Kali |
| T+3 | Authentication succeeded; shares enumerated: `ADMIN$`, `C$`, `IPC$` | Kali |
| T+3 | **Wazuh Manager logged Event ID 4624** (successful logon), Logon Type 3 (Network), source IP `192.168.1.234`, workstation name `KALI` | Wazuh Dashboard |
| T+3 | Wazuh rule engine auto-generated an alert: *"Successful Remote Logon Detected... NTLM authentication, possible pass-the-hash attack"* | Wazuh Dashboard |

---

## 4. Technical Findings

### 4.1 Reconnaissance
```bash
nmap -sV -p 445 -Pn 192.168.1.152
```
```
PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds
```

### 4.2 SMB Share Enumeration (authenticated)
```bash
smbclient -L //192.168.1.152 -U victim
```
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

> **Analyst note:** Exposure of `C$` and `ADMIN$` to an authenticated network
> user is significant — these administrative shares grant full remote access
> to the system drive and Windows directory. In a real engagement, valid
> credentials plus this share access is a direct path to remote code execution
> via tools such as Impacket's `psexec.py` or PsExec.

### 4.3 Wazuh Detection — Event ID 4624

Wazuh logged **5 separate Event ID 4624 entries** across the exercise. Two are
detailed below, representing the two distinct phases of the SMB interaction:
the initial anonymous negotiation, and the subsequent authenticated session.

**Phase 1 — Anonymous session negotiation** (precedes authentication; part of
the normal SMB handshake before credentials are supplied)

| Field | Value |
|---|---|
| `agent.name` | windows-victim-01 |
| `data.win.eventdata.ipAddress` | 192.168.1.234 |
| `data.win.eventdata.workstationName` | KALI |
| `data.win.eventdata.targetUserName` | ANONYMOUS LOGON |
| `data.win.eventdata.logonType` | 3 (Network) |
| `data.win.eventdata.authenticationPackageName` | NTLM |
| `data.win.eventdata.lmPackageName` | NTLM V1 |
| `rule.description` | Successful Remote Logon Detected - NTLM authentication, possible pass-the-hash attack |

**Phase 2 — Authenticated session** (after `smbclient -U victim` supplied valid credentials)

| Field | Value |
|---|---|
| `agent.name` | windows-victim-01 |
| `data.win.eventdata.ipAddress` | 192.168.1.234 |
| `data.win.eventdata.ipPort` | 32812 |
| `data.win.eventdata.workstationName` | KALI |
| `data.win.eventdata.targetUserName` | victim |
| `data.win.eventdata.targetUserSid` | S-1-5-21-3757128122-3842374592-1145511230-1001 |
| `data.win.eventdata.logonType` | 3 (Network) |
| `data.win.eventdata.authenticationPackageName` | NTLM |
| `data.win.eventdata.lmPackageName` | **NTLM V2** |
| `data.win.eventdata.logonProcessName` | NtLmSsp |
| `rule.description` | Successful Remote Logon Detected - User:\victim - NTLM authentication, possible pass-the-hash attack |

> **Analyst note:** The two phases used different NTLM sub-versions — the
> anonymous negotiation fell back to the weaker **NTLMv1**, while the
> credentialed session correctly negotiated **NTLMv2**. This is expected
> protocol behavior, but it's a useful detail to check in real investigations:
> a fully authenticated session that only manages to negotiate NTLMv1 is a
> stronger anomaly signal than one that negotiates NTLMv2, since NTLMv1
> is far more susceptible to relay and offline cracking attacks.

---

## 5. Detection Analysis — Analyst Interpretation

Wazuh's built-in rule set flagged this authentication as a **possible
pass-the-hash / lateral movement indicator**. Taken in isolation, that
classification is reasonable: Logon Type 3 + NTLM (rather than Kerberos) is a
common signature of both legitimate SMB file access *and* credential-based
attacks, because standalone/workgroup machines fall back to NTLM by default.

**Why this was assessed as benign in this exercise:**
- The source (Kali, `192.168.1.234`) is a known, authorized test system on the
  same physical network segment.
- The credentials used were the target's own locally configured account —
  no credential theft occurred.
- The activity occurred within a controlled, time-boxed test window.

**Why an analyst should not dismiss this pattern automatically in production:**
- NTLMv1 (seen here as `lmPackageName: NTLM V1`) is a legacy, cryptographically
  weak protocol vulnerable to relay and cracking attacks. Its presence on a
  production host — regardless of who is connecting — is itself a finding
  worth remediating.
- An identical log signature (Logon Type 3, NTLM, unfamiliar source IP) in a
  real environment, without a known/scheduled test, would warrant immediate
  escalation.

This distinction — *same telemetry, different conclusion based on context* —
is the core judgment call a SOC analyst makes dozens of times per shift.

---

## 6. Root Cause: Why the Port Was Reachable

*(Condensed troubleshooting summary — full detail available on request)*

1. LAN was re-addressed from `192.168.1.0/24` to `10.10.10.0/24` to resolve a
   subnet collision with the home network (both had originally used the same
   RFC1918 range, which would have broken routing).
2. pfSense WAN was switched from VMware NAT to a bridged adapter, giving it a
   real address on the home network so the attacker laptop could reach it.
3. A destination NAT (port forward) rule was added: WAN:445 → 10.10.10.100:445.
4. Initial access attempts failed silently. Packet capture on the pfSense LAN
   interface confirmed SYN packets reaching the target with **no response**,
   isolating the fault to the target host rather than the network path.
5. Root cause: Windows Defender Firewall's **SMB-In rule scope** was restricted
   to `LocalSubnet` under the *Private* network profile. Because NAT preserves
   the original source IP, the target saw the connection as originating from
   `192.168.1.234` — outside its own `10.10.10.0/24` subnet — and silently
   dropped it despite the rule being "enabled."
6. Resolution: widened the SMB-In rule's remote address scope to `Any`.

**Takeaway:** a correctly forwarded, "open" port at the network layer can still
be invisible at the host layer due to host-based firewall scoping — a reminder
that network and host security must be validated independently, not assumed
from one another.

---

## 7. Recommendations (as if reporting to a client)

1. Disable NTLMv1 and enforce NTLMv2/Kerberos where possible.
2. Restrict or disable `C$`/`ADMIN$` administrative share access for non-admin
   accounts; monitor access to these shares explicitly.
3. Do not expose SMB (445) directly to untrusted networks; if remote file
   access is required, use a VPN.
4. Tune the Wazuh pass-the-hash rule to reduce noise from expected internal
   NTLM traffic while preserving sensitivity to external sources.

---

## 8. Appendix — Environment Notes

- Wazuh 4.14.7, single-node (Indexer + Manager + Dashboard)
- Sysmon config: SwiftOnSecurity baseline
- pfSense CE 2.8.1

*(Additional raw event exports and network diagram to be attached.)*
