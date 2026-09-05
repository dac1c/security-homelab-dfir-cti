# DFIR Writeup #02: SSH Brute-Force Attack Against Linux Target (Purple Team Exercise)

## Executive Summary

A simulated external attacker used the `hydra` password-cracking tool to perform a
brute-force attack against an internet-exposed SSH service on a Linux host
(`Linux-Victim-01`). The attack originated from a Kali Linux attack box on the
external ("home") network and reached the target through a firewall/NAT device
acting as the network perimeter. After 8 failed authentication attempts using a
custom password list, the attacker successfully authenticated as the local user
`victim`.

The Wazuh SIEM, monitoring the target via its Linux agent and the system's
`journald`/`sshd` logs, detected both stages of the attack using **built-in
(default) detection rules** — no custom rule development was required for this
exercise, unlike Writeup #01. The attack was classified under MITRE ATT&CK
technique **T1110 (Brute Force)**, escalating to **T1078 (Valid Accounts)** once
authentication succeeded.

This exercise also surfaced a network configuration gap (missing NAT rule) during
setup, which is documented below as it materially affected the attack path and
is a useful troubleshooting reference.

## Scope & Objective

**Objective:** Simulate an external SSH brute-force attack against a Linux host
and validate that the SIEM correctly detects both the failed-attempt pattern and
the resulting successful compromise, using out-of-the-box detection content.

**In scope:**
- `Linux-Victim-01` (Ubuntu Server, target)
- `pfSense-Firewall` (perimeter firewall/NAT)
- Kali Linux (attacker box, external network segment)
- Wazuh Manager (SIEM/detection)

**Out of scope:** Post-exploitation activity after the successful login (privilege
escalation, persistence, lateral movement) — this exercise focuses on initial
access via credential brute-forcing and its detection.

## Environment / Network Topology

| Host | Role | Network | IP |
|---|---|---|---|
| Kali Linux | Attacker | External (home LAN) | 192.168.1.234 |
| pfSense-Firewall | Perimeter FW / NAT | WAN / LAN | WAN: 192.168.1.152 · LAN: 10.10.10.1 |
| Linux-Victim-01 | Target | Internal LAN | 10.10.10.105 |
| Wazuh-Manager | SIEM | Internal LAN | 10.10.10.102 |

The attacker does not have direct routing to the internal `10.10.10.0/24` segment;
all traffic must traverse the pfSense WAN interface and be forwarded via NAT to
reach the target, mirroring a realistic scenario where only the firewall's public
IP is reachable from outside.

## Timeline

| Time (local) | Event |
|---|---|
| T+0 | Port scan against firewall WAN IP confirms `22/tcp open` |
| T+~1 min | `hydra` brute-force launched against `192.168.1.152:22`, targeting user `victim` with a custom 15-entry password list |
| T+~4 sec | 8 failed authentication attempts recorded by `sshd` in rapid succession |
| T+~5 sec | Wazuh rule `5763` fires — "brute force trying to get access" (built-in aggregation rule) |
| T+~5 sec | 9th attempt succeeds — password matched |
| T+~5 sec | Wazuh rule `40112` fires — "Multiple authentication failures followed by a success" |

## Technical Findings

### Attack execution

```
hydra -l victim -P ~/password.txt ssh://192.168.1.152 -s 22 -V
```

- `-l victim` — fixed username (single-account attack, no user enumeration performed)
- `-P ~/password.txt` — 15-entry custom password list, seeded with the target account's real password
- `-s 22` — explicit port, required because the target is reached through a NAT-forwarded port on the firewall, not a default local connection

Result:

```
[22][ssh] host: 192.168.1.152   login: victim   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
```

The attack tool required only ~5 seconds to exhaust the password list and identify
the valid credential, illustrating how quickly an unthrottled SSH service can be
compromised even with a small candidate list — real-world attacks would typically
use lists of millions of entries.

### Raw log evidence (target-side)

```
Sep 05 15:46:50 linux-victim-01 sshd-session[43071]: Failed password for victim from 192.168.1.234 port 58834 ssh2
Sep 05 15:46:50 linux-victim-01 sshd-session[43090]: Failed password for victim from 192.168.1.234 port 58918 ssh2
...
Sep 05 15:46:48 linux-victim-01 sshd-session[43085]: Accepted password for victim from 192.168.1.234 port 58886 ssh2
```

Eight distinct `sshd-session` PIDs recorded failed attempts within roughly one
second of each other, each from a different ephemeral source port — consistent
with hydra's default of multiple parallel connection attempts (Hydra's own output
noted 15 parallel tasks were configured, capped to the server's concurrent
connection limit).

## Detection Analysis

Two Wazuh **built-in** rules fired, forming a clear two-stage detection story.

### Stage 1 — Brute-force pattern detected

| Field | Value |
|---|---|
| `rule.id` | 5763 |
| `rule.level` | 10 |
| `rule.description` | sshd: brute force trying to get access to the system. Authentication failed. |
| `rule.frequency` | 8 |
| `rule.mitre.id` | T1110 |
| `rule.mitre.tactic` | Credential Access |
| `rule.mitre.technique` | Brute Force |
| `data.srcip` | 192.168.1.234 |
| `data.dstuser` | victim |

This is a **correlation/aggregation rule**, not a single-event alert: it does not
fire on the first failed login, but only after Wazuh observes a threshold number
of `sshd: authentication failed` events from the same source within a short time
window. This design choice matters operationally — a single failed login is
common and low-signal (a user simply mistyping a password), while a burst of
failures in a few seconds is a high-confidence indicator of automated password
guessing. Building detections on frequency/time-window patterns rather than
individual events is a standard technique for keeping false-positive rates low
in production SOC environments.

### Stage 2 — Escalation: failures followed by success

| Field | Value |
|---|---|
| `rule.id` | 40112 |
| `rule.level` | 12 |
| `rule.description` | Multiple authentication failures followed by a success. |
| `rule.frequency` | 2 |
| `rule.mitre.id` | T1078, T1110 |
| `rule.mitre.tactic` | Defense Evasion, Persistence, Privilege Escalation, Initial Access, Credential Access |
| `rule.mitre.technique` | Valid Accounts, Brute Force |
| `rule.mail` | true |

This second rule is the more critical alert from a SOC perspective: it correlates
the preceding failure burst with an immediately subsequent successful login for
the *same* account, which is a far stronger indicator of compromise than either
signal alone. A successful login on its own is not inherently suspicious; a
successful login immediately after a wave of failures against the same account
almost certainly indicates the account is now compromised. Notably this rule is
flagged `rule.mail: true`, meaning it is configured to trigger an email
notification — in a live SOC this event would generate an active alert to an
analyst rather than sitting passively in the log stream, reflecting its higher
severity (level 12 vs. level 10 for the failure-only rule).

The dual MITRE tactic mapping (Credential Access → Initial Access → Defense
Evasion/Persistence/Privilege Escalation) reflects that a successful brute-force
compromise is not just a credential-access event — it is the pivot point that
opens the door to every subsequent stage of an intrusion.

## Root Cause / Lessons Learned — Network Path Troubleshooting

Before the attack could be executed, port scanning against the target's internal
IP directly from the attacker box returned `filtered` rather than `open`,
despite the SSH service being confirmed active and reachable from the internal
network host.

**Diagnostic process:**
1. Confirmed the target's own firewall was not the cause — `ufw status` returned `inactive`.
2. Confirmed the service was reachable from *within* the internal segment — a ping from the internal network's host machine to the target succeeded.
3. This isolated the problem to the path *between* the external attacker segment and the internal segment — specifically, the perimeter firewall's NAT configuration.

**Root cause:** The firewall had an existing NAT port-forward rule from a prior
exercise (Writeup #01) mapping an external port to a *different* internal host
and port (SMB/445 to a Windows target). No equivalent rule existed to forward
external traffic on port 22 to `10.10.10.105`. Without such a rule, inbound
packets addressed to the firewall's WAN interface on port 22 had nowhere to be
routed internally and were silently dropped — this is expected, correct
firewall behavior, not a fault.

**Resolution:** Added a WAN NAT port-forward rule (WAN:22 → 10.10.10.105:22).
After this change, a scan against the firewall's WAN address correctly returned
`22/tcp open`, while a scan against the internal target IP directly continued to
return `filtered` — also expected and correct, since external hosts have no
route to the internal subnet and should never reach it by any path other than
through the firewall.

**Lesson:** In a segmented network, "is the service open" is not a single
yes/no question — it depends on *which vantage point* you test from, and each
new internal service exposed externally requires its own explicit NAT rule.
Testing exclusively against the internal IP from an external host, or exclusively
from an internal host, can each independently produce a misleading picture of
what an actual internet-based attacker would observe.

## Recommendations

1. **Enable SSH key-based authentication and disable password authentication**
   (`PasswordAuthentication no` in `sshd_config`) — this would have prevented
   this attack outright, regardless of password strength or detection tooling.
2. **Rate-limit or fail2ban SSH connections** at the host or firewall level to
   automatically block source IPs after a small number of failed attempts,
   rather than relying solely on detection-after-the-fact.
3. **Enforce a strong password policy** if password authentication must remain
   enabled, and rotate any credential that has been used in a testing/exposed
   context (the account password used in this exercise should be rotated).
4. **Restrict SSH exposure** to only the specific external IPs that require
   access (e.g., via firewall rules), rather than allowing any source to reach
   the port.
5. **Verify SOC alert routing** for level-12+ rules such as `40112` to ensure
   the configured email/notification channel reaches an analyst who can
   respond in real time, since this rule specifically indicates likely account
   compromise.

## Appendix

- Attack tool: `hydra` v9.7 (Kali Linux)
- Detection platform: Wazuh 4.14.7 (Manager + Indexer + Dashboard, all-in-one)
- Relevant Wazuh rule IDs: `5763`, `40112` (both built-in, `ruleset` default — no custom rule authored for this exercise)
- MITRE ATT&CK techniques observed: T1110 (Brute Force), T1078 (Valid Accounts)
