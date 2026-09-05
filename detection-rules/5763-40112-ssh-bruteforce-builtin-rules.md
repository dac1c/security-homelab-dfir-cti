# Detection Rules 5763 & 40112: SSH Brute-Force (Built-in Wazuh Rules)

## Overview

Unlike [rule 100010](100010-external-ntlm-logon.md), which was authored from
scratch for this lab, rules **5763** and **40112** are part of Wazuh's
**default ruleset** (`ossec_rules.xml` / `sshd_rules.xml`). They are documented
here to record how they were identified, tested, and mapped to the incident
observed in [writeup #02](../dfir-writeups/02-ssh-bruteforce-linux-victim.md).

Analyzing and correctly interpreting existing, vendor-supplied detection
content is a distinct skill from writing custom rules — in most SOC
environments the majority of day-to-day alert triage happens against a
pre-built ruleset, so understanding *why* a built-in rule fired, what it
depends on, and how confident it should make an analyst is just as important
as being able to write new ones.

---

## Rule 5763 — Brute-force pattern (failures only)

```
Rule ID:          5763
Level:            10
Description:      sshd: brute force trying to get access to the system.
                   Authentication failed.
Groups:           syslog, sshd, authentication_failures
MITRE ATT&CK:     T1110 (Brute Force) — Tactic: Credential Access
```

**How it works:** This is a **correlation rule**, not a single-event rule. It
does not fire on any individual `sshd: authentication failed` log line.
Instead, it is defined (in Wazuh's rule engine) to watch for a minimum number
of authentication-failure events from the *same source IP* within a bounded
time window, and only fires once that frequency threshold is crossed. In the
observed alert, `rule.frequency: 8` — the rule fired after the 8th failed
attempt from `192.168.1.234` in rapid succession.

**Why frequency-based, not per-event:** A single failed SSH login is common
and low-signal — a legitimate user can easily mistype a password. Alerting an
analyst on every single failure would generate unusable noise. By requiring a
burst of failures within a short window, this rule filters out normal human
error and isolates the pattern that is characteristic of automated
password-guessing tools (like `hydra`), which attempt many credentials in a
few seconds.

**Dependency:** This rule relies on the underlying `sshd` decoder correctly
parsing `Failed password for <user> from <ip> port <port>` lines from the
system log source (in this lab, ingested via `journald` on the Ubuntu
target). If the decoder does not match the log format — for example, on a
different Linux distribution or SSH implementation with non-standard log
phrasing — this rule will silently never fire, regardless of how many failed
logins occur. This is a useful validation point when onboarding a new log
source: confirm the decoder is matching before trusting the absence of
alerts.

---

## Rule 40112 — Failures followed by a success

```
Rule ID:          40112
Level:            12
Description:      Multiple authentication failures followed by a success.
Groups:           syslog, attacks
MITRE ATT&CK:     T1110 (Brute Force), T1078 (Valid Accounts)
                   Tactics: Credential Access, Initial Access, Defense Evasion,
                   Persistence, Privilege Escalation
Mail:             true (flagged for notification)
```

**How it works:** This is a second-order correlation rule, one level up from
5763. It correlates a preceding burst of authentication failures for a given
account with an **immediately subsequent successful login for that same
account**. In the observed alert, `rule.frequency: 2` reflects the minimal
internal state needed to link "there were recent failures" with "then a
success occurred" for the same target — it does not require re-counting the
entire failure burst, since rule 5763 (or the underlying failure count) has
already established that pattern exists.

**Why this is the higher-priority alert:** A successful login is not
inherently suspicious on its own — that's how legitimate access looks. A
successful login for an account that *just* experienced a wave of failed
attempts is a very different signal: it strongly suggests the password was
guessed rather than entered correctly by its legitimate owner. This is
reflected in the higher severity level (12 vs. 10) and the fact that this
rule — unlike 5763 — is flagged `rule.mail: true`, meaning it is configured to
actively notify (e.g. via email) rather than sit passively in the log stream.
In a live SOC, this rule firing should be treated as a likely-compromised
account until proven otherwise, warranting immediate password reset and
session review for the affected user.

**Dual MITRE mapping rationale:** The rule maps to both T1110 (the brute-force
method used to obtain the credential) and T1078 (the resulting use of what is
now a "valid" — but attacker-controlled — account). The five listed tactics
reflect that a successful credential-guessing compromise is a pivot point: it
simultaneously represents the culmination of a Credential Access attempt and
the start of Initial Access, with everything that follows (persistence,
privilege escalation, defense evasion) now made possible using a legitimate
account rather than an exploited vulnerability — which is itself harder to
detect and often harder to remediate (rotating a password is not the same as
patching a bug).

---

## Validation

Both rules were confirmed against live traffic generated by `hydra` in
[writeup #02](../dfir-writeups/02-ssh-bruteforce-linux-victim.md):

- Rule 5763 fired once, after 8 failed attempts from `192.168.1.234` against user `victim`.
- Rule 40112 fired immediately after, correlating those failures with the successful 9th attempt.

No modification to the default ruleset was required for either rule — both
are enabled out of the box in a standard Wazuh 4.14.7 installation. This
exercise's value was in **identifying which built-in rules matter for a given
attack scenario, confirming they fire as expected against a real (simulated)
attack, and understanding the detection logic well enough to explain it** —
not in writing new detection content.
