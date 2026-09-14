# Custom Rule 100011 — Correlated Lateral Movement: Service Creation + Suspicious Process Execution

**Rule ID:** 100011 · **Level:** 12 · **Parent rules:** 92052 (if_sid), 92650 (if_matched_sid)
**MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares) · T1569.002 (Service Execution) · T1059.003 (Windows Command Shell)

## Purpose

Rules 92650 (service installation from Windows root path) and 92052 (abnormal `cmd.exe` parent) both fire
during a successful Impacket `psexec`-style attack — 92650 at the moment the malicious service is
registered, 92052 a fraction of a second later when the resulting SYSTEM-level command shell is opened.
Neither rule alone tells the full story: 92650 is level 12 and generates an email alert, but 92052 is
level 4 with `mail: false`, meaning the analyst learns about the service installation but is not
automatically notified that a SYSTEM shell was subsequently opened as a direct consequence.

The two rules firing within under one second on the same agent is itself a high-confidence composite
indicator. This custom rule correlates that pair into a single level 12 alert covering the full
technique chain — service-based remote execution to interactive SYSTEM shell — which matches no single
default Wazuh rule.

## Final rule

```xml
<group name="windows,authentication,sysmon,">
  <rule id="100011" level="12" timeframe="60">
    <if_sid>92052</if_sid>
    <if_matched_sid>92650</if_matched_sid>
    <description>Correlated Lateral Movement: Service Creation followed by Suspicious Process Execution (Possible PsExec/Impacket)</description>
    <mitre>
      <id>T1021.002</id>
      <id>T1569.002</id>
      <id>T1059.003</id>
    </mitre>
    <options>alert_by_email</options>
  </rule>
</group>
```

The rule fires when rule 92052 is seen within 60 seconds of a prior match on rule 92650, on the same
agent. `<options>alert_by_email</options>` sets `mail: true`, ensuring an analyst is notified at the
moment the composite indicator is confirmed rather than only at the service-installation stage.

## Build process — what didn't work, and why

Getting from "individual rules fire" to "correlation rule fires correctly" took three iterations,
each surfacing a different piece of how Wazuh's correlation engine works:

**Attempt 1 — `timeframe` as a child element**

The first draft placed `timeframe` as its own XML element:
```xml
<rule id="100011" level="12">
  <timeframe>60</timeframe>
  ...
</rule>
```
The manager rejected this on startup:
```
ERROR: (7600): Invalid option 'timeframe' for rule 100011
```
`timeframe` is an attribute on the `<rule>` tag, not a child element — the correct syntax is
`<rule id="100011" level="12" timeframe="60">`.

After making this change, the manager still failed to start with the same error. Re-reading the file
with `cat` showed the old `<timeframe>60</timeframe>` element was still present alongside the newly
added attribute — both had silently coexisted after the `nano` edit. The fix was to remove the
stale element entirely and verify with `cat` before restarting. The broader lesson: always re-read a
config file after editing it rather than assuming the edit was applied as intended.

**Attempt 2 — `<same_field>agent.id</same_field>`**

With the `timeframe` fix in place, the manager started cleanly and the rule loaded without error.
However, it never fired, even with 92650 and 92052 confirmed present for the same agent within the
60-second window:

```
rule.id:92650  →  2026-09-13 22:58:23.685 UTC  (agent.id: 001)
rule.id:92052  →  2026-09-13 22:58:24.145 UTC  (agent.id: 001, +0.46s)
rule.id:100011 →  no hits
```

The `<same_field>agent.id</same_field>` line was added with the intent of ensuring both constituent
events came from the same agent. It had the opposite effect: `<same_field>` in Wazuh only compares
fields extracted dynamically by a decoder (via `<field name="...">`), not fixed metadata that Wazuh
attaches to every alert automatically — `agent.id` falls into the latter category. Because the field
never resolves to a decoder-extracted value, the comparison silently fails with no error logged, and
the correlation never triggers.

`<same_field>` is also redundant here: `if_matched_sid` correlation is already scoped to the same
agent by default, and only crosses agent boundaries if `<global_frequency/>` is explicitly added.
The fix was to delete the `<same_field>` line entirely.

## Validation

```bash
sudo systemctl restart wazuh-manager
sudo grep -A 12 '"100011"' /var/ossec/etc/rules/local_rules.xml   # confirm rule loaded
```

Re-running the Impacket `psexec` attack against `Windows-Victim-01` after the fix produced a
matching alert on the first attempt:

```
rule.id:          100011
rule.level:       12
rule.mail:        true
rule.frequency:   2
rule.description: Correlated Lateral Movement: Service Creation followed by Suspicious Process Execution (Possible PsExec/Impacket)
rule.mitre.id:    T1021.002, T1569.002, T1059.003
agent.name:       windows-victim-01
```

The correlated alert carries all three MITRE technique IDs from its two constituent rules, giving an
analyst the full technique chain — delivery via Admin Shares, service-based execution, and interactive
command shell — in a single alert rather than requiring manual correlation across two separate
low-context events.

Full attack recreation and alert evidence are documented in
[Writeup #03](../dfir-writeups/03-smb-admin-shares-lateral-movement.md) (Update section, 14 September 2026).

## Key takeaway

Wazuh's `<same_field>` tag operates only on dynamically decoder-extracted fields, not on static
alert metadata. For correlating events across the same agent, `if_matched_sid` already enforces
same-agent scoping by default — adding `<same_field>agent.id</same_field>` does not strengthen
the rule, it silently breaks it.
