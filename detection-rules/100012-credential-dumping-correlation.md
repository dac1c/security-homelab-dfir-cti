# Custom Rule 100012 — Correlated Credential Dumping: Privileged Logon + Service Configuration Change

**Rule ID:** 100012 · **Level:** 12 · **Parent rules:** 61104 (if_sid), 67028 (if_matched_sid)
**MITRE ATT&CK:** T1003 (OS Credential Dumping) · T1003.002 (Security Account Manager) · T1078 (Valid Accounts)

## Purpose

Rule 67028 (Special Privileges Assigned — EventID 4672) fires whenever a privileged logon is granted
sensitive rights such as `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege` — the exact
set of privileges required to read the SAM and LSA secrets hives remotely. On its own it is low-signal:
it is level 3 and fires on any privileged interactive or network logon, legitimate or not.

Rule 61104 (Service startup type was changed — EventID 7040) fires whenever any Windows service has
its startup type modified. It is also low-signal alone (level 3), and generic — it is not specific to
RemoteRegistry and fires for routine changes such as the Background Intelligent Transfer Service.

During a `secretsdump.py`-style attack, Impacket does not touch LSASS memory directly. Instead it
authenticates with a privileged account, then remotely starts the RemoteRegistry service (if not
already running) to read the SAM/SECURITY hives over the Windows Remote Registry protocol, and finally
restores the service to its original (usually disabled) startup type as a cleanup step. This produces
exactly one 4672 event followed, within seconds, by two 7040 events for the same service (once to
enable it, once to restore it) — a distinctive pattern that neither rule captures alone, but which is
a strong single-agent indicator of remote credential dumping when combined.

## Final rule

```xml
<rule id="100012" level="12" timeframe="120">
  <if_matched_sid>67028</if_matched_sid>
  <if_sid>61104</if_sid>
  <description>Possible credential dumping: privileged logon followed by service configuration change (e.g. RemoteRegistry)</description>
  <mitre>
    <id>T1003</id>
    <id>T1003.002</id>
    <id>T1078</id>
  </mitre>
  <group>credential_dumping,</group>
</rule>
```

The rule fires when rule 61104 (service startup type change) is seen within 120 seconds of a prior
match on rule 67028 (privileged logon), on the same agent. Note the order relative to Rule 100011:
here `if_matched_sid` references the *earlier* event (4672) and `if_sid` references the *later* event
(7040), since the privileged logon always precedes the service change in this attack chain — the
opposite ordering from the PsExec correlation rule, where the triggering event came first.

No `<same_field>agent.id</same_field>` was added, consistent with the lesson documented in Rule
100011: `if_matched_sid` correlation is already scoped to the same agent by default, and
`<same_field>` only operates on fields extracted dynamically by a decoder, not static alert metadata
such as `agent.id`.

A wider `timeframe` (120s vs. 60s in Rule 100011) was chosen because this attack chain spans a full
authenticate → enable-service → dump → restore-service cycle rather than a single service creation
followed immediately by shell execution, and empirically took roughly 13 seconds between the two 7040
events during testing — 120s leaves comfortable margin without meaningfully raising the false-positive
window.

## Build process

Unlike Rule 100011, this rule loaded and fired correctly on the first attempt — the `timeframe`
attribute placement and the omission of `<same_field>` were already known pitfalls from that earlier
rule and were avoided from the start.

The only issue encountered was operational rather than rule-logic related: the first attempt to save
`local_rules.xml` from `nano` failed with `Permission denied`, because the editor had been opened
without `sudo`. The fix was to save the buffer to a temporary file (`Ctrl+O` → `/tmp/local_rules_new.xml`),
then use `sudo cp` to copy it over the real config file, which preserves the original file's ownership
and permissions.

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo cp /tmp/local_rules_new.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

## Validation

```bash
sudo grep -i "rules" /var/ossec/logs/ossec.log | tail -n 20
# Total rules enabled: '8454'   (up from 8453 prior to the restart — confirms the new rule loaded)
sudo systemctl status wazuh-manager --no-pager
# Active: active (running)
```

Re-running `secretsdump.py` against `Windows-Victim-01` produced a matching alert on the first attempt:

```
rule.id:          100012
rule.level:       12
rule.mail:        true
rule.frequency:   2
rule.description: Possible credential dumping: privileged logon followed by service configuration change (e.g. RemoteRegistry)
rule.mitre.id:    T1003, T1003.002, T1078
agent.name:       windows-victim-01
```

Two hits were recorded, corresponding to the two 7040 events (RemoteRegistry demand-start → disabled,
and disabled → demand-start) both falling within the 120-second correlation window of the single 4672
privileged logon event.

Full attack recreation and alert evidence are documented in
[Writeup #04](../dfir-writeups/04-credential-dumping-impacket.md).

## Key takeaway

A privileged logon and a service configuration change are each unremarkable on their own — both occur
routinely during legitimate administration. Correlating them within a short window converts two
low-confidence, low-level signals into a single high-confidence indicator of remote credential access
tooling, without requiring any Sysmon-level process or LSASS-access telemetry.
