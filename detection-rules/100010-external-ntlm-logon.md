# Custom Rule 100010 — External-Source NTLM Network Logon

**Rule ID:** 100010 · **Level:** 12 · **Parent rule:** 92657
**MITRE ATT&CK:** T1550.002 (Use Alternate Authentication Material: Pass the Hash)

## Purpose

The default Wazuh rule (92657) fires on **any** NTLM network logon (Logon
Type 3), regardless of source. In a real environment this generates constant
noise, since ordinary internal SMB/file-sharing traffic uses the exact same
authentication pattern as a credential-based lateral movement attack.

This custom rule narrows that signal: it only escalates to a high-severity
alert (level 12) when the NTLM logon originates from **outside** the lab's
trusted LAN (`10.10.10.0/24`) — i.e., traffic that has crossed the pfSense
perimeter from the "external" side, matching a realistic external-attacker
scenario.


> **Note (verified 22 September 2026):** This rule originally listed T1075 (Pass the Hash) alongside T1550.002. T1075 is a deprecated/revoked object in the current MITRE ATT&CK release, consolidated into T1550.002 (Use Alternate Authentication Material: Pass the Hash). Only T1550.002 is now referenced.

## Final rule

```xml
<group name="windows,authentication,sysmon,">
  <rule id="100010" level="12">
    <if_sid>92657</if_sid>
    <field name="win.eventdata.ipAddress" negate="yes">^10\.10\.10\.</field>
    <description>NTLM Network Logon outside local network (Possible Pass-the-Hash / Lateral Movement)</description>
      <mitre>
      <id>T1550.002</id>
    </mitre>
  </rule>
</group>
```

## Build process — what didn't work, and why

Getting from "default rule fires" to "custom rule fires correctly" took three
iterations, each surfacing a different piece of how Wazuh's rule engine
actually reads Windows event data:

**Attempt 1 — `<srcip negate="yes">10.10.10.0/24</srcip>`**
Failed silently (rule never matched). Wazuh's generic `<srcip>` tag reads a
normalized system field that Wazuh itself populates from *decoded* fields —
it does **not** automatically read arbitrary nested event data. The Windows
eventchannel decoder places the source address at
`data.win.eventdata.ipAddress`, not in the generic `srcip` slot, so the
comparison never had data to work against.

**Attempt 2 — `<field name="win.eventdata.ipAddress" type="cidr">`**
Failed at syntax validation:
```
WARNING: (7600): Invalid value 'cidr' for attribute 'type' in rule 100010
```
Wazuh's `<field>` tag does not support `cidr` as a type — CIDR-style matching
is only valid on `<srcip>`/`<dstip>`, not on arbitrary custom fields.

**Attempt 3 — `<field name="win.eventdata.ipAddress" negate="yes">^10\.10\.10\.</field>` (final)**
Targets the correct nested field directly, using it as a plain
regex-matched string field rather than trying to force IP/CIDR semantics onto
it. `negate="yes"` inverts the match: the rule fires when the address does
**not** start with `10.10.10.` — i.e., when it's external.

## Validation

```bash
sudo /var/ossec/bin/wazuh-analysisd -t   # syntax check — passed
sudo systemctl restart wazuh-manager
```

Re-running the SMB access from Kali (`smbclient -L //192.168.1.152 -U victim`)
produced a matching alert in Wazuh Discover:
```
rule.id: 100010
rule.level: 12
```
confirming the rule correctly escalates external NTLM logons while (by
design) staying silent on internal LAN-to-LAN SMB traffic.

## Key takeaway

Wazuh's `<srcip>` convenience tag is not a generic "any IP field" matcher —
it only works against fields the decoder has explicitly normalized. For
product-specific or vendor-specific nested fields (like Windows eventchannel
data), `<field name="...">` with a regex is the correct and more reliable
approach.
