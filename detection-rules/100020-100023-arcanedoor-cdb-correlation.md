# Custom Rules 100020–100023 — Tiered ArcaneDoor Threat-Intel Matching on pfSense Firewall Logs

**Rule IDs:** 100020 / 100021 (likely actor-controlled tier, level 12) · 100022 / 100023 (multi-tenant tier, level 8) · **Matching:** `decoded_as` custom decoder `pfsense-filterlog` + CDB list lookup
**MITRE ATT&CK:** T1133 (External Remote Services), as tagged in the OpenCTI dataset
**Supporting artifacts:** custom decoder, two CDB lists ([`actor`](./lists/arcanedoor-actor-ips.txt), [`multi-tenant`](./lists/arcanedoor-multitenant-ips.txt)), pfSense → Wazuh syslog pipeline

## Purpose

These rules are the first place in this lab where cyber threat intelligence directly drives detection. [CTI Report #02](../cti-reports/02-arcanedoor-perimeter-devices.md) analyzed the ArcaneDoor campaign and produced 60 unique IPv4 indicators. Until now that list only lived in OpenCTI. Here it is loaded into Wazuh as CDB lists and matched automatically against pfSense firewall logs.

The 60 addresses are **not equally trustworthy**. Cisco Talos' original publication splits them into 22 "likely actor-controlled" addresses and 38 "multi-tenant" addresses, and warns that some listed addresses are shared or anonymization infrastructure rather than attacker-owned. The rules therefore work in two tiers:

| Rule | Field matched | List | Level |
|---|---|---|---|
| 100020 | source IP (traffic *from* the address) | actor-controlled (22) | 12 |
| 100021 | destination IP (traffic *to* the address) | actor-controlled (22) | 12 |
| 100022 | source IP | multi-tenant (38) | 8 |
| 100023 | destination IP | multi-tenant (38) | 8 |

Neither tier blocks anything. The rules generate alerts for triage. Because the indicators date from April 2024, a hit is a lead to investigate, not proof of compromise (see [Limitations](#limitations)).

## Data flow

```
Kali / Internet
      │  (SYN to WAN)
      ▼
pfSense (filterlog)  ──UDP/514 syslog──►  Wazuh remoted (10.10.10.102)
                                               │
                                     custom decoder pfsense-filterlog
                                     (extracts srcip, dstip, ports, action…)
                                               │
                                     rules 100020–100023
                                     (lookup against two CDB lists)
                                               │
                                               ▼
                                            alert
```

## Components

### pfSense side (Status → System Logs → Settings)

- Enable Remote Logging: yes
- Remote log server: `10.10.10.102:514`
- Remote Syslog Contents: **Firewall Events**

The setting is written to `/var/etc/syslog.d/pfSense.conf` (not `/var/etc/syslog.conf`, as older pfSense documentation suggests), with the content `*.* @10.10.10.102:514`.

### Wazuh side — syslog listener (`ossec.conf`)

A second `<remote>` block was added. The existing block for agents (1514/tcp) is untouched.

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.10.10.1</allowed-ips>
  <local_ip>10.10.10.102</local_ip>
</remote>
```

`ossec.log` confirms the listener: `Remote syslog allowed from: '10.10.10.1'` and `Listening on port 514/UDP (syslog)`.

### Custom decoder

File: `/var/ossec/etc/decoders/local_decoder.xml` (appended; backup `local_decoder.xml.bak`).

```xml
<decoder name="pfsense-filterlog">
  <prematch type="pcre2">(?:^|\s)\d*,\d*,\d*,\d+,\w+,match,</prematch>
</decoder>

<decoder name="pfsense-filterlog-ip4">
  <parent>pfsense-filterlog</parent>
  <regex type="pcre2">(?:^|\s)\d*,\d*,\d*,(\d+),(\w+),match,(\w+),(\w+),4,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,\d+,(\w+),\d+,(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+),(\d+),(\d+)</regex>
  <order>tracker,interface,action,direction,protocol,srcip,dstip,srcport,dstport</order>
</decoder>
```

The decoder covers **IPv4 TCP/UDP** filterlog lines only. ICMP and IPv6 lines are not field-extracted, which was not needed for this use case.

### CDB lists

| List | Repo copy | Entries | Meaning |
|---|---|---|---|
| `/var/ossec/etc/lists/arcanedoor-actor-ips` | [`lists/arcanedoor-actor-ips.txt`](./lists/arcanedoor-actor-ips.txt) | 22 | Talos: likely actor-controlled infrastructure |
| `/var/ossec/etc/lists/arcanedoor-multitenant-ips` | [`lists/arcanedoor-multitenant-ips.txt`](./lists/arcanedoor-multitenant-ips.txt) | 38 | Talos: multi-tenant infrastructure |

Both use Wazuh's `key:` format (one `IP:` per line), ownership `wazuh:wazuh`, mode `660`, and are registered in `ossec.conf` inside the `<ruleset>` block:

```xml
<list>etc/lists/arcanedoor-actor-ips</list>
<list>etc/lists/arcanedoor-multitenant-ips</list>
```

**Provenance.** The 60-address set comes from the OpenCTI export used in CTI Report #02. The **split into tiers comes from the Cisco Talos blog post** (IOC section), not from the OpenCTI dataset. The 22 actor-controlled addresses were entered from the Talos list, and the multi-tenant list is the remainder (60 minus 22). This was checked programmatically with `comm` before deployment: no actor address was missing from the original 60, the two groups do not overlap, and their union equals the original list exactly.

### Final rules

File: `/var/ossec/etc/rules/local_rules.xml`. Backups: `local_rules.xml.pre-cdb` (before the first CDB version) and `local_rules.xml.pre-tiers` (before the split into tiers).

```xml
<group name="pfsense,threat_intel,">
  <!-- Tier 1: likely actor-controlled ArcaneDoor infrastructure (Cisco Talos classification) -->
  <rule id="100020" level="12">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="srcip" lookup="address_match_key">etc/lists/arcanedoor-actor-ips</list>
    <description>pfSense firewall: inbound traffic from likely actor-controlled ArcaneDoor IP (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,arcanedoor_actor,</group>
  </rule>
  <rule id="100021" level="12">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="dstip" lookup="address_match_key">etc/lists/arcanedoor-actor-ips</list>
    <description>pfSense firewall: traffic to likely actor-controlled ArcaneDoor IP (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,arcanedoor_actor,</group>
  </rule>
  <!-- Tier 2: multi-tenant / shared infrastructure listed by Talos (lower confidence) -->
  <rule id="100022" level="8">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="srcip" lookup="address_match_key">etc/lists/arcanedoor-multitenant-ips</list>
    <description>pfSense firewall: inbound traffic from multi-tenant ArcaneDoor IP, lower confidence (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,arcanedoor_multitenant,</group>
  </rule>
  <rule id="100023" level="8">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="dstip" lookup="address_match_key">etc/lists/arcanedoor-multitenant-ips</list>
    <description>pfSense firewall: traffic to multi-tenant ArcaneDoor IP, lower confidence (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,arcanedoor_multitenant,</group>
  </rule>
</group>
```

`address_match_key` matches the field value against the list keys as IP addresses. Within a tier, the two rules differ only in which decoded field is looked up.

## Build process

Nearly all of the initial effort went into getting pfSense firewall logs decoded at all. The pipeline has four layers (network → reception → decoding → rule), and the problem was found by testing each layer independently instead of trusting the final symptom.

**1. Wazuh Discover only shows alerts.** Discover never displays raw or undecoded events, only events that matched a rule. "No Results" therefore did not say whether packets were missing or merely undecoded. Reception was checked separately with `tcpdump -i any udp port 514 -n` on the Wazuh VM (and pfSense Packet Capture on the LAN interface): packets were arriving.

**2. Reception confirmed, decoding failing.** To see whether Wazuh received but discarded the events, `<logall_json>yes</logall_json>` was enabled temporarily and `/var/ossec/logs/archives/archives.json` was searched for the traffic. It was reverted to `no` afterwards, because the archive grows quickly and fills the disk. The events were present and undecoded.

**3. Root cause: the predecoder misreads the pfSense header.** pfSense sends filterlog lines without a hostname field, for example:

```
Sep 20 22:17:34 filterlog[45376]: 4,,,1000000103,em0,match,block,in,4,...
```

Wazuh's built-in syslog predecoder interprets `filterlog[45376]:` as the *hostname*, so `program_name` is never set to `filterlog`. The stock pfSense decoders key on that program name, so none of them matched, and the result was `No decoder matched` even though the syslog framing was valid. `wazuh-logtest` output confirms it: `hostname: 'filterlog[45376]:'`.

**4. Fix: a decoder that does not depend on the header.** The custom decoder anchors on the CSV structure of the filterlog payload (`number,number,number,number,word,match,`) using `(?:^|\s)` instead of `^`, so it works wherever the payload starts in the line. `wazuh-logtest` was the key tool here: it tests decoders and rules against a pasted log line, without real traffic and without restarting the manager.

```bash
echo '<raw log line>' | sudo /var/ossec/bin/wazuh-logtest
```

**5. Editing over SSH.** The VMware console does not support pasting multi-line commands, and typing them by hand introduced errors (for example `-A8` typed with a wrong dash character). From this point on, configuration changes were made over SSH from the host (`ssh wazuh@10.10.10.102`), where copy/paste works.

**6. Rollback lesson: refresh the modification time.** During the first live test the Kali address (`192.168.1.105`) was added to the then-single list temporarily. Afterwards the clean 60-line backup was restored with `cp -p`, which preserves the *old* modification time, and the manager was restarted. The text file was clean, yet the removed address **still triggered the rule**. After running `touch` on the list file and restarting again, the `.cdb` file was rebuilt (its timestamp moved past the text file's) and the address no longer matched.

This is the observed behavior. The working hypothesis is that recompilation depends on the text file being newer than the existing `.cdb`, but that mechanism was not independently verified. The practical rule stands regardless: **after any list rollback, `touch` the list file before restarting, then confirm with `wazuh-logtest` that removed entries no longer match.** Do not rely on the text file contents alone.

**7. Splitting the list into tiers.** After verifying CTI Report #02 against the original Talos publication, it turned out that the 60 addresses mix two confidence levels. The change was deployed defensively:

- Backups first: `ossec.conf.pre-tiers`, `local_rules.xml.pre-tiers` and `arcanedoor-ips.pre-tiers`.
- The two new lists were added *next to* the old one and registered, so the existing rules kept working until the new ones were ready.
- The rule block was replaced by a small Python script instead of a manual edit. It asserted that exactly one old block existed and that IDs 100022/100023 were not yet in use, and refused to write otherwise.
- `wazuh-analysisd -t` (configuration check) ran before every restart, chained so that the restart only happens if the check passes. A syntax error therefore cannot take the manager down.
- Only after the tiered rules passed all tests was the old list's registration removed from `ossec.conf`. The file stays on disk as a backup, but no rule references it.

**8. One alert per event: tier precedence.** An event whose source is a multi-tenant address and whose destination is an actor-controlled address matches both a tier-1 and a tier-2 rule. Testing showed that only the tier-1 rule (100021, level 12) fires. This is consistent with rules being evaluated in file order (tier 1 is written first), but it is equally consistent with "highest level wins", and the two explanations were not separated by reordering the rules. The practical consequence is the same either way: in a mixed event, the multi-tenant match is not reported separately.

## Validation

### Initial single-list version (level 10, combined 60-address list)

All logtest checks used synthetic filterlog lines that differ only in the IP address under test.

- **Control:** listed source IP `216.238.66.251` decoded with all fields and fired rule 100020 (level 10, T1133).
- **Negative:** unlisted source IP `192.168.1.105` decoded with all fields but matched **no rule**, which shows the list discriminates instead of every decoded filterlog line alerting.
- **Live end-to-end test.** The Kali address was temporarily added to the list (60 → 61 entries, manager restarted), then a real scan was run from Kali against the pfSense WAN address:

```bash
sudo nmap -Pn -sS -p 22,80,443,3389,8080 192.168.1.152
```

Wazuh Discover (`rule.id: "100020"`, last 15 minutes) showed **8 hits** within about one second, all with `data.srcip: 192.168.1.105`, `data.dstip: 192.168.1.152`, `data.action: block`, `data.direction: in`, `data.interface: em0`. The alerts were for destination ports **80, 443, 3389 and 8080**, two SYN attempts each (source ports 59726 and 59728), consistent with nmap retransmitting SYNs to filtered ports. In `alerts.json` the event source is `location: 10.10.10.1`, which confirms the alert came through the pfSense syslog path and not a local agent.

The Kali address was then removed. As described in build lesson 6, the first re-check still matched it, and a `touch` plus restart was needed before it stopped alerting.

### Tiered version (rules 100020–100023)

Six `wazuh-logtest` checks with synthetic lines, run **twice**: once after deploying the tiered rules, and once more after the old combined list had been unregistered from `ossec.conf`. Results were identical both times.

| # | Test line | Result |
|---|---|---|
| 1 | source `216.238.75.155` (actor) | 100020, level 12, alert |
| 2 | destination `216.238.75.155` (actor) | 100021, level 12, alert |
| 3 | source `216.238.66.251` (multi-tenant) | 100022, level 8, alert |
| 4 | destination `216.238.66.251` (multi-tenant) | 100023, level 8, alert |
| 5 | source `192.168.1.105` (not listed) | decoded, **no rule matched** |
| 6 | source multi-tenant, destination actor | **100021**, level 12 (see build lesson 8) |

All four rules were therefore validated with `wazuh-logtest` only. **Live traffic was not repeated after the split**; the live test above covers the source-match path of the initial single-list version. The manager and the configuration check were clean after every restart.

## Limitations

- **Alerting, not blocking or hunting.** The rules only see events logged after the pipeline existed. They do not search historical traffic from the campaign window (see Detection Opportunity 1 in the CTI report).
- **Indicator age.** The addresses come from an April 2024 publication. Reassigned cloud/VPS addresses can produce hits unrelated to ArcaneDoor, so hits need enrichment and triage. This applies most to the multi-tenant tier, which is why it alerts at a lower level.
- **Classification is a snapshot.** The tiers reflect Talos' classification of the IOC list as published. They are static and were not re-verified against any later update.
- **Coverage.** Only what pfSense logs is seen (Firewall Events, sent as remote syslog). Only IPv4 TCP/UDP lines are decoded; ICMP and IPv6 are not.
- **Syslog transport.** UDP syslog has no delivery guarantee or authentication. `allowed-ips` restricts the accepted source address but does not authenticate the sender.
- **Manual list maintenance.** Updating a list means editing the file and restarting the manager (see build lesson 6). There is no automatic sync from OpenCTI.
- **One alert per event.** A mixed-tier event reports only the higher-tier rule (see build lesson 8).

## Key takeaway

An IOC list in a threat-intelligence platform has no defensive effect until something matches it against live telemetry. Loading the list as CDB lists and matching it against firewall logs turned a static CTI report into a working detection. Building it exposed a non-obvious ingestion problem (the predecoder treating `filterlog[PID]:` as a hostname) that a stock configuration would have hidden behind "No results". Verifying the report against its primary source then showed that the list mixed two confidence levels, and the detections were restructured to say so. Each layer of a pipeline must be verified independently, a rollback must be verified by behavior and not by file contents, and a threat-intel list is only as good as the confidence metadata that travels with it.
