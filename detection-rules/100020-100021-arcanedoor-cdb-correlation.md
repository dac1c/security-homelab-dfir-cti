# Custom Rules 100020 & 100021 — ArcaneDoor Threat-Intel Matching on pfSense Firewall Logs

**Rule IDs:** 100020 (source IP match) · 100021 (destination IP match) · **Level:** 10 · **Matching:** `decoded_as` custom decoder `pfsense-filterlog` + CDB list lookup
**MITRE ATT&CK:** T1133 (External Remote Services)
**Supporting artifacts:** custom decoder ([`local_decoder.xml`](#custom-decoder)), CDB list ([`lists/arcanedoor-ips.txt`](./lists/arcanedoor-ips.txt)), pfSense → Wazuh syslog pipeline

## Purpose

These rules are the first place in this lab where cyber threat intelligence directly drives detection. [CTI Report #02](../cti-reports/02-arcanedoor-perimeter-devices.md) analyzed the ArcaneDoor campaign and produced 60 unique IPv4 indicators. Until now that list only lived in OpenCTI. Here it is loaded into Wazuh as a CDB list and matched automatically against pfSense firewall logs.

- **Rule 100020** fires when the **source** address of a logged firewall event is on the list, meaning traffic *from* a listed IP toward the lab.
- **Rule 100021** fires when the **destination** address is on the list, meaning traffic *to* a listed IP from inside the lab.

Neither rule blocks anything. They generate alerts for triage. Because the indicators date from April 2024 and many are cloud/VPS addresses that may have been reassigned since, a hit is a lead to investigate, not proof of compromise (see [Limitations](#limitations)).

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
                                     rules 100020 / 100021
                                     (lookup against CDB list arcanedoor-ips)
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

### CDB list

- Source list: `/var/ossec/etc/lists/arcanedoor-ips`, a copy is kept in this repo as [`lists/arcanedoor-ips.txt`](./lists/arcanedoor-ips.txt)
- 60 IPv4 addresses, one per line, in Wazuh's `key:` format (for example `216.238.66.251:`), taken from the same OpenCTI export as CTI Report #02
- Ownership `wazuh:wazuh`, mode `660`
- Registered in `ossec.conf` inside the `<ruleset>` block:

```xml
<list>etc/lists/arcanedoor-ips</list>
```

Wazuh compiles the text list into `arcanedoor-ips.cdb` when the manager starts.

### Final rules

File: `/var/ossec/etc/rules/local_rules.xml` (backup before this change: `local_rules.xml.pre-cdb`).

```xml
<group name="pfsense,threat_intel,">
  <rule id="100020" level="10">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="srcip" lookup="address_match_key">etc/lists/arcanedoor-ips</list>
    <description>pfSense firewall: inbound traffic from IP listed in ArcaneDoor threat intel (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,</group>
  </rule>
  <rule id="100021" level="10">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="dstip" lookup="address_match_key">etc/lists/arcanedoor-ips</list>
    <description>pfSense firewall: traffic to IP listed in ArcaneDoor threat intel (CTI Report 02)</description>
    <mitre>
      <id>T1133</id>
    </mitre>
    <group>arcanedoor,</group>
  </rule>
</group>
```

`address_match_key` matches the field value against the list keys as IP addresses. The two rules differ only in which decoded field is looked up.

## Build process

The rules themselves were simple. Nearly all the effort went into getting pfSense firewall logs decoded at all. The pipeline has four layers (network → reception → decoding → rule), and the problem was found by testing each layer independently instead of trusting the final symptom.

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

**6. Rollback lesson: refresh the modification time.** During live testing the Kali address (`192.168.1.105`) was added to the list temporarily. Afterwards the clean 60-line backup was restored with `cp -p`, which preserves the *old* modification time, and the manager was restarted. The text file was clean, yet the removed address **still triggered rule 100020**. After running `touch` on the list file and restarting again, the `.cdb` file was rebuilt (its timestamp moved past the text file's) and the address no longer matched.

This is the observed behavior. The working hypothesis is that recompilation depends on the text file being newer than the existing `.cdb`, but that mechanism was not independently verified. The practical rule stands regardless: **after any list rollback, `touch` the list file before restarting, then confirm with `wazuh-logtest` that removed entries no longer match.** Do not rely on the text file contents alone.

## Validation

All logtest checks used synthetic filterlog lines that differ only in the IP address under test.

**Control — listed source IP (`216.238.66.251`)** decoded with all fields and fired:

```
name:         pfsense-filterlog
srcip:        216.238.66.251
dstip:        192.168.1.152
dstport:      445
id:           100020
level:        10
mitre.id:     T1133
Alert to be generated.
```

**Negative — unlisted source IP (`192.168.1.105`)** decoded with all fields (`srcip: 192.168.1.105`) but matched **no rule**, and there was no "Alert to be generated". This shows the list actually discriminates, rather than every decoded filterlog line alerting.

**Live end-to-end test.** The Kali address was temporarily added to the list (60 → 61 entries, manager restarted), then a real scan was run from Kali against the pfSense WAN address:

```bash
sudo nmap -Pn -sS -p 22,80,443,3389,8080 192.168.1.152
```

Wazuh Discover (`rule.id: "100020"`, last 15 minutes) showed **8 hits** within about one second, all with `data.srcip: 192.168.1.105`, `data.dstip: 192.168.1.152`, `data.action: block`, `data.direction: in`, `data.interface: em0`. The alerts were for destination ports **80, 443, 3389 and 8080**, two SYN attempts each (source ports 59726 and 59728), consistent with nmap retransmitting SYNs to filtered ports. In `alerts.json` the event source is `location: 10.10.10.1`, which confirms the alert came through the pfSense syslog path and not a local agent. Rule 100021 did not fire, as expected, since the destination address was not on the list.

**Rule 100021.** Validated with `wazuh-logtest` only, using a synthetic outbound line with a listed destination (`10.10.10.100 → 216.238.66.251`). It was not exercised with live traffic.

**Cleanup and re-verification.** After the live test the list was restored to the original 60 entries (`grep -c 192.168.1.105` returned `0`, ownership `wazuh:wazuh`, mode `660`). The first re-check still matched the removed address (see build lesson 6). After `touch` and restart, the Kali address no longer alerted, and the listed address `216.238.66.251` still fired 100020. All Wazuh services (`analysisd`, `remoted`, `logcollector`, `apid`) were running afterwards. A VMware snapshot was taken in that clean state.

Custom configuration also survived an accidental Ctrl+Alt+Del on the Wazuh VM earlier: Ubuntu treated it as a clean reboot, and the decoder, rules, list and `ossec.conf` were all intact and re-validated.

## Limitations

- **Alerting, not blocking or hunting.** The rules only see events logged after the pipeline existed. They do not search historical traffic from the April 2024 campaign window (see Detection Opportunity 1 in the CTI report).
- **Indicator age.** The addresses come from an April 2024 publication. Reassigned cloud/VPS addresses can produce hits unrelated to ArcaneDoor, so hits need enrichment and triage.
- **Coverage.** Only what pfSense logs is seen (Firewall Events, sent as remote syslog). Only IPv4 TCP/UDP lines are decoded; ICMP and IPv6 are not.
- **Syslog transport.** UDP syslog has no delivery guarantee or authentication. `allowed-ips` restricts the accepted source address but does not authenticate the sender.
- **Manual list maintenance.** Updating the list means editing the file and restarting the manager (see build lesson 6). There is no automatic sync from OpenCTI.

## Key takeaway

An IOC list in a threat-intelligence platform has no defensive effect until something matches it against live telemetry. Loading the list as a CDB and matching it against firewall logs turned a static CTI report into a working detection, and building it exposed a non-obvious ingestion problem (the predecoder treating `filterlog[PID]:` as a hostname) that a stock configuration would have hidden behind "No results". The same exercise showed why each layer of a pipeline must be verified independently, and why a rollback has to be verified by behavior and not just by file contents.
