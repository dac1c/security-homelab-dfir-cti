# Custom Rules 100024 & 100025 — Secret Blizzard AiTM Infrastructure Matching on pfSense Firewall Logs

**Rule IDs:** 100024 (source IP match) · 100025 (destination IP match) · **Level:** 12
**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), as tagged by Microsoft's original publication (not in the ingested OpenCTI dataset — see [CTI Report #03](../cti-reports/03-secret-blizzard-frozen-in-transit.md))
**Supporting artifacts:** CDB list ([`lists/secretblizzard-ips.txt`](./lists/secretblizzard-ips.txt)), the same custom `pfsense-filterlog` decoder and syslog pipeline built for rules 100020–100023

## Purpose

These rules extend the pfSense → Wazuh threat-intel matching pipeline (originally built for [CTI Report #02](../cti-reports/02-arcanedoor-perimeter-devices.md), documented in [rules 100020–100023](./100020-100023-arcanedoor-cdb-correlation.md)) to a second, unrelated campaign: [CTI Report #03](../cti-reports/03-secret-blizzard-frozen-in-transit.md), covering Secret Blizzard's (Turla's) ISP-level AiTM campaign against diplomats in Moscow.

Unlike the ArcaneDoor list, this dataset contributes only **one** network indicator with primary-source confirmation: the IP address `45.61.149.109`. CTI Report #03's data-quality findings section documents that most of the file-hash indicators in that dataset could not be confirmed against Microsoft's own published IOC table — file hashes are not something this pfSense/network-log pipeline can match in any case, so that finding does not affect these rules directly, but it is the reason no tiering scheme was built here: with a single confirmed indicator there is nothing to split into confidence tiers.

The confirmed campaign domain, `kav-certificates.info`, is **not** matched by any rule here. pfSense's `filterlog` format (the source this pipeline decodes) carries only IP addresses, not DNS query names, so a domain-based indicator cannot be matched by this pipeline without a DNS-log source this lab does not currently collect. This is recorded as an open gap rather than worked around.

| Rule | Field matched | List | Level |
|---|---|---|---|
| 100024 | source IP (traffic *from* the address) | secretblizzard-ips (1) | 12 |
| 100025 | destination IP (traffic *to* the address) | secretblizzard-ips (1) | 12 |

Neither rule blocks anything; both generate alerts for triage.

## Components

### CDB list

`/var/ossec/etc/lists/secretblizzard-ips`, one entry (`45.61.149.109:`), ownership `wazuh:wazuh`, mode `660`, repo copy at [`lists/secretblizzard-ips.txt`](./lists/secretblizzard-ips.txt). Registered in `ossec.conf` alongside the two ArcaneDoor lists:

```xml
<list>etc/lists/arcanedoor-actor-ips</list>
<list>etc/lists/arcanedoor-multitenant-ips</list>
<list>etc/lists/secretblizzard-ips</list>
```

**Provenance.** The IP address was checked directly against Microsoft's published IOC table for this campaign (see CTI Report #03, Data Quality Findings) and matches exactly.

### Final rules

Appended to `/var/ossec/etc/rules/local_rules.xml` as a new `<group>` block, after the existing ArcaneDoor group. Backups taken before this change: `ossec.conf.pre-secretblizzard`, `local_rules.xml.pre-secretblizzard`.

```xml
<group name="pfsense,threat_intel,">
  <rule id="100024" level="12">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="srcip" lookup="address_match_key">etc/lists/secretblizzard-ips</list>
    <description>pfSense firewall: inbound traffic from Secret Blizzard AiTM infrastructure (CTI Report 03)</description>
    <mitre>
      <id>T1557</id>
    </mitre>
    <group>secretblizzard,</group>
  </rule>
  <rule id="100025" level="12">
    <decoded_as>pfsense-filterlog</decoded_as>
    <list field="dstip" lookup="address_match_key">etc/lists/secretblizzard-ips</list>
    <description>pfSense firewall: traffic to Secret Blizzard AiTM infrastructure (CTI Report 03)</description>
    <mitre>
      <id>T1557</id>
    </mitre>
    <group>secretblizzard,</group>
  </rule>
</group>
```

Both rules reuse the `pfsense-filterlog` decoder and `address_match_key` lookup mechanism already built and documented for rules 100020–100023; no new decoder work was required.

Level 12 was chosen — higher than the ArcaneDoor actor tier (also 12) — on the basis that this is a single, individually-confirmed indicator directly tied to a still-relevant, actively tracked state actor, rather than one entry in a large, partially-unconfirmed list.

## Build process

This extension reused the existing pipeline (pfSense syslog forwarding, the custom `pfsense-filterlog` decoder, and the CDB list mechanism), so none of the original decoding problems from rules 100020–100023 reappeared. The only new step was appending a rule block rather than editing an existing one:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /tmp/local_rules_before.xml
sudo bash -c 'cat /tmp/local_rules_before.xml /tmp/secretblizzard_rules.xml > /var/ossec/etc/rules/local_rules.xml'
```

`wazuh-analysisd -t` (configuration check) was run and confirmed to pass before restarting the manager, following the same defensive pattern established for the ArcaneDoor tier split: never restart on unverified configuration.

## Validation

Three `wazuh-logtest` checks with synthetic filterlog lines, differing only in the IP address under test:

| # | Test line | Result |
|---|---|---|
| 1 | source `45.61.149.109` | 100024, level 12, T1557, alert |
| 2 | destination `45.61.149.109` | 100025, level 12, T1557, alert |
| 3 | source `192.168.1.105` (not listed) | decoded, **no rule matched** |

No live traffic test was run for these rules (unlike the initial ArcaneDoor validation, which included a live nmap scan). Given the pipeline itself was already proven end-to-end for the identical decoder and lookup mechanism, a repeat live test was judged to add validation of the same mechanism rather than new information; this is a deliberate scope decision, not an oversight.

## Limitations

- **Single indicator, single source.** Unlike the ArcaneDoor lists, this list has no internal structure to validate (no tiering, no cross-checking two subsets against each other) — its confidence rests entirely on the one-time check against Microsoft's published IOC table.
- **Domain indicator not covered.** `kav-certificates.info` cannot be matched by this pipeline without a DNS-log source (see Purpose).
- **Alerting, not blocking or hunting.** As with the ArcaneDoor rules, this only sees events logged after the rule existed; it does not search historical traffic.
- **No live-traffic validation for this specific list**, per the Validation section above.
- **Manual list maintenance**, same as the ArcaneDoor lists — no automatic sync from OpenCTI.

## Key takeaway

Extending an existing, already-debugged pipeline to a second CTI report was fast precisely because the hard problems (syslog reception, decoder correctness, CDB compilation and reload behavior) were solved once and reused. The more interesting decision here was what *not* to build: no tiering (only one confirmed indicator existed to tier), no domain rule (the log source cannot support it), and no repeat live-fire test (it would have re-validated a mechanism already proven, not added new confidence). Knowing when additional validation work would not change the risk assessment is as much a part of detection engineering as building the detection itself.
