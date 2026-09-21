# CTI Report #02: ArcaneDoor — Espionage-Focused Campaign Against Perimeter Network Devices

**TLP:CLEAR** · **Confidence:** Moderate (third-party OSINT, not independently verified in this lab) · **Date:** September 2026

## Executive Summary

This report analyzes **ArcaneDoor**, an espionage-focused intrusion campaign disclosed in April 2024 that targeted perimeter network devices, specifically Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) products. The source material is a MISP event published by Cisco Talos and ingested into this lab's OpenCTI instance through the CIRCL OSINT feed: an intrusion set, one ATT&CK technique, 60 unique IPv4 addresses, and several text excerpts drawn from Cisco advisories.

Where Report #01 ([KrustyLoader](./01-krustyloader-ivanti-connectsecure.md)) centered on malware and file indicators, this dataset is dominated by network infrastructure indicators. That makes it a useful exercise in a different question: what can an analyst realistically do with a large, aging IP list, and how much of it is still actionable more than two years after publication?

This is a retrospective analysis. No Cisco ASA/FTD device exists in this lab, and no activity from this campaign was observed here.

---

## Threat Overview

The campaign targeted devices that sit at the network edge: firewalls and VPN concentrators that see all inbound and outbound traffic and are typically not covered by endpoint detection tooling. This is the defining characteristic of the campaign, and it recurs across several of the reports in this lab's CIRCL feed (Ivanti in Report #01, and others in the same "Correlated Containers" list).

The ingested Cisco text describes two vulnerabilities in ASA/FTD software:

* **A denial-of-service flaw** in the management and VPN web servers, triggered by a crafted HTTP request that exploits incomplete error checking during header parsing, causing the device to reload. No authentication is required.
* **A local code-execution flaw** in a legacy capability for preloading VPN clients and plug-ins. An attacker with administrator-level access copies a crafted file to the device's `disk0:` file system, and arbitrary code runs with root privileges after the next reload. Because the injected code can survive reboots, Cisco raised the advisory's severity rating from Medium to High.

The second flaw is the more strategically significant of the two. It is not an initial-access bug, since it requires existing administrative access. Its value to an attacker is **persistence**: surviving reboots on a device that defenders rarely reimage or inspect at the filesystem level.

Also included in the dataset is a Cisco-recommended memory check for signs of tampering: run `show memory region | include lina` and look for more than one executable (`r-xp`) region, especially one of exactly `0x1000` bytes.

---

## Technical Analysis

### Infrastructure profile

The 60 unique IPv4 indicators show clear clustering rather than random spread:

| Pattern | Observation |
|---|---|
| `216.238.x.x` | 8 addresses across several /24 ranges within a single /16 block |
| `213.156.138.x` | 3 addresses in one /24 (`.68`, `.77`, `.78`) |
| `89.44.198.x` | 3 addresses in one /24 (`.16`, `.189`, `.196`) |
| `45.86.163.x`, `185.244.210.x`, `154.22.235.x`, `172.105.x.x` | Pairs within the same /24 or /16 |

Repeated use of neighboring addresses suggests infrastructure rented in batches from the same providers, which is consistent with a disposable, rotate-as-needed operating model. This dataset does not state who owns these ranges, so provider attribution is deliberately left out of this report and would need separate WHOIS/ASN enrichment.

### Indicator quality problem

Of the 70 Indicator objects in this export, 60 are IP addresses and 10 are `text:value` indicators. Several of those text indicators are single generic words: `Report`, `Published`, `Blog`, `Trusted`. These appear to be MISP attribute comments or tags that the connector converted into indicators, and a value like `Trusted` cannot be used for detection without generating false positives on any text field that contains it. The same artifact appeared in Report #01's dataset (`Trusted`, `Python`).

This is a **data-quality finding about the ingestion pipeline**, and it matters operationally: if these indicators were pushed unfiltered into a detection or blocking system, they would be noise at best and cause outages at worst. Practical mitigation is to filter indicators by type and pattern before export, and to apply a minimum specificity threshold to text-based indicators.

### Age of the indicators

The IP indicators originate from an April 2024 publication. Roughly 29 months later, many of these addresses are likely to have been reassigned, particularly cloud/VPS ranges where addresses cycle between customers. Their value today is mostly **retrospective hunting** (checking historical logs for contact with these addresses during the 2024 window), not live blocking. Blocking a stale VPS address risks cutting off an unrelated legitimate tenant.

### Additional context from public reporting (not in the ingested dataset)

The following details come from general public knowledge of this campaign and are **not** contained in the OpenCTI dataset. They should be verified against Cisco Talos' original publication before being relied on:

* Talos tracked the actor as **UAT4356**, and Microsoft separately as **STORM-1849**.
* The campaign used two custom implants, commonly named **Line Dancer** (an in-memory component) and **Line Runner** (a persistence mechanism).
* The vulnerabilities in the ingested text correspond to **CVE-2024-20353** (denial of service) and **CVE-2024-20359** (persistence via the legacy preload feature).
* Talos assessed the actor as state-sponsored.

---

## MITRE ATT&CK Mapping

Only **T1133** is present in the ingested dataset (as an Attack Pattern linked to the ArcaneDoor Intrusion Set). The others are analyst-assigned from the behavior described above and are tentative.

| Tactic | Technique | Source |
|---|---|---|
| Persistence / Initial Access | **T1133** — External Remote Services | Dataset |
| Initial Access | **T1190** — Exploit Public-Facing Application | Analyst-assigned |
| Defense Evasion | **T1601** — Modify System Image | Analyst-assigned, tentative |

---

## Detection Opportunities

1. **Retrospective hunting against the IP list.** Search historical firewall and proxy logs (for this lab, pfSense logs forwarded to Wazuh) for connections to or from any of the 60 addresses within the April 2024 window. A hit would be meaningful; absence is expected and should be documented as a negative result.
2. **Convert the IOC list into a SIEM lookup.** *(Implemented.)* The 60 IPv4 indicators were loaded as a Wazuh CDB list and matched against pfSense firewall logs by custom rules 100020 (source match) and 100021 (destination match). This is the first case in this lab of CTI feeding detection rather than sitting alongside it. Note that this is forward-looking alerting, not retrospective hunting: it only matches traffic logged after the pipeline was built. See [Rules 100020/100021](../detection-rules/100020-100021-arcanedoor-cdb-correlation.md).
3. **Device-level integrity checking.** The Cisco-provided memory check is specific to ASA/FTD and cannot be applied in this lab, but the principle generalizes: perimeter devices need periodic integrity verification that does not depend on the device's own logging, since a compromised device may report itself as clean.
4. **Forward perimeter device logs to the SIEM.** Edge devices are a frequent blind spot. Even without an ASA, the lab's pfSense firewall follows the same pattern and is the right place to practice this. *(Implemented for pfSense: firewall events are forwarded to Wazuh over syslog, which required a custom decoder. See the document linked above.)*

---

## Recommendations

* **Do not block this IP list blindly.** Given its age and the presence of shared cloud address space, treat it as a hunting dataset with a documented retention window, not a permanent blocklist.
* **CDB matching is alerting, not blocking.** In this lab the list drives level-10 alerts for triage only. Because the indicators are more than two years old, treat a hit as a lead that needs enrichment, expect false positives from reassigned addresses, and refresh or retire the list on a documented schedule.
* **Filter indicators at ingestion.** Drop single-word text indicators and require a minimum specificity for text-type patterns before pushing anything from OpenCTI into detection tooling.
* **Treat edge devices as monitored assets.** Ensure firewalls and VPN appliances forward logs to a central SIEM and have a defined firmware-integrity check schedule.
* **Prioritize patching for persistence-capable vulnerabilities.** A flaw that requires prior admin access is easy to under-rate, but it is precisely what turns a one-time intrusion into a durable foothold.

---

## Sources

* Cisco Talos, ArcaneDoor publication (April 2024), via the CIRCL OSINT MISP feed as ingested into this lab's OpenCTI instance on 15–16 September 2026
* Cisco security advisory excerpts contained in the ingested dataset (paraphrased in this report)
* Public reporting on UAT4356 / STORM-1849 (context only, not in the ingested dataset; see the verification note above)

> **Analyst note:** The ingested MISP event contained IP indicators, an intrusion set, one ATT&CK technique, and advisory excerpts, but no narrative campaign analysis. The infrastructure clustering analysis, the indicator-quality and age findings, the detection opportunities, and the recommendations are original work built on the raw data. Details drawn from outside the dataset are explicitly labeled as such.

---

## Appendix: Indicators

*All indicators are TLP:CLEAR. 60 unique IPv4 addresses were present in the export; they are defanged below.*

| # | IPv4 (defanged) | # | IPv4 (defanged) |
|---|---|---|---|
| 1 | 5[.]183[.]95[.]95 | 31 | 154[.]39[.]142[.]47 |
| 2 | 45[.]63[.]119[.]131 | 32 | 172[.]105[.]90[.]154 |
| 3 | 45[.]76[.]118[.]87 | 33 | 172[.]105[.]94[.]93 |
| 4 | 45[.]77[.]52[.]253 | 34 | 172[.]233[.]245[.]241 |
| 5 | 45[.]77[.]54[.]14 | 35 | 176[.]31[.]18[.]153 |
| 6 | 45[.]86[.]163[.]224 | 36 | 185[.]123[.]101[.]250 |
| 7 | 45[.]86[.]163[.]244 | 37 | 185[.]167[.]60[.]85 |
| 8 | 45[.]128[.]134[.]189 | 38 | 185[.]227[.]111[.]17 |
| 9 | 51[.]15[.]145[.]37 | 39 | 185[.]244[.]210[.]65 |
| 10 | 89[.]44[.]198[.]16 | 40 | 185[.]244[.]210[.]120 |
| 11 | 89[.]44[.]198[.]189 | 41 | 192[.]36[.]57[.]181 |
| 12 | 89[.]44[.]198[.]196 | 42 | 192[.]210[.]137[.]35 |
| 13 | 96[.]44[.]159[.]46 | 43 | 194[.]4[.]49[.]6 |
| 14 | 103[.]20[.]222[.]218 | 44 | 194[.]32[.]78[.]183 |
| 15 | 103[.]27[.]132[.]69 | 45 | 205[.]234[.]232[.]196 |
| 16 | 103[.]51[.]140[.]101 | 46 | 207[.]148[.]74[.]250 |
| 17 | 103[.]114[.]200[.]230 | 47 | 212[.]193[.]2[.]48 |
| 18 | 103[.]119[.]3[.]230 | 48 | 213[.]156[.]138[.]68 |
| 19 | 103[.]125[.]218[.]198 | 49 | 213[.]156[.]138[.]77 |
| 20 | 104[.]156[.]232[.]22 | 50 | 213[.]156[.]138[.]78 |
| 21 | 107[.]148[.]19[.]88 | 51 | 216[.]155[.]157[.]136 |
| 22 | 107[.]172[.]16[.]208 | 52 | 216[.]238[.]66[.]251 |
| 23 | 107[.]173[.]140[.]111 | 53 | 216[.]238[.]71[.]49 |
| 24 | 121[.]37[.]174[.]139 | 54 | 216[.]238[.]72[.]201 |
| 25 | 121[.]227[.]168[.]69 | 55 | 216[.]238[.]74[.]95 |
| 26 | 131[.]196[.]252[.]148 | 56 | 216[.]238[.]75[.]155 |
| 27 | 139[.]162[.]135[.]12 | 57 | 216[.]238[.]81[.]149 |
| 28 | 149[.]28[.]166[.]244 | 58 | 216[.]238[.]85[.]220 |
| 29 | 152[.]70[.]83[.]47 | 59 | 216[.]238[.]86[.]24 |
| 30 | 154[.]22[.]235[.]13 | 60 | 154[.]22[.]235[.]17 |
