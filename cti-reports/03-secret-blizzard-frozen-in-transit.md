# CTI Report #03: Frozen in Transit — Secret Blizzard's ISP-Level AiTM Campaign Against Diplomats

**TLP:CLEAR** · **Confidence:** Moderate (third-party OSINT, not independently verified in this lab) · **Date:** September 2026

## Executive Summary

This report analyzes a cyberespionage campaign disclosed by Microsoft Threat Intelligence in July 2025, in which the Russian state-sponsored actor **Secret Blizzard** (also known as Turla) used an adversary-in-the-middle (AiTM) position at the internet-service-provider level inside Russia to deploy custom malware, **ApolloShadow**, against foreign embassies in Moscow. The source material is a MISP event ingested into this lab's OpenCTI instance through the CIRCL OSINT feed: an Intrusion Set, one domain, one IP address, 24 file-hash observables, and four ready-to-use Microsoft Sentinel/Defender hunting queries.

This is the first report in this lab's series where a cross-check against the primary source did not just add context — it found a material mismatch between what the vendor published and what the ingested dataset actually contains. That finding, and what it means for trusting a CDB list or detection rule built from CTI without checking it first, is the main technical contribution of this report.

This is a retrospective analysis. No AiTM position, ISP-level intercept, or embassy network exists in this lab, and no activity from this campaign was observed here.

---

## Threat Overview

Secret Blizzard is attributed by the U.S. Cybersecurity and Infrastructure Security Agency to Russia's Federal Security Service (Center 16), and is more widely known under the alias **Turla** — the same threat actor referenced in the OpenCTI Intrusion-Set object for this report, with further aliases including Venomous Bear, Uroburos, Snake, Waterbug, and Krypton. Per MITRE ATT&CK, the group has operated since at least 2004 against government, embassy, military, and research targets in more than 50 countries.

The campaign covered by this report is notable for where the interception happens rather than for the malware itself. Microsoft assessed that Secret Blizzard achieved, for the first time confirmed, an AiTM position at the **ISP/telecom level inside Russia**, likely enabled by Russia's lawful-intercept infrastructure. Diplomatic personnel connecting through a local Russian internet or telecom provider were redirected through a captive portal — the same mechanism used at hotel or airport Wi-Fi — and from there to attacker infrastructure that delivered ApolloShadow, disguised as a Kaspersky Anti-Virus root-certificate installer.

Once installed, ApolloShadow's function is less about the payload and more about **enabling everything after it**: it installs a rogue trusted root certificate (allowing TLS interception of the target's own traffic), sets the network profile to "Private" to relax host firewall rules, and creates a persistent local administrator account (`UpdatusUser`) with a non-expiring, hardcoded password. Microsoft did not observe direct lateral movement in this campaign, but assessed these changes as most plausibly intended to reduce the difficulty of lateral movement later.

---

## Technical Analysis

### Infection chain

The chain begins outside the malware itself, at the network layer: a target device behind Secret Blizzard's AiTM position has its routine connectivity check (Windows' built-in Test Connectivity Status Indicator, which normally just confirms internet access) redirected to a captive portal instead of completing normally. From there the browser is redirected again, to an attacker-controlled domain presenting a certificate error, which prompts the user to download and run a file disguised as a Kaspersky installer (`CertificateDB.exe` per Microsoft's published IOC table — not present in the ingested dataset, see Data Quality Findings below).

ApolloShadow branches its behavior based on whether it is already running with an elevated token:

- **Low-privilege path:** it enumerates the host's local IP configuration, Base64-encodes it twice, and exfiltrates it inside a GET request that mimics a legitimate DigiCert timestamp-service URL. Because the request is issued from behind the actor's AiTM position, it can be silently redirected to attacker infrastructure and answered with an obfuscated VBScript second-stage payload, without the attacker needing a real DigiCert compromise.
- **Elevation:** the malware re-launches itself via a Windows API call that triggers a standard UAC prompt, asking the user to approve changes from an app named `CertificateDB.exe`. If approved, it proceeds to the elevated path.
- **Elevated-privilege path:** it installs two root/CA certificates from temporary files using the built-in `certutil` utility, then writes a Firefox-specific preference file so Firefox (which does not use the Windows certificate store by default) also trusts them. It then relaxes host network posture two ways — changing the `NetworkList` registry profile for each connected network to "Private" (taking effect after reboot), and directly toggling Windows Firewall rule groups for Network Discovery and File and Printer Sharing via COM objects (taking effect immediately) — before creating the persistent `UpdatusUser` administrator account.

Throughout, ApolloShadow obfuscates internal strings with XOR against hardcoded constants, decoding them only at the point of use and re-encoding them afterward — a lightweight but functional technique for frustrating quick static analysis.

### Data quality findings

Cross-checking the ingested dataset against Microsoft's own published IOC table turned up a more significant discrepancy than in either prior report in this series:

**The domain and IP match exactly** (`kav-certificates.info`, `45.61.149.109`) — no issue there.

**The file hashes do not.** Microsoft's blog post publishes exactly two SHA-256 hashes for ApolloShadow, plus the display name `CertificateDB.exe`. The ingested dataset instead contains **24 file-hash observables covering 8 distinct files** (each represented as MD5, SHA-1, and SHA-256). Checking programmatically:

- Only **one** of Microsoft's two published SHA-256 hashes (`13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20`) appears in the dataset at all.
- Microsoft's **second** published hash is **absent** from the dataset entirely.
- The dataset's other **7 file hash sets are not published anywhere in Microsoft's blog** — their provenance is unknown from this dataset alone. They may be automated "related sample" enrichment from a threat-intel platform (a common connector behavior), but nothing in the export identifies them as such or attributes them to a source.
- `CertificateDB.exe` itself is not present in the dataset as a filename indicator.

There is also a smaller, familiar-shaped issue: one Indicator object encodes the single Microsoft-confirmed hash **twice** — correctly as a SHA-256 file-hash pattern, and a second time as a `file:name` pattern using the hash string itself as if it were a filename. This is the same class of ingestion artifact noted in Reports #01 and #02 (a MISP attribute converted into an indicator using the wrong field), just manifesting differently here.

**Practical consequence:** of the 8 distinct file samples in this dataset, only 1 can currently be attributed to this campaign with confidence, because only 1 is confirmed against the primary source. The other 7 should be treated as **unverified** until corroborated elsewhere (for example, against VirusTotal detections, a YARA rule match, or a second public report), not as confirmed ApolloShadow samples. This report's appendix marks the confirmed hash separately from the rest for exactly this reason.

Separately, of the 23 Text-type objects in the export, 4 are genuinely useful — real Microsoft Sentinel ASIM hunting queries (see Detection Opportunities) — while the remaining 19 are noise: PE section names (`.rsrc`, `.data`, `.text`, `.reloc`, `.pdata`, `.rdata`), the string `exe`, GeoIP database provenance strings, an ASN name, a country name, and source labels like "Blog" and "Microsoft Defender XDR". This is the same MISP-attribute-as-indicator pattern already documented in Reports #01 and #02, and it means the "23 Text indicators" figure a raw entity count would suggest is misleading without this breakdown.

---

## MITRE ATT&CK Mapping

No Attack Pattern object is present in the ingested OpenCTI dataset for this report — a gap, given how central the AiTM technique is to the campaign's significance. The row below is drawn directly from Microsoft's own blog post, which explicitly links the technique to MITRE's page for it, rather than being analyst-inferred from the malware's general behavior.

| Tactic | Technique | Source |
|---|---|---|
| Credential Access, Collection | **T1557** — Adversary-in-the-Middle | Microsoft's original publication (not in the ingested dataset) |
| Defense Evasion | **T1553.004** — Subvert Trust Controls: Install Root Certificate | Analyst-assigned, from the malware's certificate-installation behavior described above |
| Persistence | **T1136.001** — Create Account: Local Account | Analyst-assigned, from the `UpdatusUser` account creation described above |
| Defense Evasion | **T1562.004** — Impair Defenses: Disable or Modify System Firewall | Analyst-assigned, from the firewall-rule and network-profile changes described above |

T1557 is a current, non-deprecated technique in the present MITRE ATT&CK release (verified 22 September 2026); it is worth noting that ArcaneDoor (CTI Report #02) is also listed by MITRE as a documented procedure example for this same technique, at the network-device layer rather than the ISP layer.

---

## Detection Opportunities

1. **Deploy the vendor-published hunting queries as-is.** Unusually for this lab's CTI reports, the ingested dataset includes four working Microsoft Sentinel ASIM queries (network-session, web-session, and file-event variants) that check the confirmed domain, IP, and single confirmed hash against telemetry. These do not need to be written from scratch — they need a workspace to run in, which this lab does not have (no Sentinel deployment), so this is recorded as a capability gap rather than exercised here.
2. **Extend the pfSense → Wazuh CDB pipeline** (built for CTI Report #02) with the confirmed IP from this campaign. *(Implemented.)* Rules 100024/100025 match the confirmed IP (`45.61.149.109`) against pfSense firewall logs. Because pfSense's `filterlog` format does not carry DNS query names, the confirmed domain (`kav-certificates.info`) is not matched by this pipeline; that would need a DNS-log source this lab does not currently collect. See [Rules 100024/100025](../detection-rules/100024-100025-secretblizzard-cdb-correlation.md).
3. **Do not build detection content against the 7 unverified file hashes** without first corroborating them independently. Loading them into a CDB list or YARA rule at the same confidence as the one Microsoft-confirmed hash would repeat, at smaller scale, the same category of mistake this report's Data Quality Findings section identifies.
4. **Certificate-store and firewall-posture monitoring.** Because ApolloShadow's persistence mechanism relies on `certutil` root-store modification and Windows Firewall rule-group toggling rather than a novel technique, existing detections for unexpected `certutil -addstore` execution or firewall rule changes via COM (already a reasonable target for Sysmon/Windows event monitoring) would likely have generic value against this technique family, not just this specific campaign.

---

## Recommendations

* **Attribute the unconfirmed hashes before acting on them.** Seven of the eight file samples in this dataset cannot currently be tied to Microsoft's public reporting. Treat them as candidates for further validation, not as actionable ApolloShadow IOCs.
* **Prefer the vendor's own hunting content when it is provided.** The four ASIM queries in this dataset are higher-value than the raw indicator list alone, and reduce the risk of an analyst re-deriving detection logic imperfectly from IOCs when the vendor has already published working logic.
* **Treat the domain and IP as the highest-confidence indicators in this dataset**, since both are independently confirmed against Microsoft's own IOC table with no ambiguity.
* **For any organization operating in Russia:** Microsoft's own top recommendation — routing traffic through an encrypted tunnel to infrastructure not controlled by a local ISP — is the most direct mitigation for an ISP-level AiTM position, since standard endpoint or network hardening cannot address interception happening upstream of both.

---

## Sources

* Microsoft Threat Intelligence, "Frozen in transit: Secret Blizzard's AiTM campaign against diplomats" (31 July 2025): https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/ — primary source, used to verify all IOCs, the infection chain, and the MITRE technique mapping in this report
* CIRCL OSINT MISP feed, as ingested into this lab's OpenCTI instance on 20 September 2026
* MITRE ATT&CK, Turla (G0010) and T1557 (Adversary-in-the-Middle) group/technique pages, checked 22 September 2026

> **Analyst note:** The ingested MISP event contained an Intrusion Set, one domain, one IP address, 24 file-hash observables, and four Sentinel/Defender hunting queries, but no Attack Pattern object and no narrative campaign analysis. The infection-chain summary is drawn from Microsoft's own published blog, paraphrased rather than quoted. The data-quality cross-check — comparing the ingested hashes against Microsoft's published IOC table — is original verification work performed for this report, not present in the dataset itself. The MITRE mapping's single dataset-independent row (T1557) is drawn directly from Microsoft's publication rather than inferred; the remaining three rows are analyst-assigned from the described malware behavior and are not confirmed by either the dataset or Microsoft's own ATT&CK tagging for this report.

---

## Appendix: Indicators

*All indicators are TLP:CLEAR.*

**Network indicators — confirmed against Microsoft's published IOC table:**

| Indicator | Type | Description |
|---|---|---|
| kav-certificates[.]info | Domain | Actor-controlled domain, delivers ApolloShadow |
| 45[.]61[.]149[.]109 | IPv4 | Actor-controlled IP address |

**File hash — confirmed against Microsoft's published IOC table:**

| SHA-256 | SHA-1 | MD5 |
|---|---|---|
| 13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20 | 60f2c0932b114e99eb81e1ace478b5f5d0fa4d27 | 9587f236e40b9581bd7084f68c83b14b |

**File hashes — present in the ingested dataset, NOT found in Microsoft's published IOC table (unverified; see Data Quality Findings):**

| # | SHA-256 |
|---|---|
| 1 | af5a9ec8881f3c17e909bba8083309a6f960b786d81770dd5ef52bbb1f19ffbd |
| 2 | 0a40e81744d3133766dd74a52c66106ee8afeaa8ce3ad8c8644eea2cd3d52d1c |
| 3 | 7dbf5dcea0b582bead47e024e5a1b0506265a1c07c70b6a053e89b1e60156e8d |
| 4 | dd72350864b15b6c9f7aba96b684fb64221f739c11315077b30077f3e70066e3 |
| 5 | c6cd32408bcaeee92ddf99653ae5f2ec380b7a7e90e8b1ccebb6a9ec72807cdd |
| 6 | e6be7b3fa94419af6744391b2bae63169a408e09353f35d8b1fe00fff05e8bec |
| 7 | 0431e7e6741272791142debbd3a9971a72d2f8d9705dcad9c9af73365aa44929 |

*(Each of the 7 rows above also has a corresponding SHA-1 and MD5 value in the raw export; omitted here since none of the three hash types for these 7 files could be confirmed against the primary source.)*

**Microsoft-published indicator NOT found in the ingested dataset:**

| Indicator | Type |
|---|---|
| e94c00fde5bf749ae6db980eff492859d22cacb4bc941ad4ad047dca26fd5616 | SHA-256 |
| CertificateDB.exe | File name |
