# CTI Report #01: KrustyLoader — Rust-Based Second-Stage Loader Linked to Ivanti Connect Secure Zero-Day Exploitation

**TLP:CLEAR** · **Confidence:** Moderate (based on third-party OSINT, not independently verified in this lab) · **Date:** September 2026

## Executive Summary

This report analyzes **KrustyLoader**, a Rust-compiled second-stage malware loader first identified by security researcher Théo Letailleur (Synacktiv) during the mass exploitation of two Ivanti Connect Secure VPN zero-day vulnerabilities in January 2024. The purpose of this report is to translate a raw OpenCTI dataset — ingested into this lab's threat intelligence platform via the CIRCL OSINT MISP feed — into an analyst-style writeup: what the threat is, how it operated, which indicators are attributable to it, and what detection/response value this has for an organization exposed to internet-facing VPN appliances.

This is a retrospective analysis of a 2024 campaign, not a live incident observed in this lab. Its value here is demonstrating the analytical workflow this lab's CTI stack (OpenCTI + CIRCL feed) is built to support: ingest → correlate → interpret → produce actionable output, rather than leaving raw STIX objects unread in a database.

---

## Threat Overview

On **10 January 2024**, Ivanti disclosed two critical vulnerabilities affecting its Connect Secure VPN appliance:

| CVE | Type | Impact |
|---|---|---|
| **CVE-2023-46805** | Authentication bypass | Allows an unauthenticated attacker to access restricted admin resources |
| **CVE-2024-21887** | Command injection | Allows an authenticated attacker (or one who has already bypassed auth via the above) to execute arbitrary commands on the appliance |

Chained together, these two flaws gave attackers unauthenticated remote code execution against internet-facing Ivanti Connect Secure appliances — a high-value target class, since these devices sit at the network perimeter and often hold direct trust relationships into internal corporate networks.

Volexity and Mandiant both published incident response findings shortly after disclosure, documenting active, widespread exploitation in the wild prior to a patch being available (i.e., true zero-day exploitation). On 18 January 2024, Volexity's follow-up research identified previously unclassified Rust-compiled payloads being dropped on compromised appliances. Synacktiv's subsequent malware analysis is the first to name and technically document this payload as **KrustyLoader**.

---

## Technical Analysis

### Role in the attack chain

KrustyLoader is not the initial exploit — it is the **second-stage loader** delivered *after* successful exploitation of the Ivanti CVE pair. Its function is narrow and deliberate: establish a foothold on the compromised appliance and retrieve a further payload (public reporting on KrustyLoader, including Synacktiv's analysis, describes the follow-on payload as **Sliver**, an open-source, cross-platform command-and-control framework increasingly used as a Cobalt Strike substitute by intrusion sets; this specific detail is not contained in the ingested OpenCTI dataset and should be verified against the original Synacktiv publication before being relied upon).

### Notable characteristics observed in this dataset

* **Language/compilation:** Written in Rust and statically compiled — a deliberate choice that complicates both static signature detection (Rust binaries produce different byte patterns than the C/C++ malware most legacy AV signatures are tuned for) and reverse engineering (Rust's memory model and calling conventions differ meaningfully from the languages most RE tooling defaults to).
* **Filesystem staging:** The associated YARA rule (`Linux_Downloader_KrustyLoader`, authored by Synacktiv) flags use of the `/tmp/` directory for staging and a `TOKIO_WORKER_THREADS` string artifact — a direct fingerprint of Rust's async Tokio runtime being statically linked into the binary, an unusual and fairly distinctive artifact for this OS/architecture combination.
* **Self-referencing behavior:** The YARA rule also targets a byte pattern corresponding to the loader reading its own binary via `/proc/self/exe` — commonly used by malware to self-copy, verify its own hash, or re-exec itself after modifying its environment.
* **Deceptive file naming:** Files associated with this campaign in the dataset use names designed to blend into legitimate VPN appliance operation, e.g. `lastauthserverused.js` and `health.py` — names that would not draw analyst attention during a casual directory listing on the appliance.
* **Staging infrastructure:** Three Amazon S3 bucket URLs were used for payload hosting/staging (`book4timepublic.s3.amazonaws.com`, `blooming.s3.amazonaws.com`, `blaze-uk.s3.amazonaws.com`), each serving a single randomized-looking object path. Using legitimate cloud storage providers for payload delivery is a common technique to blend malicious traffic into normal cloud egress patterns and to survive basic domain-reputation blocklisting.
* **Volume of indicators:** The ingested dataset includes roughly 37 distinct file hash indicators (MD5/SHA-1/SHA-256) attributed to this campaign, plus three filename-only indicators. The large number of hashes is consistent with multiple payload variants or components, though the dataset itself does not state why.

---

## MITRE ATT&CK Mapping

Only **T1190** is present in the ingested OpenCTI dataset. The remaining techniques below are analyst-assigned, based on the behavior described in this report, and are not sourced from the CIRCL feed.

| Tactic | Technique | Relevance |
|---|---|---|
| Initial Access | **T1190** — Exploit Public-Facing Application | The Ivanti CVE pair is the entry vector; this is the single Attack Pattern object OpenCTI correlates across all ~50 entities in this dataset |
| Execution | **T1059** — Command and Scripting Interpreter | Post-exploitation command injection via CVE-2024-21887 |
| Defense Evasion | **T1027** — Obfuscated Files or Information | Rust compilation and deceptive file naming both serve this purpose |
| Command and Control | **T1071** — Application Layer Protocol | Use of legitimate cloud storage (S3) for staging blends C2/delivery traffic with normal HTTPS egress |
| Persistence / Access | **T1133** — External Remote Services | The compromised asset class (VPN appliances) is itself an externally exposed remote-access service |

---

## Detection Opportunities

Directly relevant to this lab's own stack:

1. **Perimeter/WAF layer (pfSense):** Since this campaign's initial access relies entirely on a specific pair of CVEs against a specific vendor appliance, the single highest-value control is patching — this is a case where detection engineering is a secondary control, not the primary one. Organizations running Ivanti Connect Secure should confirm patch status against CVE-2023-46805 / CVE-2024-21887 before investing in detection tuning for this specific loader.
2. **Network egress monitoring:** The use of S3 URLs for staging highlights a detection gap common to many perimeter setups — HTTPS traffic to `*.amazonaws.com` is rarely inspected or alerted on by default, since it is bulk legitimate traffic for most organizations. A SIEM rule correlating **new/rare S3 bucket subdomains contacted by a network appliance that does not normally initiate outbound web requests** (e.g., a VPN gateway) would have meaningfully higher signal than a generic "traffic to AWS" alert.
3. **File integrity monitoring:** The deceptive filenames (`health.py`, `lastauthserverused.js`) reinforce a lesson already documented in this lab's Windows/Linux FIM configuration (`syscheck` in the Wazuh agent config, see [`docs/windows-agent-integration/README.md`](../docs/windows-agent-integration/README.md)): legitimate-sounding filenames are a weak trust signal, and FIM baselines on network appliances (where feasible) or their management interfaces are more reliable than filename-based triage.
4. **Rust-binary specific tuning:** For organizations able to deploy EDR/YARA scanning against Linux-based network appliances, the `TOKIO_WORKER_THREADS` string and the `/proc/self/exe`-reading byte pattern documented in Synacktiv's public YARA rule are both durable, low-false-positive indicators specific to this loader family, since they stem from compiler/runtime choices rather than easily-changed strings.

---

## Recommendations

* **Patch management priority:** Any internet-facing Ivanti Connect Secure (or Policy Secure) appliance not yet patched against CVE-2023-46805/CVE-2024-21887 should be treated as a critical, time-sensitive finding — this is a well-documented, mass-exploited vulnerability pair with public IOCs, not a theoretical risk.
* **Assume compromise on delayed patching:** Because exploitation was active *before* patches were available, organizations that patched late should not treat patching alone as remediation — a compromise assessment (checking for the file/hash indicators in this report, and for outbound connections to AWS S3 from the appliance itself) is warranted.
* **Extend S3-staging detection logic beyond this campaign:** The broader technique (using major cloud storage providers to host payloads) is reusable by many threat actors beyond this specific intrusion set. The correlation logic proposed above (rare S3 subdomains contacted by infrastructure that shouldn't be making outbound web requests) has value independent of KrustyLoader specifically.

---

## Sources

* Synacktiv — KrustyLoader malware analysis (via CIRCL OSINT MISP feed, ingested into this lab's OpenCTI instance, 15 September 2026)
* Public vulnerability disclosures for CVE-2023-46805 and CVE-2024-21887 (Ivanti, January 2024)
* Volexity and Mandiant incident response publications on Ivanti Connect Secure exploitation (January 2024), as referenced in the ingested CIRCL dataset

> **Analyst note:** This report was produced entirely from indicator-level data (Indicator, StixFile, Url, Attack-Pattern, and Text STIX objects) ingested via this lab's CIRCL OSINT connector — the source MISP event itself contained no narrative report text, so the analysis, structure, and detection recommendations above are original work built on top of the raw IOC set, not a summary of an existing written report.

---

## Appendix: Selected Indicators

*(Full indicator set — roughly 37 file hashes — is available in the raw OpenCTI export; a representative sample is listed below. All indicators are TLP:CLEAR.)*

| Type | Value | Notes |
|---|---|---|
| URL | `http://book4timepublic.s3.amazonaws.com/gEsD2heW4crIT` | Staging/delivery |
| URL | `http://blooming.s3.amazonaws.com/Ea7fbW98CyM5O` | Staging/delivery |
| URL | `http://blaze-uk.s3.amazonaws.com/WymRvUz1HeRw3` | Staging/delivery |
| Filename | `lastauthserverused.js` | Deceptive naming, mimics legitimate appliance file |
| Filename | `health.py` | Deceptive naming |
| Filename | `category.py` | Deceptive naming |
| SHA-1 | `a19bdf4f7ccc68470c172e67ffe4a1bdef5d7bc4` | Associated payload |
| SHA-1 | `1bc9a9190b86d42f5c74735da669e76a5c7ff6fe` | Associated payload |
| SHA-1 | `8c7fdcd3a192a37bdbb8e6877a9b8e14c07dd8d5` | Associated payload |
| MD5 | `3045f5b3d355a9ab26ab6f44cc831a83` | Associated payload |
| MD5 | `63b0574cbe77d6231513f32e0d042484` | Associated payload |
| MD5 | `d0c7a334a4d9dcd3c6335ae13bee59ea` | Associated payload |
