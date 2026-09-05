# Cybersecurity Home Lab — DFIR \& CTI Focus

**Author:** Haris Dacić — [LinkedIn](https://www.linkedin.com/in/dacicharis/) · [TryHackMe](https://tryhackme.com/p/harisD)
**Focus areas:** Digital Forensics \& Incident Response · Cyber Threat Intelligence · SOC Operations

\---

## Why this exists

Most junior security portfolios list certifications and finished courses. This
one is different: it's a **fully self-built, self-documented security
laboratory** — network segmentation, a working SIEM, live purple-team
exercises, and detection engineering — built from two consumer PCs and
documented the way a real SOC team documents its work.

The same curiosity that drives this lab led to an independent OSINT
investigation that uncovered unsecured personal data on a Montenegrin
government web portal — formally confirmed and acted on by the national Data
Protection Agency (AZLP), resulting in a compliance inspection of two state
institutions. This lab is that same instinct, applied systematically.

\---

## Architecture

Two physically separate machines, deliberately split by role — a Blue Team
system and a Red Team system — connected only through the home network, to
keep the exercises realistic and the defensive side genuinely isolated.

```
┌─────────────────────────────────────────┐        ┌──────────────────────────┐
│  DESKTOP — Blue Team / SOC               │        │  LAPTOP — Red Team / CTI │
│  (Ryzen 7 3700X · 16GB · VMware WS Pro)  │        │  (i5 12th gen · VirtualBox)│
│                                           │        │                          │
│  ┌─────────────┐                         │        │  ┌────────────────────┐  │
│  │  pfSense CE  │  WAN (bridged) ─────────┼───home─┼─►│  Kali Linux        │  │
│  │  firewall/GW │                         │  network│  (attacker)         │  │
│  └──────┬───────┘                         │        │  └────────────────────┘  │
│         │ LAN 10.10.10.0/24               │        │  ┌────────────────────┐  │
│  ┌──────┴───────┐   ┌──────────────────┐  │        │  │  OpenCTI / MISP    │  │
│  │ Windows 11    │   │  Wazuh Manager   │  │        │  │  (planned)         │  │
│  │ target        │──►│  SIEM/XDR        │  │        │  └────────────────────┘  │
│  │ + Sysmon      │   │  + Dashboard     │  │        │                          │
│  └───────────────┘   └──────────────────┘  │        │                          │
└─────────────────────────────────────────┘        └──────────────────────────┘
```

*(Full diagram with IPs and NAT flow in* [*`network-diagrams/`*](./network-diagrams)*)*

![Homelab Network Topology](network-diagrams/homelab-topology.svg)

\---

## Stack

|Layer|Tools|
|-|-|
|Hypervisors|VMware Workstation Pro, Oracle VirtualBox|
|Network / Firewall|pfSense CE|
|SIEM / XDR|Wazuh (Indexer + Manager + Dashboard)|
|Endpoint telemetry|Sysmon (SwiftOnSecurity config)|
|Offensive tooling|Kali Linux, nmap, smbclient, enum4linux|
|CTI (in progress)|OpenCTI, MISP|
|SOAR (planned)|Shuffle|
|Infrastructure (in progress)|Docker, Kubernetes|

\---

## Repository structure

|Folder|Contents|
|-|-|
|[`dfir-writeups/`](./dfir-writeups)|Full incident-style reports for each purple team exercise — timeline, technical findings, detection analysis, root cause, recommendations|
|[`detection-rules/`](./detection-rules)|Custom Wazuh/Sigma detection rules written for specific attack patterns observed in this lab|
|[`network-diagrams/`](./network-diagrams)|Network topology and NAT/routing diagrams|
|[`cti-reports/`](./cti-reports)|Threat intelligence analyses (APT/malware campaigns) using OpenCTI/MISP|
|[`docs/`](./docs)|Lab build documentation and architecture notes|
|[`screenshots/`](./screenshots)|Supporting evidence referenced in writeups|

\---

## Exercises so far

|#|Title|Techniques|Status|
|-|-|-|-|
|01| [External SMB Exposure \& Detection](./dfir-writeups/01-external-smb-exposure-purple-team-exercise.md)|T1046 Network Service Scanning, T1021.002 SMB/Admin Shares, T1078 Valid Accounts|Complete|
|02| [SSH Brute-Force Attack Against Linux Target](dfir-writeups/02-ssh-bruteforce-linux-victim.md) | T1110 Brute Force, T1078 Valid Accounts | Complete |

More exercises are added as the lab grows — each one documented as a
standalone incident report, not just a log of commands run.

\---

## What's next

* \[x] Linux target with auditd, for cross-platform detection coverage
* \[ ] Additional attack scenarios (RDP brute-force, credential dumping)
* \[ ] Custom Wazuh rules tuned to reduce false positives from this specific environment
* \[ ] OpenCTI populated with real, public threat intel for analyst-style reporting
* \[ ] SOAR automation with Shuffle

\---

## Contact

Open to junior SOC / DFIR / CTI roles, remote or relocation.
[LinkedIn](#) · [TryHackMe profile](#)

