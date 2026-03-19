# 🔍 Operation PCAP Autopsy
## Detection-First PCAP Analysis — Real-World Malware Traffic

[![Series](https://img.shields.io/badge/series-Operation%20PCAP%20Autopsy-blue)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![Focus](https://img.shields.io/badge/focus-Detection%20Rule%20Development%20%26%20Network%20Forensics-teal)](https://github.com/cyberlandji/operation-pcap-autopsy)

[![Wireshark](https://img.shields.io/badge/tool-Wireshark-blue)](https://www.wireshark.org/)
[![Suricata](https://img.shields.io/badge/tool-Suricata-orange)](https://suricata.io/)
[![Linux](https://img.shields.io/badge/tool-Linux-yellow)](https://www.linux.org/)
[![Detection Engineering](https://img.shields.io/badge/skill-Detection%20Engineering-purple)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)

---

## 📌 Overview

Operation PCAP Autopsy is a detection-focused investigation series built on real-world malware traffic sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net).

Each operation targets a different malware family. The workflow is consistent: analyze the traffic, extract IOCs, map to MITRE ATT&CK, write Suricata detection rules based on observed behavior, and prove they fire. Every rule is validated on a dedicated SOC STATION via PCAP replay — not assumed to work.

This series complements Operation Iron Watch. Where Iron Watch proves I can build detection infrastructure, PCAP Autopsy proves I can investigate malicious traffic and write detections that actually catch it.

---

## 🎯 What This Series Covers

- PCAP-driven malware traffic analysis (Wireshark)
- IOC extraction and MITRE ATT&CK mapping
- Suricata detection rule writing and validation
- Behavioral detection design (encrypted C2 constraints)
- Content-match detection design (HTTP-based C2)
- JA3 TLS fingerprinting and correlation
- PCAP replay testing methodology
- Investigation documentation and analytical reasoning

---

## 📊 Series Table

| Exercise | Malware | Rules | Validated | Key Finding | Status |
|----------|---------|-------|-----------|-------------|--------|
| [PA-01: You Dirty Rat!](pa-01-you-dirty-rat) | STRRAT (Java-based RAT) | 3 | 3/3 | Encrypted C2 defeats content-match rules — behavioral detection required | ✅ Complete |
| [PA-02: Lumma in the Room-ah](pa-02-lumma-in-the-room-ah) | Lumma Stealer (infostealer) | 13 | 12/13 | Layered detection compensates when Cloudflare ECH blinds TLS inspection | ✅ Complete |

---

## 🔧 Methodology

Every operation follows the same repeatable workflow:

**Phase 1 — Orientation:** Open PCAP, identify victim (IP, hostname, user account, domain), note packet count and time span.

**Phase 2 — Traffic Analysis:** Identify infection vector, map C2 communications, extract artifacts, follow the kill chain from initial access to exfiltration.

**Phase 3 — IOC Extraction:** Compile malicious IPs, domains, URIs, hashes, User-Agents, JA3 fingerprints. Enrich via VirusTotal, AbuseIPDB, WHOIS.

**Phase 4 — ATT&CK Mapping:** Map every observed action to MITRE ATT&CK techniques. Only what can be proven from the traffic — not assumptions.

**Phase 5 — Detection Rule Writing:** Write Suricata rules targeting the observed behavior. Broad rules for coverage, precision rules for confidence.

**Phase 6 — Validation:** Replay the original PCAP through Suricata with custom rules. If it doesn't fire, it's not a detection — it's a guess.

---

## 📈 Series Progression

| Dimension | PA-01 (STRRAT) | PA-02 (Lumma Stealer) |
|-----------|----------------|----------------------|
| C2 Protocol | Base64 over raw TCP | HTTP POST over TLS |
| C2 Visibility | Encrypted — not inspectable | HTTP content visible |
| Rule Approach | Behavioral (port, size, frequency) | Content-match (URI, Host, method) |
| Infrastructure | Single C2 + LOTS delivery | Five-domain layered relay + Cloudflare |
| Operator Model | Manual — human operator | Automated — predefined routines |
| Key Lesson | Behavioral rules when content is encrypted | Content-match rules when C2 uses HTTP; DNS rules when TLS SNI is hidden |

---

## 🖥️ Lab Environment

| Component | Details |
|-----------|---------|
| SOC STATION | Dedicated Kali Linux VM (VMware Workstation) |
| Analysis Tools | Wireshark, tshark, CyberChef |
| Detection Engine | Suricata 8.0.3 |
| PCAP Source | [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) |

---

## 🔗 Links

- **Portfolio:** [cyberlandji.com](https://www.cyberlandji.com)
- **LinkedIn:** [linkedin.com/in/yohan-cedric-landji](https://www.linkedin.com/in/yohan-cedric-landji)
- **Iron Watch Series:** [github.com/cyberlandji](https://github.com/cyberlandji)

---

*Operation PCAP Autopsy — cyberlandji*
*I design, build, and validate detection systems — from architecture to alert.*
