# Operation PCAP Autopsy — Detection Rule Development

![Operation PCAP Autopsy](https://img.shields.io/badge/Operation-PCAP_Autopsy-0D1117?style=for-the-badge)
![Phase: Detection Engineering](https://img.shields.io/badge/Phase-Detection_Engineering-blueviolet?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-E95420?style=for-the-badge&logo=suricata&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-EF3B2D?style=for-the-badge)

Detection rules written, validated, and documented from real-world malicious network traffic. Each operation takes a PCAP containing actual malware activity, reconstructs the attack chain, and produces **tested Suricata rules** with proof they fire against the original traffic.

**Author:** [cyberlandji.com](https://cyberlandji.com) — [GitHub](https://github.com/cyberlandji)

---

## Methodology

```
Investigate → Identify detectable behavior → Write rules → Replay PCAP → Validate → Document
```

Every rule in this repository has been validated via offline PCAP replay using Suricata with the `-S` flag (custom rules only, no default ruleset). If a rule is in this repo, it fires. Validation evidence is included for each operation.

---

## Operations

| Operation | Malware | Rules | Engine | Status |
|-----------|---------|-------|--------|--------|
| [PA-01](pa-01-you-dirty-rat/) | STRRAT (Java RAT) | 3 Suricata | Suricata 8.0.3 | ✅ Validated |

---

## Repository Structure

```
operation-pcap-autopsy/
├── README.md                          ← You are here
├── PA-01_you-dirty-rat/
│   ├── README.md                      ← Detection-focused write-up
│   ├── rules/
│   │   └── PA-01.rules                ← Validated Suricata rules
│   ├── validation/
│   │   ├── PA-01_validation-notes.md  ← Testing methodology + debugging arc
│   │   └── screenshots/               ← Proof of rule firing
│   ├── iocs/
│   │   └── PA-01_IOCs.csv             ← Structured IOC export
│   └── lessons-learned.md             ← Walkthrough comparison + corrections
├── PA-02_.../
│   └── ...
└── templates/
    └── ...
```

Each operation produces:
- Validated detection rules (Suricata, Sigma when applicable)
- PCAP replay validation evidence
- Structured IOC list
- MITRE ATT&CK mapping
- Lessons learned from walkthrough comparison

---

## PCAP Sources

PCAPs are **never uploaded** to this repository. Sources are linked in each operation's README.

- Primary: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)
- Secondary: [CyberDefenders](https://cyberdefenders.org/)

---

## Tools

| Tool | Purpose |
|------|---------|
| Wireshark / tshark | Traffic analysis, stream reconstruction, TLS fingerprinting |
| Suricata | Detection rule engine, offline PCAP replay for validation |
| CyberChef | Data decoding (Base64, hex, XOR) |
| VirusTotal | IOC enrichment and reputation |
| Zui / Brim | Rapid triage with IDS signature matching |

---

## About

I design, build, and validate detection systems — from architecture to alert. This repository demonstrates detection rule development through real-world network forensics.

Other projects:
- [Operation Iron Watch](https://github.com/cyberlandji/operation-iron-watch) — SOC detection pipeline (Suricata + Graylog SIEM)
- [cyberlandji.com](https://cyberlandji.com) — Portfolio
