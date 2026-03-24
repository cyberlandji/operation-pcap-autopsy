# PA-03 — "The Ghost in the Wire"

![Malware](https://img.shields.io/badge/Malware-GhostWeaver%20RAT-red)
![Loader](https://img.shields.io/badge/Loader-MintsLoader-orange)
![Initial Access](https://img.shields.io/badge/Initial%20Access-KongTuke%20%2F%20ClickFix-yellow)
![Rules](https://img.shields.io/badge/Suricata%20Rules-16%20validated-blue)
![Sigma](https://img.shields.io/badge/Sigma%20Rules-3%20deferred%20to%20PB--02-lightblue)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-14%20techniques-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Tools](https://img.shields.io/badge/Tools-Wireshark%20%7C%20Suricata%20%7C%20CyberChef%20%7C%20VirusTotal-lightgrey)

**Multi-actor supply chain investigation: KongTuke → MintsLoader → GhostWeaver RAT. 6-stage attack chain reconstructed from packet-level analysis. 16 Suricata detection rules validated, covering DNS, TLS, HTTP, and TCP layers.**

---

## Supply Chain

```
KongTuke              →   MintsLoader            →   GhostWeaver RAT
(ClickFix lure)           (multi-stage loader)       (Python-based C2)
soulversr.com             finger.exe callback        DGA .top domains
                          main.ps1 / wgr.ps1         TLS 1.0 encrypted
                          AV enumeration             ~20,000 packets
                          conditional delivery        persistent session
```

---

## Detection Rules Summary

16 Suricata rules across 4 detection layers, validated 16/16 against the original PCAP.

| Layer | Count | Coverage |
|-------|-------|----------|
| DNS | 5 | All malicious domains (delivery, C2, DGA) |
| TLS | 2 | SNI for initial access, JA3 for C2 Python client |
| HTTP | 7 | Host matching, PowerShell UA, Werkzeug server, script file delivery, AV enumeration POST, DllImport payload |
| TCP | 2 | IP+port for primary C2, outbound FINGER protocol (port 79) — near-zero false positives |

3 additional Sigma rules identified but deferred to Operation Prism Box (PB-02): DGA NXDOMAIN rate, DNS entropy scoring, sequential IP lookup correlation.

### Rule Validation

- First run: 10/16 fired
- Failures: SNI not populated by malware, http.host strips port, http.server buffer unavailable, pcre missing delimiter, response header direction, alert tls without TLS keywords
- Final run: **16/16 fired** (3 iterations)

---

## Attack Chain

```
[Stage 0] soulversr.com (HTTPS) — ClickFix social engineering lure
     ↓
[Stage 1] finger.exe → 144.31.238.37:79 — Covert callback, no DNS, hardcoded IP
     ↓
[Stage 2a] PowerShell GET → 85.137.253.64:3456 — Downloads main.ps1 (recon)
     ↓
[Stage 2b] PowerShell POST /m — Reports "Windows Defender" → receives wgr.ps1
     ↓
[Stage 3] PowerShell GET → sbwur1.top:80 — Downloads GhostWeaver deployment script
     ↓    DllImport(user32.dll) + ShowWindowAsync + windowstyle hidden
     ↓
[Stage 4] DGA resolution → 4ec74y9kph5vko2.top → 173.232.146.62:25658
     ↓    TLS 1.2, Python client (JA3), 19,619 packets, persistent C2
     ↓
[Stage 5] Public IP recon — api.ipify.org + checkip.dyndns.org + ipinfo.io
     ↓
[Stage 6] Active operator session — tool deployment, no exfil/lateral movement observed
```

---

## MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|-----------|------|--------|
| T1189 | Drive-by Compromise | Initial Access |
| T1204.002 | User Execution: Malicious File | Execution |
| T1059.001 | PowerShell | Execution |
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1564.003 | Hide Artifacts: Hidden Window | Defense Evasion |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1518.001 | Security Software Discovery | Discovery |
| T1016 | System Network Configuration Discovery | Discovery |
| T1568.002 | Dynamic Resolution: DGA | Command and Control |
| T1071.001 | Application Layer Protocol: Web | Command and Control |
| T1573.002 | Encrypted Channel | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1132.001 | Data Encoding: Standard Encoding | Command and Control |

---

## Key Findings

- **ClickFix delivery blends in perfectly** — JA3/JA3S at Stage 0 match normal browser behavior. TLS fingerprinting useless at initial access. Detection surface limited to domain name only.
- **FINGER protocol as covert channel** — Legacy 1970s protocol (RFC 742/1288) abused for payload delivery. Windows ships finger.exe by default. Outbound port 79 = near-zero false positive detection opportunity.
- **Conditional payload delivery** — MintsLoader checks victim's AV software and delivers different payloads based on the result. Adaptive attacker behavior.
- **DGA for C2 resilience** — GhostWeaver uses Domain Generation Algorithm with .top TLD. 10+ NXDOMAIN attempts observed, 2 domains resolved (1 primary, 1 fallback unused).
- **Empty SNI defeats TLS detection** — Primary C2 does not populate SNI in Client Hello. Malware resolves domain via DNS then connects directly to IP. DNS-layer rules are the only domain-level detection for this C2.
- **Python-based RAT** — JA3 fingerprint identifies Python TLS library, not a browser. JA3 + JA3S combination uniquely fingerprints GhostWeaver C2 infrastructure.
- **TLS 1.0 = attacker OPSEC gap** — C2 uses TLS 1.0 instead of 1.3, exposing more handshake metadata for defenders.

---

## IOC Summary

| Type | Count |
|------|-------|
| Domains (malicious) | 3 (soulversr.com, sbwur1.top, gecdfcjcbcmmakk.top) |
| Domains (DGA — C2) | 2 resolved + 10 NXDOMAIN |
| IPs | 5 (144.31.238.37, 85.137.253.64, 64.52.80.153, 173.232.146.62, 45.61.136.186) |
| Ports | 3 (79, 3456, 25658) |
| JA3/JA3S | 2 hashes |
| Filenames | 2 (main.ps1, wgr.ps1) |
| Server headers | 2 (Werkzeug, QWaWQUF8cyFhydXhS) |

Full IOC list: [`iocs/PA-03_IOCs.csv`](./iocs/PA-03_IOCs.csv)

---

## Structure

```
pa-03-the-ghost-in-the-wire/
├── iocs/
│   └── PA-03_IOCs.csv                     # Structured IOC list (35 IOCs)
├── rules/
│   ├── PA-03.rules                        # 16 validated Suricata rules
│   └── PA-03_sigma_backlog.md             # 3 Sigma rules deferred to Prism Box
├── screenshots/
│   └── ...                                # Analysis + validation screenshots
├── validation/
│   └── PA-03_Rule_Validation.md           # Debug process: 10/16 → 16/16
├── README.md                              # This file
└── lessons-learned.md                     # Key takeaways
```

---

## PCAP Autopsy Series

| Operation | Title | Malware Family | Rules | Key Lesson | Status |
|-----------|-------|---------------|-------|------------|--------|
| [PA-01](https://github.com/cyberlandji/operation-pcap-autopsy/tree/main/pa-01-you-dirty-rat) | You Dirty Rat! | STRRAT | 3 Suricata | Content-match fails on encrypted C2 — rewrite as behavioral | ✅ Complete |
| [PA-02](https://github.com/cyberlandji/operation-pcap-autopsy/tree/main/pa-02-lumma-in-the-room-ah) | Lumma in the Room-ah | Lumma Stealer | 13 Suricata | Cloudflare ECH defeats TLS SNI — layered detection required | ✅ Complete |
| **PA-03** | **The Ghost in the Wire** | **GhostWeaver RAT** | **16 Suricata + 3 Sigma** | **Empty SNI defeats TLS detection — DNS layer is critical. DGA requires behavioral rules beyond Suricata (Sigma).** | ✅ **Complete** |

---

## Author

**cyberlandji** — Blue Team Practitioner | ISC2 CC | CompTIA Security+ (in progress)

Portfolio: [cyberlandji.com](https://cyberlandji.com) · GitHub: [github.com/cyberlandji](https://github.com/cyberlandji)
