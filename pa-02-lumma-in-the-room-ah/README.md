# 🔍 PA-02 — "Lumma in the Room-ah"
## Lumma Stealer — Layered Infrastructure & Content-Match Detection

[![Status](https://img.shields.io/badge/status-complete-brightgreen)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![Malware](https://img.shields.io/badge/malware-Lumma%20Stealer-red)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![Rules](https://img.shields.io/badge/suricata%20rules-13-blue)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![Validated](https://img.shields.io/badge/validated-12%2F13%20firing-brightgreen)](https://github.com/cyberlandji/operation-pcap-autopsy)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-10%20techniques-orange)](https://github.com/cyberlandji/operation-pcap-autopsy)

---

## 📌 Overview

PA-02 investigates a **Lumma Stealer** infection identified on a Windows workstation. The malware operated through a **five-domain layered infrastructure** — three Cloudflare-fronted delivery domains, one staging server, and one direct C2 server — to exfiltrate browser credentials, cookies, and system fingerprint data via HTTP POST requests.

This operation was deliberately chosen because Lumma's HTTP-based exfiltration allows **content-match Suricata rules** — the opposite of PA-01 (STRRAT) where encrypted C2 forced behavioral-only detection. Together, the two operations demonstrate that a detection engineer must master both approaches.

**Key investigation findings:**
- Cloudflare Encrypted Client Hello (ECH) hides delivery domains from TLS inspection — DNS is the only reliable detection layer
- Two-phase C2 connection pattern with distinct JA3 fingerprints (check-in vs exfil module)
- Automated exfiltration of browser fingerprints, credentials, and session tokens via `/api/set_agent`

---

## 🎯 Detection Rules Summary

13 Suricata rules across 3 detection layers — **12/13 validated against source PCAP.**

| Layer | Rules | Coverage |
|-------|-------|----------|
| DNS | 5 rules (SID 100001–100005) | All 5 malicious domains — earliest detection point |
| TLS SNI + JA3 | 5 rules (SID 100006–100010) | Domain confirmation + JA3 exfil module correlation |
| HTTP Content | 3 rules (SID 100011–100013) | C2 host match, POST /api/set_agent, behavioral (domain-agnostic) |

**Rule 100006 (TLS SNI for hiyter.com) — documented non-detection.** Cloudflare ECH hides the real domain in the SNI field. DNS rule 100001 compensates — validating the layered detection approach.

---

## 🏗️ Kill Chain

```
[?] INITIAL ACCESS — HTTPS redirect (not visible in PCAP)
     Assessed: Drive-by compromise (T1189) — HIGH CONFIDENCE
 ↓
[✓] INITIAL BEACON — hiyter.com (104.21.22.231 / Cloudflare)
     ~45s — DNS query + TLS handshake, SNI hidden by ECH
 ↓
[✓] PAYLOAD DELIVERY — media.megafilehub4.lat + arch.filemegahab4.sbs
     ~45-48s — Both Cloudflare-fronted, redundant delivery
 ↓
[✓] STAGING/CONFIG — whooptm.cyou (62.72.32.156)
     ~90s — Direct IP, no CDN
 ↓
[✓] C2 EXFILTRATION — whitepepper.su (153.92.1.49)
     ~92s — Golang C2, HTTP POST to /api/set_agent
     Two JA3 fingerprints: check-in session + exfil session
     Automated browser credential & fingerprint theft
```

---

## 🖥️ Victim Details

| Detail | Value |
|--------|-------|
| IP Address | 10.1.21.58 |
| MAC Address | 00:21:5d:c8:0e:f2 |
| Hostname | DESKTOP-ES9F3ML |
| User Account | gwyatt |
| Full Name | Gabriel Wyatt |

---

## 🔗 Infrastructure

| Domain | IP | Role | Infrastructure |
|--------|-----|------|----------------|
| hiyter.com | 104.21.22.231 | Initial beacon | Cloudflare (ECH) |
| media.megafilehub4.lat | 104.21.48.156 | Payload delivery | Cloudflare |
| arch.filemegahab4.sbs | 104.17.25.14 | Payload delivery (redundancy) | Cloudflare |
| whooptm.cyou | 62.72.32.156 | Staging/config | Direct |
| whitepepper.su | 153.92.1.49 | C2 exfiltration | Direct |

---

## 🧬 MITRE ATT&CK Mapping

| Tactic | Technique | Name | Confidence |
|--------|-----------|------|------------|
| Initial Access | T1189 | Drive-by Compromise | HIGH — assessed |
| Execution | T1204.002 | User Execution: Malicious File | LOW — endpoint data required |
| Defense Evasion | T1090.004 | Proxy: Domain Fronting | CONFIRMED |
| Defense Evasion | T1036 | Masquerading | CONFIRMED |
| Discovery | T1082 | System Information Discovery | CONFIRMED |
| Command & Control | T1071.001 | Web Protocols | CONFIRMED |
| Command & Control | T1104 | Multi-Stage Channels | CONFIRMED |
| Command & Control | T1573.002 | Encrypted Channel | CONFIRMED |
| Exfiltration | T1020 | Automated Exfiltration | CONFIRMED |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | CONFIRMED |

---

## 📊 Validation Results

| SID | Layer | Target | Result |
|-----|-------|--------|--------|
| 100001 | DNS | hiyter.com | ✅ |
| 100002 | DNS | arch.filemegahab4.sbs | ✅ |
| 100003 | DNS | media.megafilehub4.lat | ✅ |
| 100004 | DNS | whooptm.cyou | ✅ |
| 100005 | DNS | whitepepper.su | ✅ |
| 100006 | TLS SNI | hiyter.com | ❌ Expected — ECH |
| 100007 | TLS SNI | whooptm.cyou | ✅ |
| 100008 | TLS SNI | media.megafilehub4.lat | ✅ |
| 100009 | TLS SNI | whitepepper.su | ✅ |
| 100010 | JA3+SNI | whitepepper.su + JA3 | ✅ |
| 100011 | HTTP | whitepepper.su host | ✅ |
| 100012 | HTTP | POST /api/set_agent | ✅ |
| 100013 | HTTP | Behavioral (no domain) | ✅ |

---

## 🔧 Troubleshooting

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| Rules 100011/100012 parsing error | `nocase` on `http.host` — Suricata auto-normalizes, making `nocase` redundant | Removed `nocase` from `http.host` content matches |
| Rule 100006 no detection | Cloudflare ECH hides real domain in TLS SNI | Documented as expected; DNS rule 100001 compensates |

---

## 📂 Folder Structure

```
pa-02-lumma-in-the-room-ah/
├── README.md                          # This file
├── rules/
│   └── PA-02.rules                    # 13 Suricata rules (DNS + TLS + HTTP)
├── iocs/
│   └── PA-02_IOCs.csv                 # Structured IOC export
├── validation/
│   └── screenshots/                   # fast.log validation evidence
├── report/
│   └── PA-02_Final_Investigation_Report.md
└── lessons-learned.md                 # Key concepts & series progression
```

---

## 📈 PA-01 vs PA-02 — Series Progression

| Dimension | PA-01 (STRRAT) | PA-02 (Lumma Stealer) |
|-----------|----------------|----------------------|
| C2 Protocol | Base64 over raw TCP | HTTP POST over TLS |
| C2 Visibility | Encrypted — content not inspectable | HTTP content visible |
| Rule Approach | Behavioral (port, size, frequency) | Content-match (URI, Host, method) |
| Infrastructure | Single C2 + LOTS delivery | Five-domain layered relay + Cloudflare |
| Operator Model | Manual — human operator | Automated — predefined routines |
| Key Lesson | Behavioral rules when content is encrypted | Content-match rules when C2 uses HTTP; DNS rules when TLS SNI is hidden |

---

## 🔗 Series Table

| Exercise | Focus | Rules | Status |
|----------|-------|-------|--------|
| [PA-01: You Dirty Rat!](../pa-01-you-dirty-rat) | STRRAT — behavioral Suricata rules | 3 | ✅ Complete |
| **PA-02: Lumma in the Room-ah** | **Lumma Stealer — content-match + layered detection** | **13** | **✅ Complete** |

---

## 🔗 Links

- **Source PCAP:** [malware-traffic-analysis.net — 2026-01-31](https://www.malware-traffic-analysis.net/2026/01/31/index.html)
- **Portfolio:** [cyberlandji.com](https://www.cyberlandji.com)
- **Full Report:** [PA-02 Final Investigation Report](report/PA-02_Final_Investigation_Report.md)

---

*Operation PCAP Autopsy — cyberlandji*
*I design, build, and validate detection systems — from architecture to alert.*
