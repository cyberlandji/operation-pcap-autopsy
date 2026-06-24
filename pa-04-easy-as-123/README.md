# PA-04 — "Easy as 123"

![Malware](https://img.shields.io/badge/Malware-NetSupport%20Manager%20RAT-red)
![Tool Abuse](https://img.shields.io/badge/Tool%20Abuse-Legitimate%20RMM-orange)
![C2](https://img.shields.io/badge/C2-Plaintext%20HTTP%20on%20443-yellow)
![Rules](https://img.shields.io/badge/Suricata%20Rules-7%20validated-blue)
![Sigma](https://img.shields.io/badge/Sigma%20Rules-1%20deferred%20to%20PB--02-lightblue)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-4%20techniques-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Tools](https://img.shields.io/badge/Tools-Wireshark%20%7C%20Suricata%20%7C%20VirusTotal-lightgrey)

**Active Directory intrusion: NetSupport Manager RAT C2 in a noisy enterprise capture. Victim host fully profiled across ARP / NBNS / Kerberos / SAMR, then C2 isolated from heavy benign baseline. 7 Suricata detection rules validated, covering DNS, IP, HTTP signature, and behavioral layers. Initial access predates the capture window.**

---

## Environment

```
Domain:   EASYAS123 / easyas123.tech
DC/DNS/KDC: 10.2.28.2
Victim:   DESKTOP-TEYQ2NR (10.2.28.88, Intel 00:19:d1:b2:4d:ad)
User:     brolf (RID 1103, SID S-1-5-21-408266568-3947399335-3725113099-1103)
C2:       vadusa.xyz → 45.131.214.85 (plaintext HTTP on port 443)
```

---

## Investigation Arc

```
[Phase 1] Victim Identification
     ↓    ARP (gratuitous announcement) → host boots onto segment
     ↓    NBNS → hostname DESKTOP-TEYQ2NR + domain EASYAS123
     ↓    Kerberos AS-REQ → user brolf, realm EASYAS123, KDC 10.2.28.2
     ↓    SAMR → LookupNames(brolf)=RID 1103 → benign logon token-building
     ↓
[Phase 2] Baseline Cleared (high-noise capture)
     ↓    DHCP, ARP revalidation, AD DNS/SRV, SSDP, QUIC — benign
     ↓    armmf.adobe.com (0/92), g.live.com (0/91) — benign telemetry
     ↓    HTTP GET wall → Microsoft/Akamai update/cert noise — benign
     ↓
[Phase 3] C2 Establishment
     ↓    DNS vadusa.xyz → 45.131.214.85 (via internal DC/DNS)
     ↓    TCP handshake → first HTTP request is POST (already-resident client)
     ↓    NetSupport Manager/1.3 ↔ NetSupport Gateway/1.92
     ↓    Plaintext HTTP on 443, CMD= protocol, POST /fakeurl.htm
     ↓
[Phase 4] Channel-Content Analysis
     ↓    Setup burst (4 POSTs / ~0.8s) → steady ~60s idle keepalive beacon
     ↓    Uniform 286-byte encoded payload to end of capture
     ↓    No operator tasking / hands-on-keyboard observed in-window
     ↓
[Pre-capture] Initial access / delivery — NOT in capture window
```

---

## Detection Rules Summary

7 Suricata rules across 3 tiers, validated 7/7 against the original PCAP.

| Tier | Count | Coverage |
|------|-------|----------|
| IOC (brittle) | 3 | DNS `vadusa.xyz`, C2 IP `45.131.214.85`, URI `/fakeurl.htm` |
| Signature (tool family) | 2 | Client UA `NetSupport Manager`, Server banner `NetSupport Gateway` |
| Behavioral (durable) | 2 | `CMD=POLL/ENCD` command protocol in POST body; plaintext HTTP on port 443 (protocol/port anomaly) |

1 additional Sigma rule deferred to Operation Prism Box (PB-02): beacon-cadence correlation (~60s fixed-interval POST to a single destination — stateful, beyond Suricata's per-flow model).

### Rule Validation

- First run: 3/7 fired
- Failure: literal placeholder text left in 4 rule bodies → parse rejection at engine load (never tested against traffic)
- Final run: **7/7 fired** (1 iteration after cleanup)
- Key confirmation: Rule 3 fires despite the **absolute-form request URI** (`POST http://45.131.214.85/fakeurl.htm`) — Suricata normalizes the path into `http.uri`. Rule 5 fires on the reversed (server→client) direction for the response banner.

---

## MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|-----------|------|--------|
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1219 | Remote Access Software | Command and Control |
| T1132 | Data Encoding | Command and Control |
| T1571 | Non-Standard Port (protocol/port mismatch) | Command and Control |

*Pre-compromise techniques (initial access, execution) are out of scope — the infection predates the capture window.*

---

## Key Findings

- **Behavior decides, not the identifier** — the central lesson, hit four ways: a playful domain name (`EASYAS123` = the victim org, not the attacker), a "Phishing IOC" tag on a clean Adobe domain, a `-41` VirusTotal community score on a clean Microsoft domain, and "unusual" JA3 fingerprints from non-browser legit clients. Every alarming *label* was overridden by converging behavioral evidence.
- **Plaintext HTTP on port 443** — the C2 runs cleartext HTTP on the TLS port. Blends into expected outbound-443 traffic and dodges TLS-oriented inspection, but the unencrypted transport leaves the entire command protocol readable — confidentiality traded for blending. Generic, high-value behavioral detection.
- **POST-first = already-resident client** — the C2 stream opens with a POST (no preceding GET/retrieval), positively indicating the NetSupport client was on the host before the capture began. Delivery is out-of-window.
- **NetSupport is dual-use** — a legitimate RMM tool, heavily abused. The UA/Server banner alone is a *signature*, not a verdict (it fires on legit use too). The alert must key on behavior (external C2 destination, `CMD=` protocol, plaintext-on-443) and use the banner as *enrichment*. Identifier = context; behavior = trigger.
- **Encoded, not encrypted** — the steady-state `DATA=` payload is byte-for-byte identical across every beacon. That repetition is itself the tell: real encryption randomizes (IV/nonce), so identical output ⇒ reversible encoding, not cryptography. A fixed encoded keepalive token.
- **SAMR verdict from target, not timing** — the SAMR session resolved to `brolf` (RID 1103), the logged-in user → benign logon token-building. The verdict rests on *whose account was queried*, not on the activity being early in the capture.
- **The capture is a window, not the movie** — earliest observable malicious activity is the C2 beacon; the initial access happened before recording. Findings are bounded to what the capture contains.

---

## IOC Summary

| Type | Value |
|------|-------|
| Domain (C2) | `vadusa.xyz` |
| IP (C2) | `45.131.214.85` |
| URI | `/fakeurl.htm` |
| HTTP User-Agent | `NetSupport Manager/1.3` |
| HTTP Server banner | `NetSupport Gateway/1.92 (Windows NT)` |
| C2 protocol | `CMD=POLL` / `CMD=ENCD` key-value over HTTP POST |
| Behaviour | Plaintext HTTP on port 443; ~60s idle keepalive beacon |

Full IOC list: [`iocs/PA-04_IOCs.csv`](./iocs/PA-04_IOCs.csv)

---

## Structure

```
pa-04-easy-as-123/
├── iocs/
│   └── PA-04_IOCs.csv                     # Structured IOC list
├── rules/
│   ├── PA-04.rules                        # 7 validated Suricata rules
│   └── PA-04_sigma_backlog.md             # Beacon-cadence rule deferred to Prism Box
├── screenshots/
│   └── ...                                # Analysis + validation screenshots
├── validation/
│   └── PA-04_Rule_Validation.md           # Parse-fail → 7/7 fired
├── README.md                              # This file
└── lessons-learned.md                     # Key takeaways
```

---

## PCAP Autopsy Series

| Operation | Title | Malware Family | Rules | Key Lesson | Status |
|-----------|-------|---------------|-------|------------|--------|
| [PA-01](https://github.com/cyberlandji/operation-pcap-autopsy/tree/main/pa-01-you-dirty-rat) | You Dirty Rat! | STRRAT | 3 Suricata | Content-match fails on encrypted C2 — rewrite as behavioral | ✅ Complete |
| [PA-02](https://github.com/cyberlandji/operation-pcap-autopsy/tree/main/pa-02-lumma-in-the-room-ah) | Lumma in the Room-ah | Lumma Stealer | 13 Suricata | Cloudflare ECH defeats TLS SNI — layered detection required | ✅ Complete |
| [PA-03](https://github.com/cyberlandji/operation-pcap-autopsy/tree/main/pa-03-the-ghost-in-the-wire) | The Ghost in the Wire | GhostWeaver RAT | 16 Suricata + 3 Sigma | Empty SNI defeats TLS detection — DNS layer is critical. DGA requires behavioral rules beyond Suricata (Sigma). | ✅ Complete |
| **PA-04** | **Easy as 123** | **NetSupport Manager RAT** | **7 Suricata + 1 Sigma** | **Dual-use RMM abused as C2 — alert on behavior, not the tool banner. Plaintext HTTP on 443 is generic, durable detection. Capture is a window, not the movie.** | ✅ **Complete** |

---

## Author

**cyberlandji** — Blue Team Practitioner | ISC2 CC | CompTIA Security+ (in progress)

Portfolio: [cyberlandji.com](https://cyberlandji.com) · GitHub: [github.com/cyberlandji](https://github.com/cyberlandji)
