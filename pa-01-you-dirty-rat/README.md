# PA-01 — STRRAT C2 Detection Suite

![Operation PCAP Autopsy](https://img.shields.io/badge/Operation-PCAP_Autopsy-0D1117?style=for-the-badge)
![PA-01](https://img.shields.io/badge/PA--01-You_Dirty_Rat!-blue?style=for-the-badge)
![STRRAT](https://img.shields.io/badge/Malware-STRRAT-red?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-E95420?style=for-the-badge&logo=suricata&logoColor=white)
![Rules: 3 Validated](https://img.shields.io/badge/Rules-3_Validated-brightgreen?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-EF3B2D?style=for-the-badge)

**PCAP Source:** [malware-traffic-analysis.net — "You Dirty Rat!" (2024-07-30)](https://www.malware-traffic-analysis.net/2024/07/30/index.html)  
**Malware Family:** STRRAT (Java-based RAT)  
**Rules Engine:** Suricata 8.0.3  
**Validation:** PCAP replay — all rules confirmed firing  
**Author:** [cyberlandji.com](https://cyberlandji.com)

---

## Threat Summary

A Windows workstation was compromised by STRRAT, a Java-based Remote Access Trojan delivered via GitHub's content delivery network (objects.githubusercontent.com) — a Living Off Trusted Services (LOTS) technique. The malware pulled Java dependencies from Maven Central, performed automated GeoIP reconnaissance via ip-api.com, then established a persistent C2 session on port 12132 using Base64-encoded data over TCP. The operator conducted surveillance (Defender status, timezone, window logger) but did not escalate to exfiltration within the capture timeframe.

**Attribution note:** Malware was initially attributed to Remcos RAT during investigation based on behavioral similarity (window logger, Base64 C2, recon sequence). Walkthrough comparison and IDS signature analysis (`ET MALWARE STRRAT CnC Checking`) corrected this to STRRAT. The Java dependency chain observed during investigation was a clue that was not connected to attribution until after comparison. Behavioral detection rules remained valid despite misidentification.

---

## Detection Rules

### SID 1000001 — C2 Communication on Non-Standard Port

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 12132 (msg:"PA-01 - Outbound TCP to Non-Standard Port 12132 (Possible STRRAT C2)"; flow:established,to_server; threshold:type limit, track by_src, count 1, seconds 300; sid:1000001; rev:2;)
```

| Field | Value |
|-------|-------|
| Detects | Outbound established TCP connection to port 12132 |
| ATT&CK | T1571 — Non-Standard Port |
| Threshold | 1 alert per source IP per 5 minutes |
| False Positives | Legitimate services on port 12132 (rare) |
| Confidence | HIGH |

### SID 1000002 — Post-Infection GeoIP Reconnaissance

```
alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"PA-01 - Post-Infection Recon - GeoIP Lookup to ip-api.com"; http.host; content:"ip-api.com"; http.uri; content:"/json"; sid:1000002; rev:1;)
```

| Field | Value |
|-------|-------|
| Detects | HTTP request to ip-api.com/json (automated victim geolocation) |
| ATT&CK | T1016 — System Network Configuration Discovery |
| False Positives | Legitimate GeoIP lookups by applications (context matters) |
| Confidence | MEDIUM |

### SID 1000003 — Sustained C2 Beaconing Pattern

```
alert tcp $HOME_NET any -> $EXTERNAL_NET ![80,443,53,8080] (msg:"PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets)"; flow:established; dsize:<200; threshold:type both, track by_dst, count 20, seconds 60; sid:1000003; rev:2;)
```

| Field | Value |
|-------|-------|
| Detects | 20+ packets under 200 bytes to the same destination within 60 seconds on non-standard ports |
| ATT&CK | T1071 — Application Layer Protocol |
| False Positives | VPN keepalives, gaming traffic, IoT on non-standard ports |
| Confidence | MEDIUM — behavioral pattern, requires analyst triage |

---

## Validation Results

All rules validated via offline PCAP replay (`suricata -r <pcap> -S PA-01.rules -l ./output/`).

| SID | Alert Count | Target | Status |
|-----|-------------|--------|--------|
| 1000001 | 2 | 141.98.10.79:12132 | ✅ Validated |
| 1000002 | 1 | 208.95.112.1:80 | ✅ Validated |
| 1000003 | 8 | 141.98.10.79:12132 | ✅ Validated |

See [`validation/PA-01_validation-notes.md`](validation/PA-01_validation-notes.md) for the full testing arc including why the initial content-based rules failed and how they were rewritten as behavioral rules.

---

## Why Content Matching Failed — Detection Engineering Lesson

The original versions of SID 1000001 and 1000003 used content-based detection:

- SID 1000001 matched the literal string `"ping"` in small TCP payloads
- SID 1000003 used a regex to match Base64-encoded patterns

Both failed during PCAP replay. Diagnostic investigation (`grep "141.98" eve.json`) showed Suricata processed the C2 traffic but reported `"alerted":false` — the rules did not match.

**Root cause:** The Base64-encoded data and "ping" strings visible in Wireshark's "Follow TCP Stream" exist at the **application layer** after TCP reassembly. Suricata inspects **raw packet payloads**, where the same data is binary/encrypted. Content matching cannot detect encrypted or binary C2 protocols.

**Resolution:** Rules were rewritten to detect **behavior** instead of content — port usage, packet size patterns, and connection frequency. These behavioral indicators survive encryption, obfuscation, and even malware family misidentification.

```
❌ content:"ping"          → binary C2, string not present in raw packets
❌ pcre:"/Base64 regex/"   → encoding visible only after reassembly
✅ flow + port + dsize     → behavioral pattern, works on encrypted traffic
```

---

## IOCs

| Type | Value | Context |
|------|-------|---------|
| C2 IP | `141.98.10.79` | STRRAT C2 server |
| C2 Port | `12132/TCP` | Non-standard port |
| Recon IP | `208.95.112.1` | ip-api.com — automated GeoIP |
| Delivery | `objects.githubusercontent.com` | 852KB payload via HTTPS (LOTS) |
| Dependency | `repo1.maven.org` | Java component pull |
| JA3S | `fe7d83b83176171c12a6c4e35d6267e0` | C2 server TLS fingerprint |

Full IOC list: [`iocs/PA-01_IOCs.csv`](iocs/PA-01_IOCs.csv)

## MITRE ATT&CK

| ID | Technique | Evidence |
|----|-----------|----------|
| T1102 | Web Service | Payload hosted on GitHub (LOTS) |
| T1571 | Non-Standard Port | C2 on port 12132 |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over TCP, GeoIP over HTTP |
| T1132.001 | Data Encoding: Standard Encoding | Base64-encoded C2 data |
| T1016 | System Network Configuration Discovery | GeoIP lookup to ip-api.com |
| T1518.001 | Security Software Discovery | Defender status check |
| T1082 | System Information Discovery | Timezone check |
| T1010 | Application Window Discovery | Window logger surveillance |
| T1573 | Encrypted Channel | Payload delivery over HTTPS |

---

## Victim Context

| Field | Value |
|-------|-------|
| IP | 172.16.1.66 |
| Hostname | DESKTOP-SKBR25F |
| User | ccollier |
| Domain | wiresharkworkshop.online |

---

## References

- PCAP: [malware-traffic-analysis.net/2024/07/30](https://www.malware-traffic-analysis.net/2024/07/30/index.html)
- Walkthrough: Pavol Kluka — [A quick guide to analysing malicious network traffic](https://medium.com/@pavol.kluka/a-quick-guide-to-analysing-malicious-network-traffic-7b2c3ba819d6) (Medium)
- STRRAT: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/jar.strrat)
- MITRE ATT&CK: [attack.mitre.org](https://attack.mitre.org/)
