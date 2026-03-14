# PA-01 — Indicators of Compromise

**Malware Family:** STRRAT (Java-based RAT)  
**PCAP Date:** 2024-07-30  
**Confidence levels:** HIGH = confirmed via multiple evidence sources | MEDIUM = assessed via behavioral analysis or single source

---

## Network IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| C2 IP | `141.98.10.79` | STRRAT C2 server — operator recon + surveillance | HIGH |
| C2 Port | `12132/TCP` | Non-standard port used for C2 | HIGH |
| Recon IP | `208.95.112.1` | ip-api.com — automated GeoIP fingerprinting | HIGH |
| JA3S Hash | `fe7d83b83176171c12a6c4e35d6267e0` | C2 server TLS fingerprint | HIGH |

## Delivery IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| Domain | `objects.githubusercontent.com` | 852KB payload download over HTTPS (LOTS) | HIGH |
| Domain | `github.com` | Hosting platform abused for payload delivery | HIGH |
| Domain | `repo1.maven.org` | Maven Central — Java dependency pull | MEDIUM |
| Domain | `javadl-esd-secure.oracle.com` | Oracle Java runtime component | MEDIUM |

## Protocol IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| C2 Protocol | Base64-encoded data over TCP | Obfuscated C2 on port 12132 | HIGH |
| Payload Size | ~852KB | Consistent with packed Java RAT binary | MEDIUM |

## Victim (Internal — Not for Blocklisting)

| Field | Value |
|-------|-------|
| IP | `172.16.1.66` |
| Hostname | `DESKTOP-SKBR25F` |
| User | `ccollier` |
| Domain | `wiresharkworkshop.online` |

---

## MITRE ATT&CK Mapping

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

**Note:** Delivery domains (github.com, maven.org) are legitimate services abused for hosting — do not blocklist. Detection should focus on behavioral patterns post-download, not the delivery domain itself.
