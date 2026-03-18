# PA-02 — Indicators of Compromise

**Malware Family:** Lumma Stealer (infostealer)
**PCAP Date:** 2026.01.31
**Confidence levels:** HIGH = confirmed via multiple evidence sources | MEDIUM = assessed via behavioral analysis or single source

---

## Network IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| C2 IP | 153.92.1.49 | Lumma Stealer C2 server — Golang-based, exfil via /api/set_agent | HIGH |
| C2 Port | 80 | HTTP POST exfiltration | HIGH |
| C2 Domain | whitepepper.su | .su TLD — triggered ET MALWARE Lumma Stealer alert | HIGH |
| Beacon IP | 104.21.22.231 | hiyter.com — initial beacon (Cloudflare) | HIGH |
| Delivery IP | 104.21.48.156 | media.megafilehub4.lat — payload delivery (Cloudflare) | HIGH |
| Delivery IP | 104.17.25.14 | arch.filemegahab4.sbs — payload delivery redundancy (Cloudflare) | HIGH |
| Staging IP | 62.72.32.156 | whooptm.cyou — staging/config server | HIGH |

## Delivery IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| Domain | hiyter.com | Initial beacon — Cloudflare-fronted, ECH hides SNI | HIGH |
| Domain | media.megafilehub4.lat | Payload delivery — Cloudflare-fronted | HIGH |
| Domain | arch.filemegahab4.sbs | Payload delivery redundancy — Cloudflare-fronted | HIGH |
| Domain | whooptm.cyou | Staging/config — direct IP, no CDN | HIGH |

## Protocol IOCs

| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| C2 URI | /api/set_agent?id= | Bot check-in and data exfiltration endpoint | HIGH |
| C2 Bot ID | 3BF62053625378BE4C0ADF174C | Unique bot identifier — victim-specific | HIGH |
| C2 Token | 842e2802df0fa0684ed51f12f4387e761523b | Authentication token — victim-specific | HIGH |
| Content-Type | application/x-www-form-urlencoded | Exfil POST body format (8–10KB per POST) | HIGH |
| User-Agent | Chrome/144.0.0.0 | Spoofed/outdated — Lumma HTTP client fingerprint | HIGH |
| JA3 (exfil) | 966876ab31aa46bd3378db27b35b8d56 | TLS fingerprint of exfil module (2nd C2 session) | HIGH |
| JA3 (check-in) | [documented separately] | TLS fingerprint of check-in module (1st C2 session) | MEDIUM |

## Victim (Internal — Not for Blocklisting)

| Field | Value |
|-------|-------|
| IP | 10.1.21.58 |
| Hostname | DESKTOP-ES9F3ML |
| User | gwyatt |
| Full Name | Gabriel Wyatt |
| Domain | win11office.com |

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|----|-----------|----------|
| T1189 | Drive-by Compromise | Initial access over HTTPS — assessed, not confirmed |
| T1204.002 | User Execution: Malicious File | Execution occurred but mechanism not visible in PCAP |
| T1090.004 | Proxy: Domain Fronting | Delivery domains behind Cloudflare ECH |
| T1036 | Masquerading | Spoofed User-Agent: Chrome/144.0.0.0 |
| T1082 | System Information Discovery | Browser fingerprint data (fonts) in POST body |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST to /api/set_agent |
| T1104 | Multi-Stage Channels | Two JA3 fingerprints — check-in vs exfil sessions |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS used for all C2 connections |
| T1020 | Automated Exfiltration | Repeating POST requests with no operator interaction |
| T1041 | Exfiltration Over C2 Channel | Stolen data sent via same HTTP channel as C2 |

> **Note:** Delivery domains use disposable TLDs (.lat, .sbs, .cyou, .su) and are designed to rotate rapidly. IOC-based blocklisting alone is insufficient — behavioral detection via Suricata rules (see `rules/PA-02.rules`) provides more durable coverage. Detection should focus on behavioral patterns post-download, not the delivery domain itself.
