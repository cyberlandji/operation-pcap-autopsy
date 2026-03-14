# PA-01 — Detection Rule Validation Notes

**Operation:** PA-01 — "You Dirty Rat!"  
**PCAP Source:** malware-traffic-analysis.net (2024-07-30)  
**Malware Family:** STRRAT (Java-based RAT)  
**Validation Date:** 2026-03-14  
**Validation Tool:** Suricata 8.0.3 (Kali Linux — SOC STATION VM)  
**Validation Method:** Offline PCAP replay with `-S` flag (custom rules only, no default ruleset)

---

## Validation Command

```bash
suricata -r ~/Downloads/2024-07-30-traffic-analysis-exercise.pcap \
  -S ~/pcap-autopsy/PA-01/rules/PA-01.rules \
  -l ~/pcap-autopsy/PA-01/output/
```

**Note:** Capital `-S` loads ONLY the specified rules file. Lowercase `-s` would add rules on top of the default ruleset, flooding output with noise.

**$HOME_NET configuration:** Default Suricata config includes `172.16.0.0/12`, which covers the victim IP `172.16.1.66`. No config changes required.

---

## Validation Results

### Round 1 — Initial Rules (Content-Based)

**Rules tested:**

| SID | Detection Logic | Result |
|-----|----------------|--------|
| 1000001 | `content:"ping"; dsize:<20;` on non-standard ports | **DID NOT FIRE** |
| 1000002 | `http.host:"ip-api.com"; http.uri:"/json"` | **FIRED** |
| 1000003 | `pcre:"/[A-Za-z0-9+\/]{20,}={1,2}/"; dsize:>20;` on non-standard ports | **DID NOT FIRE** |

**fast.log output (Round 1):**
```
07/30/2024-04:40:07.011358  [**] [1:1000002:1] Possible Post-Infection Recon - GeoIP Lookup to ip-api.com [**] [Classification: (null)] [Priority: 3] {TCP} 172.16.1.66:49755 -> 208.95.112.1:80
```

**Diagnosis:** Used `grep "141.98" eve.json` to check if Suricata saw the C2 traffic. Result: flow record present with `"alerted":false`, confirming Suricata processed the traffic but rules did not match.

**Root cause:** The C2 traffic on port 12132 is binary/encrypted at the packet level. The literal string "ping" and the Base64 patterns visible in Wireshark's "Follow TCP Stream" view exist at the application layer after TCP reassembly — they are NOT present as raw ASCII in individual packets. Suricata inspects raw packet payloads, not reassembled application-layer data.

**Key lesson:** Content-match rules (`content:`, `pcre:`) cannot detect encrypted or binary C2 protocols. Detection must use behavioral indicators: port, flow pattern, packet size, connection frequency.

### Round 2 — Behavioral Rules

Rules rewritten to detect behavior instead of content:

| SID | Detection Logic | Result |
|-----|----------------|--------|
| 1000001 (rev:2) | `flow:established,to_server` on port 12132 | **FIRED** |
| 1000002 (rev:1) | `http.host:"ip-api.com"; http.uri:"/json"` (unchanged) | **FIRED** |
| 1000003 (rev:2) | `flow:established; dsize:<200;` threshold 20/60s on non-standard ports | **DID NOT FIRE** |

**Diagnosis for SID 1000003:** Flow data showed `bytes_toserver:27990` across `pkts_toserver:205` = ~136 bytes average per packet. The `dsize:<50` threshold was too restrictive — most packets exceeded 50 bytes.

### Round 3 — Adjusted Threshold (Option A: dsize:<200)

| SID | Detection Logic | Result |
|-----|----------------|--------|
| 1000001 (rev:2) | Port 12132 behavioral | **FIRED** (2 alerts — threshold limit working) |
| 1000002 (rev:1) | GeoIP recon | **FIRED** (1 alert) |
| 1000003 (rev:2) | dsize:<200, threshold 20/60s | **FIRED** (8 alerts — sustained beacon detection) |

**fast.log output (Round 3 — Final):**
```
07/30/2024-04:40:07.011358  [**] [1:1000002:1] Possible Post-Infection Recon - GeoIP Lookup to ip-api.com [**] [Classification: (null)] [Priority: 3] {TCP} 172.16.1.66:49755 -> 208.95.112.1:80
07/30/2024-04:40:07.026826  [**] [1:1000001:2] PA-01 - Outbound TCP to Non-Standard Port 12132 (Possible STRRAT C2) [**] [Classification: (null)] [Priority: 3] {TCP} 172.16.1.66:49754 -> 141.98.10.79:12132
07/30/2024-04:40:53.703161  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] [Classification: (null)] [Priority: 3] {TCP} 172.16.1.66:49754 -> 141.98.10.79:12132
07/30/2024-04:41:53.829783  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
07/30/2024-04:43:54.085404  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
07/30/2024-04:44:54.211813  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
07/30/2024-04:45:09.243797  [**] [1:1000001:2] PA-01 - Outbound TCP to Non-Standard Port 12132 (Possible STRRAT C2) [**] ...
07/30/2024-04:45:54.354605  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
07/30/2024-04:46:54.449540  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
07/30/2024-04:47:54.544693  [**] [1:1000003:2] PA-01 - Sustained C2 Session on Non-Standard Port (Small Packets) [**] ...
```

**ALL THREE RULES VALIDATED.**

---

## Malware Family Correction

During the investigation, the malware was initially identified as **Remcos RAT** based on behavioral similarity (window logger, Base64-encoded C2 data, recon sequence). Comparison with the published walkthrough (Pavol Kluka, Medium) and the malware-traffic-analysis.net answer key revealed the malware is actually **STRRAT** — a Java-based RAT.

**Evidence that supports STRRAT over Remcos:**
- Maven repository pull (`repo1.maven.org`) — Java dependency, consistent with Java-based malware
- Oracle Java download (`javadl-esd-secure.oracle.com`) — Java runtime component
- IDS signature match: `ET MALWARE STRRAT CnC Checking` (from Zui/Brim analysis in walkthrough)

**Impact on detection rules:** None. All three rules use behavioral detection (port, protocol pattern, packet size) — not malware family-specific content. The rules fire correctly regardless of whether the malware is STRRAT, Remcos, or any other RAT exhibiting similar C2 behavior. Only the `msg` strings were updated.

**Key takeaway:** Behavioral analysis correctly identified RAT activity and C2 patterns. Malware family attribution requires additional evidence beyond behavioral analysis alone (IDS signatures, payload analysis, OSINT cross-referencing). Behavioral detection rules survive malware misidentification because they detect what the malware *does*, not what it *is*.

---

## Detection Engineering Lessons

1. **Content matching fails on encrypted/binary C2.** Wireshark's "Follow TCP Stream" shows reassembled application-layer data. Suricata sees raw packets. If the protocol is binary or encrypted, `content:` and `pcre:` keywords will never match.

2. **Behavioral detection is more resilient.** Port-based, size-based, and frequency-based rules survive encryption, obfuscation, and even malware family misidentification.

3. **dsize thresholds must be calibrated against real traffic.** The initial dsize:<50 was too restrictive. Checking actual packet sizes from flow data (`bytes_toserver / pkts_toserver`) before writing size-based rules prevents wasted iterations.

4. **PCAP replay is the only way to validate.** Without replay testing, the first two rules would have been published untested and non-functional. The replay caught the failure immediately.

5. **Validation failures are more valuable than first-try successes.** The debugging process (content rules fail → investigate why → discover binary C2 → rewrite as behavioral → validate) produced deeper understanding than working rules would have.
