# PA-03 — Rule Validation: Errors and Fixes

## First Run Results: 10/16 rules fired

| SID | Status | Issue |
|-----|--------|-------|
| 100001 | ✅ Fired | — |
| 100002 | ✅ Fired | — |
| 100003 | ✅ Fired | — |
| 100004 | ✅ Fired | — |
| 100005 | ✅ Fired | — |
| 100006 | ✅ Fired | — |
| 100007 | ❌ Silent | SNI field empty — malware connected to IP without populating SNI |
| 100008 | ❌ Silent | Same issue — no SNI in Client Hello |
| 100009 | ❌ Silent | http.host buffer strips port number |
| 100010 | ✅ Fired | — |
| 100011 | ✅ Fired | — |
| 100012 | ❌ Silent | http.server may not be a valid sticky buffer in this Suricata version |
| 100013 | ❌ Parse error | Missing opening delimiter in pcre |
| 100014 | ✅ Fired | — |
| 100015 | ✅ Fired | — |
| 100016 | ✅ Fired | — |

---

## Error Analysis and Fixes

### SID 100007 & 100008 — TLS SNI Not Populated

**What happened:**
The DGA domain (4ec74y9kph5vko2.top) was resolved via DNS, but when the malware established the TLS connection to 173.232.146.62, it did NOT populate the Server Name Indication (SNI) field in the Client Hello. The SNI field was empty.

**Why:**
The malware resolved the domain to get the IP, then connected directly to the IP address. It had no reason to include the domain name in SNI because the C2 server doesn't need SNI-based virtual hosting — it's a dedicated C2 server, not a shared web host. This is also an OPSEC technique — empty SNI defeats TLS SNI-based detection rules.

**Verification:**
Wireshark filter: `tls.handshake.type == 1 and ip.addr == 173.232.146.62`
Check the Client Hello → Extensions → server_name. If absent or empty, SNI is not populated.

**Lesson learned:**
Never assume SNI will be populated. Malware that resolves domains via DNS then connects to the IP directly will bypass all SNI-based rules. This is why DNS-layer detection (rules 100001-100005) is critical — the domain name is ONLY visible at the DNS layer for this type of connection.

**Fix for 100008 — Replace SNI match with destination IP:**

Before (broken):
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - TLS SNI to 4ec74y9kph5vko2.top (C2 - DGA Primary)"; tls.sni; content:"4ec74y9kph5vko2.top"; nocase; sid:100008; rev:1;)
```

After (fixed):
```
alert tls $HOME_NET any -> 173.232.146.62 any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - TLS to 173.232.146.62 (C2 - DGA Primary - port 25658)"; sid:100008; rev:2;)
```

Note: This becomes IOC-specific — tied to this IP. Less durable but functional for this campaign.

**Fix for 100007 — Replace SNI+JA3 with JA3 alone:**

Before (broken):
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - JA3 + SNI correlation to 4ec74y9kph5vko2.top (C2 - DGA Primary)"; tls.sni; content:"4ec74y9kph5vko2.top"; nocase; ja3.hash; content:"07af4aa9e4d215a5ee63f9a0a277fbe3"; sid:100007; rev:1;)
```

After (fixed):
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - JA3 + IP correlation to 173.232.146.62 (C2 - DGA Primary - port 25658)"; ja3.hash; content:"07af4aa9e4d215a5ee63f9a0a277fbe3"; sid:100007; rev:2;)
```

Note: JA3 alone is more behavioral — survives IP rotation because it detects the Python TLS client library. Higher false positive risk but more durable.

**Detection Engineering takeaway:**
For C2 that doesn't populate SNI, your detection layers are:
1. DNS query rules (domain visible in cleartext DNS — always works)
2. JA3 fingerprint (identifies the client software regardless of destination)
3. Destination IP (IOC-specific, dies with infrastructure rotation)
4. Behavioral: TLS on non-standard port (port 25658 is inherently suspicious)

SNI-based detection is powerful but NOT guaranteed. Always have DNS-layer rules as backup.

---

### SID 100009 — http.host Buffer Strips Port Number

**What happened:**
The rule matched on `content:"85.137.253.64:3456"` but Suricata's `http.host` sticky buffer contains ONLY the hostname/IP — it strips the port number. The buffer contained `85.137.253.64`, not `85.137.253.64:3456`.

**Why:**
Suricata parses the HTTP Host header and separates the host from the port internally. The `http.host` buffer only exposes the host portion. This is by design — it allows rules to match hosts regardless of what port the HTTP connection uses.

**Verification:**
Check Suricata documentation for `http.host` — it explicitly states the port is excluded from the buffer.

**Lesson learned:**
Never include port numbers in `http.host` content matches. The port is part of the connection metadata, not the host buffer.

**Fix:**

Before (broken):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - host 85.137.253.64:3456 (loader/stager)"; http.host; content:"85.137.253.64:3456"; sid:100009; rev:1;)
```

After (fixed):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - host 85.137.253.64 (loader/stager - port 3456)"; http.host; content:"85.137.253.64"; sid:100009; rev:2;)
```

Port documented in msg for analyst awareness but removed from content match.

---

### SID 100012 — http.server Not a Valid Sticky Buffer

**What happened:**
The rule used `http.server` as a sticky buffer, but this keyword may not be recognized as a valid sticky buffer in the installed Suricata version. Suricata silently ignored the rule or failed to match.

**Why:**
Not all HTTP header fields have dedicated sticky buffers in Suricata. While `http.host`, `http.uri`, `http.user_agent` are well-established, `http.server` may not be available in all versions. When Suricata encounters an unrecognized keyword, the rule either fails to load or never matches.

**Fix — Use generic http.header buffer instead:**

Before (broken):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - server (loader/stager)"; http.server; content:"Werkzeug"; sid:100012; rev:1;)
```

After (fixed):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - Werkzeug server header (loader/stager)"; http.header; content:"Server"; content:"Werkzeug"; sid:100012; rev:2;)
```

Note: `http.header` is a generic buffer that covers ALL HTTP headers. By matching both `content:"Server"` and `content:"Werkzeug"`, the rule fires when the Server header contains "Werkzeug". This approach works across all Suricata versions.

**Lesson learned:**
When in doubt about whether a specific sticky buffer exists, fall back to `http.header` with multiple content matches. Always verify available keywords against the Suricata documentation for your installed version.

---

### SID 100013 — Missing PCRE Opening Delimiter

**What happened:**
Suricata threw a parse error and refused to load the rule. The error points to the pcre pattern.

**Why:**
PCRE in Suricata requires the pattern enclosed between delimiters: `/pattern/flags`. The opening `/` was missing.

```
Written:   pcre:"filename=\s*.*?\.(ps1|bat|vbs|hta|psm1)/Ri"
                 ^ missing opening delimiter

Required:  pcre:"/filename=\s*.*?\.(ps1|bat|vbs|hta|psm1)/Ri"
                 ^ must start with /
```

Without the opening delimiter, Suricata cannot determine where the pattern starts and where the flags are. The entire pcre is unparseable.

**Lesson learned:**
PCRE syntax in Suricata is always: `pcre:"/PATTERN/FLAGS";`
- Opening `/` before the pattern — REQUIRED
- Closing `/` after the pattern — REQUIRED
- Flags after the closing `/` — optional but common (R = relative, i = case-insensitive)
- The whole thing in double quotes — REQUIRED
- Terminated with semicolon — REQUIRED

**Fix:**

Before (parse error):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/Ghostweaver - Content-Disposition (loader/stager)"; http.header;content:"Content-Disposition|3a|"; pcre:"filename=\s*.*?\.(ps1|bat|vbs|hta|psm1)/Ri"; classtype:policy-violation ; sid:100013; rev:1;)
```

After (fixed):
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PA-03 - KongTuke/MintsLoader/GhostWeaver - Content-Disposition script file delivery (loader/stager)"; http.header; content:"Content-Disposition"; pcre:"/filename=\s*.*?\.(ps1|bat|vbs|hta|psm1)/Ri"; classtype:policy-violation; sid:100013; rev:2;)
```

Changes made:
1. Added missing `/` before `filename` in pcre
2. Added space after `http.header;`
3. Removed `|3a|` (hex for colon) from Content-Disposition — unnecessary, Suricata matches the header name without it
4. Removed extra space before `classtype`

---

## Summary of Fixes

| SID | Root Cause | Fix Applied | Type of Lesson |
|-----|-----------|-------------|----------------|
| 100007 | SNI not populated by malware | Replaced SNI+JA3 with JA3-only | Attacker OPSEC awareness |
| 100008 | SNI not populated by malware | Replaced SNI match with destination IP | Attacker OPSEC awareness |
| 100009 | http.host strips port number | Removed `:3456` from content match | Suricata buffer behavior |
| 100012 | http.server not valid in all versions | Replaced with http.header + dual content match | Suricata keyword compatibility |
| 100013 | Missing pcre opening delimiter `/` | Added `/` before pattern | Syntax discipline |

---

## Key Lessons for Future Rule Writing

1. **Never assume SNI is populated.** Malware that resolves DNS then connects to IP directly bypasses SNI. Always have DNS-layer rules as backup.
2. **Know what each Suricata buffer contains.** `http.host` strips ports. `http.uri` includes the path and query. Read the docs for each buffer before writing content matches.
3. **When in doubt, use generic buffers.** `http.header` covers all headers. `http.response_body` covers all response content. Specific sticky buffers are cleaner but not always available.
4. **PCRE delimiters are non-negotiable.** Always `/pattern/flags`. Missing either delimiter = parse error.
5. **Failures are findings.** Rules 100007/100008 failing taught you about empty SNI as an attacker OPSEC technique. That's a lesson you carry into every future investigation.

---

*PA-03 rule validation notes — Operation PCAP Autopsy — cyberlandji*
