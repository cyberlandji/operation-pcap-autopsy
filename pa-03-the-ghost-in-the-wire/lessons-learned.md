# PA-03 — Lessons Learned

## Operation: "The Ghost in the Wire"
## Malware: KongTuke → MintsLoader → GhostWeaver RAT

---

### 1. Empty SNI Defeats TLS Detection

The primary C2 (4ec74y9kph5vko2.top) resolved via DNS but did not populate the SNI field in the TLS Client Hello. The malware connected directly to the IP after DNS resolution. All TLS SNI-based rules were blind to this C2 connection.

**Takeaway:** Never assume SNI will be populated. DNS-layer rules are the only guaranteed domain-level detection when malware skips SNI. Always write DNS rules as backup for TLS rules.

---

### 2. DGA Requires SIEM-Level Detection

Domain Generation Algorithm behavior (high NXDOMAIN rate, entropy scoring) cannot be detected by Suricata's per-packet inspection. These patterns require counting and time-windowed correlation — Sigma rule territory.

**Takeaway:** PA-03 is the first operation to explicitly identify detection gaps that Suricata alone cannot fill. Three Sigma rules deferred to Operation Prism Box (PB-02). Suricata + SIEM is necessary for complete detection coverage.

---

### 3. FINGER Protocol = Best Behavioral Rule

Outbound port 79 from an internal host to an external IP has near-zero false positives. FINGER is a dead protocol — nobody uses it legitimately in production. This single rule fires before the attacker has a foothold, before any payload lands, before any C2 establishes.

**Takeaway:** The best detection rules target protocols and behaviors that have no legitimate business existing in a modern network. The rarer the protocol, the cleaner the signal.

---

### 4. Multi-Actor Supply Chains Multiply Detection Surface

KongTuke → MintsLoader → GhostWeaver means three different toolkits, three different coding styles, three different infrastructure choices. Each handoff between actors introduces a new detection opportunity because each actor makes different OPSEC decisions.

**Takeaway:** Complex attacks are harder to investigate but actually easier to detect — more stages mean more chances to catch them.

---

### 5. Conditional Payload Delivery Is Adaptive

MintsLoader checked the victim's AV status (Windows Defender) and delivered a different second-stage payload (wgr.ps1) based on the result. Writing a rule for "Windows Defender" only catches victims with Defender. The detection target should be the check-in protocol structure, not the AV product name.

**Takeaway:** Detect the technique (POST /m with message= body), not the content that varies per victim.

---

### 6. JA3 Tells You What Software Is Calling Out

The JA3 from the C2 connection identified a Python TLS library, not a browser. This confirmed GhostWeaver is Python-based before any malware analysis was performed. JA3 at Stage 0 (soulversr.com) matched a normal browser — confirming the victim browsed normally and ClickFix is a social engineering attack, not a technical exploit.

**Takeaway:** JA3 answers "what application made this connection?" — that's a different question from "what server responded?" (JA3S). Both are IOCs. JA3 is most useful when it reveals non-browser software making outbound connections.

---

### 7. TLS 1.2 Is an Attacker OPSEC Gap

The C2 server used TLS 1.2 instead of 1.3. TLS 1.3 hides more of the handshake metadata. Using TLS 1.2 exposed the Server Hello details, allowing JA3S fingerprinting. A well-configured attacker would use TLS 1.3 to reduce detection surface.

**Takeaway:** Not all attackers optimize their OPSEC. When they don't, exploit the gap.

---

### 8. Rule Debugging Is Part of the Process

First run: 10/16 rules fired. Six failures across three categories: attacker OPSEC (empty SNI), Suricata buffer behavior (http.host strips port, response header direction), and syntax discipline (pcre delimiter, alert tls needing keywords). Three iterations to reach 16/16.

**Takeaway:** Rules that don't fire teach you more than rules that do. Every failure revealed either an attacker technique or a Suricata behavior worth documenting.

---

### 9. Cleartext HTTP Is a Gift

Stages 2 and 3 used cleartext HTTP. Every payload, every header, every POST body was fully visible. This enabled content-based rules (DllImport, PowerShell UA, Werkzeug, .ps1 delivery, AV enumeration) that would be impossible if the attacker had used HTTPS.

**Takeaway:** Same lesson from PA-01 and PA-02 — when traffic is unencrypted, write rules for everything you can see. Content-based detection only works on cleartext.

---

### 10. The Motto Works

"Detect before the attacker is inside." Stage 0 (DNS to soulversr.com) and Stage 1 (port 79 FINGER) both fire before any payload lands on the victim. The investigation methodology (DNS → TCP → TLS → payload) held up against a 6-stage supply chain with three different actors.

**Takeaway:** The methodology developed across PA-01 and PA-02 scaled to PA-03's complexity without modification. It works.

---

### Cross-Operation Progression

| Lesson Area | PA-01 | PA-02 | PA-03 |
|-------------|-------|-------|-------|
| Encrypted C2 | Content-match fails on encrypted traffic | Cloudflare ECH defeats TLS SNI | Empty SNI defeats TLS detection |
| Detection approach | Behavioral port-based rules | Layered DNS + TLS SNI + HTTP content | DNS as critical backup + Sigma for DGA |
| Rule complexity | 3 simple rules | 13 rules across 3 layers | 16 rules across 4 layers + 3 Sigma |
| Investigation depth | Single-stage RAT | Multi-domain infostealer | Multi-actor supply chain |
| Key innovation | Rewriting content rules as behavioral | Kill chain stage labels in msg | Sigma backlog, rule debugging as documentation |

---

*PA-03 lessons learned — Operation PCAP Autopsy — cyberlandji*
