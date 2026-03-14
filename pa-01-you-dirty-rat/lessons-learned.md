# PA-01 — Lessons Learned (Walkthrough Comparison)

**Operation:** PA-01 — "You Dirty Rat!"  
**PCAP Source:** malware-traffic-analysis.net (2024-07-30)  
**Answer Key:** malware-traffic-analysis.net published answers  
**Walkthrough Reference:** Pavol Kluka — "A quick guide to analysing malicious network traffic" (Medium)

---

## What I Got Right

- **Victim identification:** IP (172.16.1.66), hostname (DESKTOP-SKBR25F), user account (ccollier), domain (wiresharkworkshop.online) — all correct
- **C2 server identification:** 141.98.10.79 on port 12132 — correct
- **GeoIP recon detection:** ip-api.com lookup identified as malware-initiated, not user-initiated — correct
- **C2 activity analysis:** Keepalive pings, Defender status check, timezone check, window logger — all correctly identified
- **Base64 encoding:** Recognized and decoded C2 data encoding — correct
- **No exfiltration conclusion:** Correctly assessed that only surveillance occurred within capture timeframe
- **Infection vector direction:** Identified objects.githubusercontent.com and repo1.maven.org as delivery mechanism (LOTS — Living Off Trusted Services) — correct behavioral assessment

## What I Got Wrong

### Malware Family Misidentification: Remcos vs STRRAT

**My assessment:** Remcos RAT — based on window logger behavior, Base64-encoded C2 data, and recon command sequence  
**Actual malware:** STRRAT — a Java-based RAT

**Why the mistake happened:** I attributed based on behavioral similarity alone. Window logging, Base64 encoding, GeoIP recon, and keepalive patterns are common across many RAT families. Without running IDS signatures (Suricata/Snort with ET rules) or performing deeper payload analysis, behavioral overlap between RAT families made accurate attribution impossible from network traffic alone.

**What the walkthrough used that I didn't:** Zui/Brim with Suricata signatures — immediately flagged `ET MALWARE STRRAT CnC Checking`. The IDS signature database contains family-specific patterns that behavioral analysis alone cannot replicate.

**The Java clues I saw but didn't connect:**
- `repo1.maven.org` — Java dependency repository (I noticed it but didn't connect it to a Java-based RAT)
- `javadl-esd-secure.oracle.com` — Oracle Java download
- These should have been a strong signal toward a Java-based malware family

**Lesson:** Behavioral analysis identifies *what* malware does. Family attribution requires *how* it does it — which means IDS signatures, payload hashes, or OSINT cross-referencing. For future operations, run the PCAP through Suricata with the full ET ruleset first to get family attribution, then validate with behavioral analysis.

## What I Would Do Differently Next Time

1. **Run Suricata with full ET ruleset first** — get IDS signature hits before starting manual analysis. This provides malware family attribution immediately and guides deeper investigation.
2. **Pay closer attention to dependency pulls** — Maven/Java downloads from a non-developer workstation should have been a stronger signal.
3. **Cross-reference behavioral patterns with multiple RAT families** — don't attribute to the first matching family. Check if multiple families share the same behavior.
4. **Use Zui/Brim as a triage tool** — the walkthrough demonstrated how effective it is for rapid identification before diving into Wireshark.
5. **Write content-based rules last, behavioral rules first** — the debugging process proved behavioral rules are more reliable for encrypted C2. Start there.

## Impact on Detection Rules

**None.** All three validated rules use behavioral detection — port, protocol pattern, packet size. They fire correctly regardless of malware family. This is actually a strength: the rules detect RAT C2 behavior generically, not STRRAT specifically. They would also catch Remcos or any other RAT using the same C2 pattern.

---

*PA-01 lessons learned — Operation PCAP Autopsy — cyberlandji*
