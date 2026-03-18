# PA-02 — Validation Notes

## Environment

- **Engine:** Suricata 8.0.3 RELEASE
- **PCAP:** 2026-01-31-traffic-analysis-exercise.pcap (51,181 packets, 26,423,689 bytes)
- **Ruleset:** PA-02.rules (13 custom rules)
- **Platform:** SOC STATION (Kali Linux VM, VMware Workstation)

## Validation Command

```bash
suricata -r ~/Downloads/2026-01-31-traffic-analysis-exercise.pcap -S ~/pcap-autopsy/PA-02/rules/PA-02.rules -l ~/pcap-autopsy/PA-02/output/
```

## Results: 12/13 Rules Firing

| SID | Layer | Target | Result | Notes |
|-----|-------|--------|--------|-------|
| 100001 | DNS | hiyter.com | ✅ FIRED | Initial beacon detected |
| 100002 | DNS | arch.filemegahab4.sbs | ✅ FIRED | Payload delivery detected |
| 100003 | DNS | media.megafilehub4.lat | ✅ FIRED | Payload delivery detected |
| 100004 | DNS | whooptm.cyou | ✅ FIRED | Staging/config detected |
| 100005 | DNS | whitepepper.su | ✅ FIRED | C2 domain — multiple hits throughout PCAP |
| 100006 | TLS SNI | hiyter.com | ❌ NO DETECTION | Expected — see explanation below |
| 100007 | TLS SNI | whooptm.cyou | ✅ FIRED | Staging connection confirmed |
| 100008 | TLS SNI | media.megafilehub4.lat | ✅ FIRED | Delivery connection confirmed |
| 100009 | TLS SNI | whitepepper.su | ✅ FIRED | Highest alert volume — every C2 TLS session |
| 100010 | JA3+SNI | whitepepper.su + JA3 | ✅ FIRED | Exfil module positively identified |
| 100011 | HTTP | whitepepper.su host | ✅ FIRED | HTTP C2 traffic confirmed |
| 100012 | HTTP | POST /api/set_agent | ✅ FIRED | Exfil POST pattern matched |
| 100013 | HTTP | Behavioral (no domain) | ✅ FIRED | Domain-agnostic detection confirmed |

## Rule 100006 — Documented Non-Detection

**Root cause:** hiyter.com is behind Cloudflare with Encrypted Client Hello (ECH). The TLS Client Hello SNI field displays `cloudflare-ech.com` instead of the actual domain name. This makes TLS SNI-based detection impossible for this specific domain.

**Compensating control:** DNS rule 100001 fired successfully for the same domain. The DNS query is plaintext and occurs before the TLS handshake, making it immune to ECH obfuscation.

**Conclusion:** This validates the layered detection strategy — when one detection layer is blind, another catches it. Rule 100006 is retained in the ruleset for environments where Cloudflare ECH is not in use.

## Troubleshooting — Parsing Errors (Fixed)

### Issue: Rules 100011 and 100012 failed to parse on first run

**Error message:**
```
E: detect-http-host: rule 100011: http.host keyword specified along with "nocase". The hostname buffer is normalized to lowercase, specifying nocase is redundant.
E: detect: error parsing signature...
```

**Root cause:** Suricata automatically normalizes the `http.host` buffer to lowercase. Adding `nocase` to a content match on this buffer is redundant and causes a parser conflict.

**Fix:** Removed `nocase` from all `http.host` content matches in rules 100011 and 100012.

**Lesson:** Know which Suricata sticky buffers auto-normalize. `http.host` normalizes to lowercase automatically. `dns.query` and `tls.sni` do not — they require explicit `nocase` for case-insensitive matching.

### First run: 10/13 rules firing (2 parsing errors + 1 expected non-detection)
### Second run: 12/13 rules firing (parsing errors fixed, 1 expected non-detection)
