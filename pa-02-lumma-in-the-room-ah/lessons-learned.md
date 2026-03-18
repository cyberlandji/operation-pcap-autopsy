# PA-02 — Lessons Learned

## PA-01 vs PA-02 — Series Progression

| Dimension | PA-01 (STRRAT) | PA-02 (Lumma Stealer) |
|-----------|----------------|----------------------|
| C2 Protocol | Base64-encoded over raw TCP (port 12132) | HTTP POST over TLS (port 443/80) |
| C2 Visibility | Encrypted — content not inspectable | HTTP content visible — form data extractable |
| Rule Approach | Behavioral (port, packet size, frequency) | Content-match (URI path, Host header, method) |
| Infrastructure | Single C2 server + LOTS delivery (GitHub) | Five-domain layered relay + Cloudflare fronting |
| Operator Model | Manual — human operator running commands | Automated — predefined stealer routines |
| Evasion | LOTS (trusted domains for delivery) | Domain fronting (Cloudflare ECH) + spoofed UA |
| Exfiltration | Surveillance data (window titles) — no bulk exfil | Automated bulk exfil (credentials, cookies, fingerprints) |
| Key Detection Lesson | Behavioral rules needed when content is encrypted | Content-match rules possible when C2 uses HTTP; DNS rules critical when TLS SNI is hidden |

## Key Concepts

1. **DNS resolution ≠ connection.** A successful DNS response means the machine knows the IP — not that it connected. Always verify TCP handshakes separately.

2. **Cloudflare-fronted connections are mostly legitimate.** Don't alert on Cloudflare infrastructure — alert on specific domain names via DNS queries and TLS SNI fields.

3. **Layered infrastructure is intentional.** Each domain serves one purpose. Take down any single node and the rest keeps working. Detection needs coverage at every stage.

4. **Disposable domains rotate faster than blocklists.** Detection must target behavioral patterns (URI paths, content types, traffic sequences) not just domain names.

5. **JA3 is powerful but never standalone.** Always combine with SNI, destination IP, or URI pattern to avoid false positives from legitimate applications using the same TLS library.

6. **Two-phase C2 connections are a behavioral indicator.** Lumma connects twice — once for config, once for exfil. This pattern persists across campaigns even when specific hashes change.

7. **The msg field is documentation, not decoration.** A well-written msg tells the next analyst the malware family, campaign, and kill chain stage at a glance.

8. **Know when to stop digging.** Chasing noise because you want to find something is how investigations go sideways. Document what you can observe, note what's not visible, and move forward.

9. **Content-based rules work when C2 uses HTTP.** This is the key difference from PA-01 where encrypted C2 forced behavioral-only rules. Lumma's HTTP-based exfil allows content matching — that's why this sample was chosen.

10. **Sticky buffers come before content matches in Suricata.** `dns.query;` and `tls.sni;` tell the engine WHERE to look — they must precede the `content:` keyword they apply to.

11. **Broad rules for coverage, precision rules for confidence.** Always write a fallback rule first, then add a precision rule with extra conditions on top.

12. **Cloudflare ECH defeats TLS SNI detection.** DNS-based detection is the only reliable layer for Cloudflare-fronted domains.

13. **`nocase` is redundant on `http.host` in Suricata.** The hostname buffer is auto-normalized to lowercase. Adding `nocase` causes parser errors.

14. **Never hardcode victim-specific data in rules.** Bot IDs, tokens, and session identifiers belong in IOC tables, not detection rules.

15. **Port `any` is correct for HTTP rules.** C2 servers can run on any port. Hardcoding port 80 makes rules blind to non-standard configurations.
