# PA-03 — Sigma Rules Backlog (Deferred to Operation Prism Box)

## Context

During PA-03 investigation, three detection opportunities were identified that **cannot be implemented as Suricata rules** because they require log correlation, counting, time windowing, or statistical analysis that Suricata's packet inspection engine cannot perform.

These will be written as **Sigma rules** in **Operation Prism Box (PB-02)** once Elastic Stack is operational and ingesting DNS logs + Suricata EVE JSON.

This document serves as the starting backlog for Sigma rule development in PB-02.

---

## Rule 1 — DGA Detection via NXDOMAIN Rate

**What to detect:** A single internal host generating a high number of failed DNS queries (NXDOMAIN responses) in a short time window.

**Why it matters:** DGA malware generates pseudo-random domain names and tries them sequentially. Most fail (NXDOMAIN). Normal hosts rarely trigger more than a few NXDOMAIN responses per minute. A spike indicates DGA activity.

**PA-03 evidence:** 10+ NXDOMAIN responses for .top domains from victim 10.2.2.37 within ~20 seconds.

**Why not Suricata:** Suricata inspects individual packets. It cannot count the number of NXDOMAIN responses per source IP over a time window. This requires SIEM-level aggregation.

**Sigma rule logic (draft):**
```
title: High NXDOMAIN Rate from Single Host (Possible DGA)
status: experimental
description: Detects potential DGA activity based on high rate of failed DNS resolutions
logsource:
    category: dns
detection:
    selection:
        response_code: 'NXDOMAIN'
    condition: selection | count(query_name) by source_ip > 10
    timeframe: 1m
level: medium
tags:
    - attack.command_and_control
    - attack.t1568.002
```

**False positive considerations:** Misconfigured applications, broken DNS caches, legitimate software checking multiple CDN endpoints. Threshold may need tuning per environment.

---

## Rule 2 — DNS Entropy Scoring on .top Domains

**What to detect:** DNS queries to domains with high character entropy (randomness) under the .top TLD.

**Why it matters:** DGA domains are algorithmically generated and have measurably higher entropy than legitimate domain names. "4ec74y9kph5vko2.top" has much higher entropy than "google.com" or "amazon.de."

**PA-03 evidence:** All DGA domains observed (both resolved and NXDOMAIN) shared random alphanumeric patterns under .top TLD.

**Why not Suricata:** Suricata cannot calculate Shannon entropy on domain names. This requires a processing layer (Zeek script, Elastic ML, or custom SIEM logic).

**Implementation approach for PB-02:**
- Zeek can calculate domain entropy via custom scripts
- Elastic ML can flag anomalous domain patterns
- Sigma rule can flag .top domains exceeding a length threshold as a simpler proxy

**False positive considerations:** Some legitimate services use hash-like subdomains (CDNs, analytics). Entropy alone needs context — combine with NXDOMAIN rate for higher confidence.

---

## Rule 3 — Sequential Queries to Public IP Lookup Services

**What to detect:** A single host querying 3 or more public IP discovery services (api.ipify.org, checkip.dyndns.org, ipinfo.io, ip-api.com, etc.) within a short time window.

**Why it matters:** Malware fingerprints the victim's network by checking their public IP. Using multiple services provides redundancy. Normal users don't query 3+ IP lookup services in quick succession.

**PA-03 evidence:** GhostWeaver RAT queried api.ipify.org, checkip.dyndns.org, and ipinfo.io within seconds of C2 establishment.

**PA-01 comparison:** Remcos used only 1 service (ip-api.com). GhostWeaver's 3x redundancy indicates higher sophistication.

**Why not Suricata:** Suricata cannot correlate multiple distinct DNS events from the same source within a time threshold. Each DNS query is an independent packet — Suricata processes them individually with no cross-packet state for this use case.

**Sigma rule logic (draft):**
```
title: Sequential Public IP Lookup Queries (Possible Malware Recon)
status: experimental
description: Detects a host querying multiple public IP discovery services in quick succession
logsource:
    category: dns
detection:
    selection:
        query_name:
            - 'api.ipify.org'
            - 'checkip.dyndns.org'
            - 'ipinfo.io'
            - 'ip-api.com'
            - 'ifconfig.me'
            - 'icanhazip.com'
            - 'wtfismyip.com'
    condition: selection | count(query_name) by source_ip >= 3
    timeframe: 5m
level: medium
tags:
    - attack.discovery
    - attack.t1016
```

**False positive considerations:** VPN clients, network diagnostic tools, legitimate apps checking connectivity. Threshold of 3+ services in 5 minutes should minimize FPs while catching automated recon.

---

## Summary

| Rule | Target Behavior | ATT&CK | Priority for PB-02 |
|------|----------------|--------|-------------------|
| 1 | DGA via NXDOMAIN rate | T1568.002 | High |
| 2 | DNS entropy scoring | T1568.002 | Medium |
| 3 | Sequential IP lookup | T1016 | Medium |

---

*PA-03 Sigma backlog — Operation PCAP Autopsy → Operation Prism Box — cyberlandji*
