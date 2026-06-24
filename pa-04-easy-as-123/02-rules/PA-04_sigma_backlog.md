# PA-04 — Sigma Backlog (Deferred to Operation Prism Box, PB-02)

Detection logic identified during PA-04 that belongs in the **log layer (Sigma →
SIEM)** rather than the **packet layer (Suricata)**. These require log sources and/or
stateful correlation not available to a network IDS, so they are deferred to Prism
Box, where the Elastic + Sysmon + Atomic Red Team pipeline can generate the telemetry
to validate them.

---

## Why these are Sigma, not Suricata

| | Suricata | Sigma |
|---|---|---|
| **Input** | packets / PCAP (the "Wireshark layer") | logs (Sysmon, Windows Event Log, proxy, DNS resolver, EDR) |
| **Model** | per-packet / per-flow | log events over time; stateful correlation possible |
| **Deploys to** | the IDS engine | any SIEM via converter (Splunk, Elastic, Sentinel) |
| **Validated by** | run vs. PCAP → `fast.log` | lint → convert → run vs. real logs (lab telemetry) |

The beacon-cadence rule below needs **counting/timing across many events** — beyond
Suricata's per-flow model — and the DNS rule is included as a **log-layer twin** of
the Suricata DNS rule (same indicator, different data source: resolver/Sysmon logs
instead of packets), which gives redundant coverage if the IDS misses it.

---

## Rule 1 — Beacon cadence (the primary deferral)

**Logic:** a single internal host sends repeated HTTP POSTs to one external
destination at a fixed interval (~60s) over an extended period — the signature of an
automated C2 keepalive, regardless of payload.

**Why deferred:** requires **stateful aggregation** (count POSTs per `src,dst` pair,
measure inter-request interval regularity) across many log events. Suricata cannot
express "every 60s for N minutes."

**Data source:** proxy / web-filter logs, or Zeek `http.log`, or firewall connection
logs.

**Draft (Sigma — correlation style; tune thresholds against baseline):**

```yaml
title: Periodic HTTP POST Beacon to Single External Destination
id: PA-04-beacon-cadence
status: experimental
description: Detects a host POSTing to one external destination at a regular interval, consistent with automated C2 keepalive beaconing.
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
    condition: selection
    timeframe: 10m
    # Aggregation expressed in the SIEM backend:
    #   group by (src_ip, dst_ip)
    #   where count(POST) >= 8 within 10m
    #   AND stddev(inter-request interval) is low (regular cadence)
fields:
    - src_ip
    - dst_ip
    - cs-method
    - cs-uri
level: high
falsepositives:
    - Software update pollers, telemetry, monitoring agents with regular check-ins
    - Tune by whitelisting known-good destinations and requiring external dst
tags:
    - attack.command_and_control
    - attack.t1071.001
```

> **Note:** true cadence/regularity scoring (low stddev of inter-arrival time) is
> backend-specific — implemented in SPL with `streamstats`/`stats`, in KQL with
> `make_list` + `series_stats`, etc. The Sigma rule flags the high-volume POST
> grouping; the regularity refinement is added in the converted query.

---

## Rule 2 — Malicious DNS resolution (log-layer twin of Suricata Rule 1)

**Logic:** a host queries the C2 domain. Same indicator as the Suricata DNS rule, but
sourced from **DNS logs** (Sysmon Event ID 22 or resolver logs) — useful where the
IDS isn't inline or the query is encrypted to the IDS but visible to the resolver.

**Data source:** Sysmon Event ID 22 (DNS query) or DNS server logs.

**Draft (Sigma):**

```yaml
title: DNS Query for NetSupport C2 Domain (vadusa.xyz)
id: PA-04-dns-vadusa
status: experimental
description: Detects a DNS query for the PA-04 NetSupport C2 domain.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 22
        QueryName: 'vadusa.xyz'
    condition: selection
fields:
    - Computer
    - User
    - QueryName
    - QueryResults
level: high
falsepositives:
    - None expected (no legitimate reason to resolve this domain)
tags:
    - attack.command_and_control
    - attack.t1071.001
```

> This is an **IOC rule** (domain rotates), but cheap and high-confidence. Its value
> is the *redundant layer*: if the network rule is bypassed, the resolver log still
> catches the lookup.

---

## Rule 3 (optional) — NetSupport process / remote-access tool execution

**Logic:** if endpoint telemetry is available, the NetSupport client *process*
running and making external network connections is a host-layer detection
complementing the network rules. (Drafted as a future PB-02 item once Sysmon process
+ network events are flowing.)

**Data source:** Sysmon Event ID 1 (process create) + Event ID 3 (network connect).

*To be authored during PB-02 with live endpoint telemetry — left as a placeholder
here.*

---

## How to write and validate Sigma (workflow reference)

```bash
# 1. Lint / validate syntax (pySigma)
sigma check PA-04-dns-vadusa.yml

# 2. Convert to your SIEM backend
sigma convert -t splunk  PA-04-dns-vadusa.yml     # → SPL
sigma convert -t elasticsearch PA-04-dns-vadusa.yml  # → ES query / KQL

# 3. Validate against REAL LOGS (not a PCAP):
#    - run the converted query in the SIEM over historical data, OR
#    - generate telemetry in lab (PB-02 Atomic Red Team) and confirm it fires
```

**Key point:** Sigma is **not** validated against a PCAP — it reads logs, not
packets. Firing these rules requires the Elastic + Sysmon pipeline being built in
Prism Box. Write and convert them now; validate them when the log layer is live.

---

## Validation paths — how to test a log-rule when you started from a PCAP

A PCAP holds only packets; Sigma needs logs. Two ways to bridge the gap, depending on
**what data layer the rule operates on**:

### Path 1 — Convert the PCAP to logs (network-data rules only)
Run the existing PCAP through **Zeek** to produce structured logs (`dns.log`,
`http.log`, `conn.log`). A Sigma rule written against network logs (proxy/DNS/conn)
can then run against *those* logs — validated from the capture you already have, no
re-infection needed.

```bash
zeek -r 2026-02-28-traffic-analysis-exercise.pcap
# → produces dns.log, http.log, conn.log → ingest → run Sigma
```

**Works for:** beacon cadence (from `http.log`/`conn.log`), DNS twin (from `dns.log`).
**Does NOT work for:** anything host-level — Zeek only derives *network* logs; process
creation, registry, and Sysmon events were never on the wire to derive.

### Path 2 — Simulate the behavior (host-data rules)
Host-layer telemetry (process, registry, Sysmon EID 1/3/22, EDR) was never in the
PCAP, so it must be **generated**. Stand up a lab endpoint (Sysmon → Elastic), run
**Atomic Red Team** to reproduce the *technique* (not the original malware), and
confirm the Sigma rule fires against the real logs produced.

**Key point:** you validate against the *behavior*, not the original sample — Atomic
Red Team reproduces the technique without needing the NetSupport binary. This is why
detection engineering scales: rules target techniques, validation simulates
techniques.

### Mapping to data layer

| Rule operates on | Source | Validation path | Available |
|---|---|---|---|
| Packets (Suricata rules) | PCAP | Suricata → `fast.log` | now ✓ (done) |
| Network logs (beacon, DNS) | Zeek-from-PCAP | Path 1 | now (PB-01) |
| Host logs (process, registry) | live endpoint | Path 2 (Atomic Red Team) | PB-02 |

This is precisely why Prism Box exists: PB-01 provides the log pipeline (and can replay
PCAP→Zeek for network-log rules); PB-02 runs Atomic Red Team to generate host telemetry
for the host-level rules.

---

## Status

| Rule | Type | Defer reason | Validate in |
|------|------|--------------|-------------|
| Beacon cadence | correlation | stateful timing across events | PB-02 (proxy/Zeek logs) |
| DNS twin | IOC | log-layer redundancy | PB-02 (Sysmon EID 22) |
| Process exec | host | needs endpoint telemetry | PB-02 (Sysmon EID 1/3) |

Counts toward Prism Box detection-as-code (pySigma, multi-backend) deliverable.
