---
name: hunt-command-and-control
description: "Hunt Command and Control (TA0011) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0011, command-and-control, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Command and Control (TA0011)

The channel back. Beaconing is the classic pattern, but interval regularity is the weakest
of the signals: what separates C2 from an update agent is **application semantics, byte
direction, and destination purpose** — not a stopwatch.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Command and Control.

## When to Use

- A host talks to a destination with no business purpose, repeatedly.
- A download of an executable or archive is followed by execution.
- DNS or ICMP carries unusual volume or labels.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | A host beacons to a novel destination | T1071 / T1573 | Regular intervals with small, roughly symmetric bytes and a stable destination absent from the allowlist |
| H2 | Tooling is pulled in before execution | T1105 | Download of executable/archive from a first-seen domain, then a process start within minutes |
| H3 | An internal host relays or tunnels traffic | T1090 | One host acting as transit for many destinations, or listening on an unexpected port |
| H4 | A covert channel uses DNS or ICMP | T1071.004 / T1095 | Long high-entropy labels, TXT/NULL queries, ICMP with payload |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Proxy logs** with URL, category, bytes sent and received.
- **Netflow** for volume and direction, including non-web ports.
- **DNS logs** with query type and response size.
- **EDR network telemetry** to attribute connections to processes.
- **Allowlist** of update, telemetry and SaaS endpoints — the comparison set for H1.

## Procedure

1. **Find beacon candidates by shape.** Interval consistency plus byte profile, per host.
   *Done when candidates are listed with interval, byte ratio and destination.*
2. **Decode the destination.** ASN, ownership, category, certificate/SNI, first-seen date.
   *Done when every destination has a stated purpose or an "unknown" label.*
3. **Check byte direction.** Upload-heavy, download-heavy or symmetric tells you whether this
   is update, telemetry, exfiltration or tasking. *Done when each candidate is classified.*
4. **Attribute to a process.** Which binary, signed by whom, started by what.
   *Done when the connection has an owner.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1071 Application Layer Protocol | Proxy/netflow/DNS | regular interval plus application mismatch |
| T1573 Encrypted Channel | TLS metadata | SNI/ASN mismatch, self-signed or pinned to nothing |
| T1090 Proxy | Netflow | one internal host as transit for many destinations |
| T1105 Ingress Tool Transfer | Proxy/EDR | download then execute within minutes |
| T1568 Dynamic Resolution | DNS | fast-flux or DDNS patterns for the same hostname |
| T1095 Non-Application Layer Protocol | Firewall/netflow | ICMP or raw protocol carrying payload |

## Detection content

### Beacon shape by destination
Regular contacts, small payloads, one destination. Interval alone is weak; interval plus low byte
volume plus novelty is not.

```esql
from logs-network_traffic-*
| stats n = count(), out = sum(source.bytes), in = sum(destination.bytes)
        by host.name, destination.ip, destination.port
| where n >= 50 and in < 10000 and out < 10000
```

*Needs:* flow records with byte counters; then subtract known update/telemetry endpoints by
application name, not by IP reputation.

### First-seen external destination
A host's first-ever contact with an external IP is the cheapest novelty signal available.

```esql
from logs-network_traffic-*
| stats first = min(@timestamp), n = count() by host.name, destination.ip
| where first >= now() - 1 day and n <= 10
```

*Needs:* 30 days of flow history to make "first" meaningful.

### Long-label DNS
Tunnels and some frameworks encode data in query labels; legitimate CDN and DKIM names also produce
long labels, so filter by label entropy and query type rather than length alone.

```kql
dns.question.name : /[a-z0-9]{40,}\./ and dns.question.type : ("TXT", "NULL", "CNAME")
```

*Needs:* resolver logs with `dns.question.name` and `dns.question.type`; verify hits against known
telemetry clients before escalating.

## Pitfalls

- **Update and telemetry agents beacon by design.** Application name, allow rule and byte
  direction identify them; a CDN in an unusual country is not evidence.
- **CDNs look foreign.** Large content networks serve well-known vendors from unexpected ASNs —
  check what the bytes are, not where they come from.
- **Interval alone is weak.** Many legitimate clients poll on fixed schedules; combine with
  novelty, direction and process attribution.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
