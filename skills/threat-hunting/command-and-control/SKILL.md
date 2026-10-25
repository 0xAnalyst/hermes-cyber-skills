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

## Observed in public case reports

Paraphrased from The DFIR Report case studies; sources and full chains in
`hunt-method/references/casebook.md`.

- Commercial C2 frameworks (Brute Ratel, AdaptixC2) and commodity frameworks (Metasploit)
  appear in the same intrusions (**C2**, **C3**, **C6**) — tool novelty is not the signal, the
  absence of any engagement that would justify it is.
- Loader → stage downloads from the same infrastructure, often on high ports (**C1**).
- Long dwell with tool changes (**C6**) means a single-day beacon sweep will miss the intrusion;
  hunt novelty across the whole window.

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
