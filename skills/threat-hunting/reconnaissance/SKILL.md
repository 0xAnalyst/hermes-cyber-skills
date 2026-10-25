---
name: hunt-reconnaissance
description: "Hunt Reconnaissance (TA0043) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0043, reconnaissance, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Reconnaissance (TA0043)

The attacker is learning the shape of the estate from outside: scanning, DNS and
certificate enumeration, technology fingerprinting, employee discovery. Almost all of the
observable evidence sits at the edge or in third-party exposure — the endpoint plane is
usually silent, which is a blind spot to state rather than a clean result.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Reconnaissance.

## When to Use

- Edge deny/404 bursts from a single source, or a new scanner user agent.
- Certificate-transparency or new-domain monitoring flags a lookalike asset.
- An exposure review asks "what did outsiders learn about us this week".

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | One source enumerates many paths or hosts in minutes | T1595 | Edge/firewall rows: single client, high 403/404 ratio, sequential path or port order |
| H2 | Fingerprinting targets a specific product, not a generic crawl | T1592 / T1590 | Product-shaped paths and UA pairs repeated across hosts (framework, admin console, API gateway) |
| H3 | The public attack surface changed without a change record | T1593 / T1596 | New hostname, certificate or listening port visible externally and absent from asset inventory |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Edge telemetry:** WAF/CDN/firewall fields for client IP, user agent, path, status, bytes.
- **Asset inventory:** hostnames, products, versions, ownership — the comparison set for H3.
- **Sanctioned-scanner list:** internal ranges, external assessment vendors, and their schedules.
- **Window + baseline:** at least 7 days of the same edge data to establish per-source p95 rates.

## Procedure

1. **Baseline edge noise.** Top clients by 403/404 per hour, grouped by user agent family.
   *Done when the per-source p95 rate and the labelled-crawler list are written down.*
2. **Find outliers.** Clients above p95 with sequential or product-shaped paths.
   *Done when every outlier is listed with a decoded sample request.*
3. **Classify.** Scanner, crawler, researcher, targeted recon, or sanctioned assessment — using
   user agent, PTR, path pattern and cadence. *Done when each outlier has a label and a reason.*
4. **Confirm exposure delta.** Diff the enumerated paths/hosts against inventory.
   *Done when any newly exposed asset is named with an owner.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1595 Active Scanning | WAF/firewall denies, edge request logs | request rate and path sequencing from one client |
| T1592 Gather Victim Host Information | Edge UA/path patterns, TLS fingerprints | product-specific probes rather than a generic crawl |
| T1590 Gather Victim Network Information | DNS query logs, certificate transparency | subdomain enumeration concentrated on one source |
| T1598 Phishing for Information | Mail gateway, identity provider | credential-harvest domain, reply-to mismatch, urgency framing |
| T1593 Search Open Websites/Domains | External only | not observable internally — track via brand monitoring instead |

## Pitfalls

- **Crawlers look like scanners.** Search-index and ad-verification agents fetch odd paths at
  volume; check the labelled user agent and PTR before escalating.
- **The CDN hides the client.** Without forwarded-for parsing, thousands of requests collapse
  onto a handful of edge IPs and the real source disappears.
- **Assessment windows.** Recon bursts frequently align with a booked pentest — check the
  calendar before writing an incident.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
