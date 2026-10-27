---
name: hunt-resource-development
description: "Hunt Resource Development (TA0042) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0042, resource-development, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Resource Development (TA0042)

Infrastructure and tooling built before contact: domains, certificates, accounts, payload
hosting. Almost none of it is visible in your estate — the hunt is over the **artifacts that
touch you**: lookalike sender domains, first-seen hosts serving payloads, and known offensive
tools appearing on endpoints. Say plainly that attacker-side infrastructure is out of view.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Resource Development.

## When to Use

- Inbound mail from a newly registered domain impersonating a brand or partner.
- Proxy/DNS shows a first-seen domain delivering an executable or archive.
- An offensive-tool name or hash appears in endpoint telemetry.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | Inbound mail comes from infrastructure registered for the campaign | T1583 / T1585 | Sender domain age under 30 days, missing or failing SPF/DKIM/DMARC, display name matching a real brand |
| H2 | A payload is staged on commodity hosting shortly before delivery | T1608 | First-seen domain serving an archive/executable, then the same URL appears in proxy or mail logs |
| H3 | Offensive tooling reaches an endpoint | T1587 / T1588 | Known tool name, hash or driver on disk without a matching change record |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Mail gateway:** sender domain, authentication results, URL and attachment hashes.
- **New-domain / passive-DNS feed:** registration dates, hosting ASN, first-seen timestamps.
- **Proxy and DNS logs:** for first-seen correlation and payload fetches.
- **Brand list:** the names an impersonation would imitate (your domains, executives, partners).

## Procedure

1. **Build the lookalike query.** Sender domains with edit distance to the brand list, plus
   age and authentication status. *Done when the query returns a ranked candidate list.*
2. **Correlate infrastructure.** For each candidate domain: first-seen date, hosting ASN, and
   whether it appears in proxy or DNS logs. *Done when every domain has a first-contact timeline.*
3. **Check tooling.** Search endpoint telemetry for the tool markers that matter to your estate,
   not a generic offensive-tool list. *Done when hits are either empty or attributed to a host.*
4. **Classify.** Campaign infrastructure, marketing/new vendor, or sinkhole noise.
   *Done when each candidate is labelled and any real delivery is escalated to Initial Access.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1583 Acquire Infrastructure | Passive DNS, new-domain feeds | registration age versus sender history |
| T1585 Establish Accounts | Mail gateway, IdP | account created then immediately used for outbound mail |
| T1587 Develop Capabilities | EDR/AV | custom tool markers or unique binaries on disk |
| T1608 Stage Capabilities | Proxy/DNS | hosting domain serving payload right before detonation |
| T1588 Obtain Capabilities | EDR/file | cracked or repurposed tooling installers |

## Detection content

### First-seen destinations per host
Newly registered or newly staged infrastructure looks exactly like this: a hostname that has never
been resolved by that host, seen a handful of times, then forgotten.

```esql
from logs-dns-*
| where dns.question.type == "A"
| stats first = min(@timestamp), hits = count() by host.name, dns.question.name
| where first >= now() - 1 day and hits <= 5
```

*Needs:* DNS resolver logs with `host.name`, `dns.question.name`, `dns.question.type`.

### Inbound mail from young, unauthenticated domains
Registration age is the cheapest reputation signal available and the one attackers cannot fake
without spending time.

```kql
event.category : "email" and email.direction : "inbound"
  and source.domain.age_days <= 30
  and not email.dmarc : "pass"
```

*Needs:* mail gateway events plus a domain-age enrichment (join or ingest-time lookup). Without the
enrichment, substitute "first seen in 30 days" from your own mail history.

## Pitfalls

- **Legitimate new domains.** Marketing campaigns, new SaaS vendors and regional partners all
  register fresh domains; correlate to expected business change.
- **Sinkholes and blocklists generate noise.** A domain already sinkholed by a provider is a
  lead about intent, not about compromise.
- **No attacker-side visibility.** You cannot see staging infrastructure that never touches
  you — scope the verdict to artifacts observed, not to the actor's capability.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
