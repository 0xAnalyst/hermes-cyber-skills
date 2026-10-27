---
name: hunt-method
description: "Shared doctrine for MITRE-mapped threat hunts: hypotheses, evidence gates, false-positive discipline."
version: 1.0.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, detection-engineering, evidence, triage]
    category: threat-hunting
    related_skills: [log-forensics, siem-alert-review]
---

# Hunt method

Doctrine shared by every `hunt-*` skill. A hunt answers one falsifiable question about a
window of telemetry; it is not a keyword sweep and not an alert review. The tactic skills
supply hypotheses and technique maps — this file supplies the discipline that keeps a
verdict honest.

**The easy signal is rarely the true one.** Every hunt in this family has produced a version
of the same lesson: the number that looks alarming is usually a vendor agent, a sanctioned
scanner, a newsletter, or an appliance log, and the number that looks like zero is usually a
query-shape error.

## When to Use

- Any `hunt-*` tactic skill is loaded — read this first, it defines the output contract.
- A hunt produced a number and you are about to call it clean or dirty.
- A detection is about to ship and you need to know what will make it unusable in production.

## The four-stage loop

1. **Hypothesis.** One sentence, falsifiable, scoped to a window and an asset set: "an attacker
   used a valid account to reach the finance file share" — not "look for lateral movement".
2. **Observable.** The telemetry that must exist if the hypothesis is true, named at field
   level. If the observable cannot exist in your data, the hunt is unanswerable — say so
   instead of reporting a zero.
3. **Discriminator.** The property separating the malicious instance from the benign one that
   looks identical at a glance. This is where hunts are won: same string, different parent
   process; same volume, different byte direction; same port, different application.
4. **Confirmation.** A second, independent plane that agrees: process telemetry plus network
   flow plus authentication log. One plane is a lead; two planes are a finding.

Skipping stage 3 produces a "hit" nobody can triage and a "clean" nobody can defend.

## Evidence rules

- **Counts lie in both directions.** Duplicate ingestion inflates; phrase-token mismatches
  deflate to zero. Any zero that changes the verdict gets a second query shape.
- **Status codes are not outcomes.** Blocked, redirected, and exploited can all return 200 —
  or 302, or nothing at all. Ask what the code would have been had the attack worked.
- **Absence needs a baseline.** "No hits" means nothing unless the same query returns hits for
  a comparable benign signal in the same window. Prove the lane is alive before calling it quiet.
- **Sample before you count, count before you conclude.** A total without a decoded sample is a
  rumour; a sample without a total is an anecdote.
- **Blind spots ship with the verdict.** Body-less logs, unforwarded planes, TLS opacity,
  matched-rule-only WAF feeds, ingest gaps. A scoped "clean" is useful; an unscoped one is a lie.

## False-positive discipline

Every detector ships with its benign lookalikes and a rule for telling them apart:

| Class | Looks like | Tell |
|---|---|---|
| Sanctioned scanning | attack traffic against your estate | scheduled, internal scanner range, same source on a cadence |
| Lab reproduction | exploit payloads on a workstation | loopback/RFC1918 destination, developer tooling nearby |
| Vendor / CDN / telemetry | C2 beaconing to an odd ASN | application name, allow rule, byte direction say update or telemetry |
| Mail and newsletter copies | alert names inside log text | the term appears in mail transport, never in a web request |
| Alert-email echoes | API names in "process telemetry" | rows are mail transport repeating an alert subject |
| Crawler / census traffic | probing the public edge | labelled user agent, robots.txt, census-style PTR |
| Admin tooling | discovery, exec, lateral movement | signed agent, parent is the management platform, change ticket exists |

## Output contract

1. **Verdict line** — one sentence: what was hunted, over what window, on what data.
2. **Signal table** — per hypothesis: count, decoded sample, classification
   (exploit / attempt / scan / lab / noise), evidence anchor.
3. **Confidence by plane** — high/medium/low per data plane, with the reason.
4. **Blind spots** — what this telemetry cannot see, stated plainly.
5. **Actions** — each with an owner-shaped verb: block, patch, confirm with owner, re-run.



Never write "clean" without the plane. Never write "no evidence" when the answer is
"no visibility".

## Pitfalls

- **Token traps.** Phrase search matches whole tokens: a product name concatenated with a
  hash, or a marker embedded inside a long base64 label, is invisible to `match_phrase`.
  Query the literal exactly, or fetch rows and filter client-side.
- **Aggregation zero.** A count combining several filters can silently return 0 while a
  sampled search proves hits. Cross-check every verdict-changing zero.
- **Time-window drift.** Daily indices, timezone offsets and ingest lag move events across
  boundaries. State the window once, in one timezone, and convert once.
- **Sampling bias.** "Newest 2,000 rows" is not a random sample when the source is bursty.
- **Deconfliction is part of the hunt.** Check the scanner inventory, the pentest calendar and
  the lab hosts before escalating internal-looking activity.

## References

- `references/hunt-report-template.md` — the five-part output, ready to fill.
