# Detection-grade output — conventions worth copying

Distilled from the structure of a mature public rule set (Elastic `detection-rules`: 2,305 rules,
143 hunts, 131 building blocks). **Structure and conventions only** — the upstream content is
Elastic License v2, so nothing is copied: we adopt the shape, write our own logic, and cite.

## Severity ↔ risk score

One canonical mapping, used consistently by ~1,800 of their rules:

| Severity | Risk score | Use when |
|---|---|---|
| low | 21 | recon, discovery, single weak indicator — volume alone would drown a queue |
| medium | 47 | a behaviour that needs a second signal; attempts blocked at the edge |
| high | 73 | working access, credential theft, lateral movement, C2 to an unowned destination |
| critical | 99 | confirmed compromise or destructive potential: security-tool tampering, dump + use, encryption, exfiltration of classified data |

Pick the severity from **what the signal proves**, not from how alarming the technique name sounds.

## Required metadata on every artifact

A rule needs all of these; a hunt can drop `risk_score` but keeps the rest:

| Field | What it must say |
|---|---|
| `name` | behaviour first, ≤ 60 characters, no victim or product name alone (`Suspicious LSASS Access via Signed Utility`, not `Credential Dumping Rule 2`) |
| `description` | what the behaviour is **and why it matters**, one or two sentences |
| `mitre` | technique IDs (sub-techniques where they exist) — mandatory in their hunt corpus |
| `integration` / data source | the specific index pattern or integration, not "all logs" |
| `false_positives` | at least one **concrete benign twin**; upstream omits it in 57% of rules, which is exactly why their rules need tuning — do better |
| `references` | a public URL that justifies the logic |
| `tags` | domain, OS, tactic lane, and the behaviour family |
| `notes` | pivot guidance: what to look at next, what to compare with |

## Analytic type — choose by question, not by habit

| Type | Answers | Example shape |
|---|---|---|
| single-event query (KQL) | "does this event exist with these attributes" | process name + parent + path |
| sequence (EQL) | "did A happen then B, in order, same host" | logon → child process → file write |
| first-seen (`new_terms`) | "is this value new for this host/user" | service name, destination domain |
| threshold | "did this happen N times in a window" | mass service stops, spray volume |
| aggregation (ES|QL) | "what is the shape of the distribution" | bytes per host, logon pairs |
| ML | "does this deviate from a fitted baseline" | beacon periodicity, rare parent-child |

Language follows the type: **KQL** for single events, **EQL** only when ordering carries meaning,
**ES|QL** for aggregation and statistics, plus **osquery SQL** on fleets and **YARA** on files.
Multi-language hunt packs are normal: one query per analytic type, all returning evidence.

## Query hygiene (their published best practices)

- Filter as early as possible in `WHERE`; every clause you push down shrinks the scan.
- Project before aggregating: `KEEP` only the fields `STATS` needs.
- `LIMIT` results to the volume a human will actually read.
- Name index patterns as specifically as the question allows — `logs-endpoint.events.process-*`,
  never a bare wildcard across every dataset.
- Use normalised fields (ECS-style) so the same query survives a data-source change.

## Validation, both directions

A detection is not finished until it has been run twice:

1. **Benign window** — the query returns zero (or only known-noise) over a quiet period.
2. **Positive fixture** — a synthetic or historical true positive fires.

Their rule set carries a test framework and per-rule fixtures for exactly this reason; adopting
the requirement costs nothing and prevents shipping untested logic.

## Lookback and delay

Rules specify a lookback (`from: now-9m`-style) and, where ingestion lags, a timestamp override.
Write the equivalent into a hunt: state the window, the ingest delay you assume, and whether the
query is retro-active (IOC/TTP sweep) or data-driven (shape discovery).

## Attribution

If a skill or query is derived from another project, say so in `references` and in the skill's
notes. Elastic's rules are Elastic License v2; the lessons are free, the text is not.
