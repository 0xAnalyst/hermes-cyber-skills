---
name: api-retest-harness
description: Use when re-running a previous API pentest to check remediation — turns an evidence JSONL log into a rerunnable probe script with baseline deltas.
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, pentest, retest, regression, evidence]
    category: security
    related_skills: [api-pentest]
---

# API Retest Harness

Converts a pentest evidence log (JSONL) into a standalone, rerunnable probe
script that replays the engagement's requests and reports deltas against the
recorded baseline. Remediation checks become one command instead of a manual
re-engagement.

## When to Use

- After an assessment, when fixes are expected and a re-test is scheduled.
- Periodic regression: verify findings stay fixed and positives stay positive.
- Any engagement that produced a JSONL evidence log (the `api-pentest` skill's
  logging rule guarantees the input exists).

## Always-On Rules

1. **Generated scripts are dry-run by default.** `--fire` is a deliberate act
   on an authorized target — never run it just to "see if it still works".
2. **Credentials never enter generated artifacts.** Key-class header values are
   emitted as `{{API_KEY}}` placeholders resolved from the `API_KEY` env var at
   runtime; the generator refuses output matching a 16+ hex secret pattern.
   Rotate-then-retest means: export the NEW key, fire, compare.
3. **The log is the source of truth.** Probes the log can't reconstruct are
   reported as unmapped — retrofit them with `--url-map`, never by guessing.

## Procedure

**Phase 0 — Generate.** `python3 .../log_to_retest.py evidence.jsonl -o retest.py`
(or add `--url-map map.json` for compact logs). Review the printed probe list.

**Phase 1 — Plan.** `python3 retest.py --plan` — the full probe list, nothing sent.

**Phase 2 — Fire + delta.** `API_KEY=<current> python3 retest.py --fire` →
per-probe `OK/DIFF/ERR` vs baseline. All-OK = baseline unchanged (nothing
remediated, or findings confirmed stable); `DIFF` rows = state changed —
investigate whether remediation or regression; `ERR` rows = network/auth
failures, re-check before concluding.

**Phase 3 — Report.** Feed the delta table into the retest report (see
`api-pentest` Phase 6 / `references/owasp-api-mapping.md` for the mapping).

## Log schema contract (for future engagements)

Best replay fidelity = ONE event per probe:
```json
{"ts":"...", "phase":"auth-matrix", "tag":"good-key", "url":"https://host/path",
 "method":"POST", "headers_sent":{"apikey":"<scrubbed-at-write-time>"},
 "status":200, "body_head":"..."}
```
Scrub credential values when writing logs; the harness re-inserts via env var.
Older split schemas (sent+result rows) are handled by phase-pairing; compact
rows without URLs need `--url-map` (see `examples/`).

## References

- `examples/gateway-url-map.json` — worked retrofit map for a SOAP-gateway
  engagement compact log (phase+tag rows pattern).
