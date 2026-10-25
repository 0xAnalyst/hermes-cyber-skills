---
name: api-retest-harness
description: Use when re-running a previous API pentest to check remediation — turns an evidence JSONL log into a rerunnable probe script with baseline deltas.
version: 0.1.1
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
   runtime; the generator refuses output containing credential-shaped material
   (24+ alnum chars with a digit — hex-only patterns miss letter-prefixed keys).
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
failures, re-check before concluding. A replay also only re-verifies the
mapped subset — baseline checks the log can't express (TLS cert dates, cipher
acceptance, port states, rate bursts) need ad-hoc re-runs in the same pass,
or the report must carry 'not re-scanned' rows.

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

## Pitfalls

- **Embed the probe table as Python literals (`pprint.pformat`), never
  `json.dumps`** — the table is a Python object in the generated script;
  JSON writes `null`/`true`/`false` which NameError at import.
- **Scrub credential-shaped values in URLs, not just headers** — key-in-query
  probes embed the secret in the URL itself, the exact leakage class retests
  replay; a headers-only scrubber ships the key into the generated file.
- **Fail-closed writes:** write to `<out>.tmp`, run the secret gate on the tmp
  content, then `os.replace` — a refusal must never leave a stale leaky
  artifact from a previous run in place of the new file.
- **Dry-run the generated script's `--plan` before delivering it** — generation
  succeeding proves nothing about the generated script; both the null-literal
  and credential-pattern bugs above surfaced only at run time.
- **Negative controls must not share the good key's placeholder** — a
  credential-shaped invalid-key value (e.g. a second real key from the same
  engagement) gets scrubbed into the same `{{API_KEY}}`, so replay silently
  converts the negative control into the positive one (phantom DIFF: 200 at
  runtime vs baseline 400). Emit a distinct placeholder per credential-shaped
  value (`{{KEY_2}}`, `{{BAD_KEY}}`) resolved from its own env var. At fire
  time, a DIFF on a negative control whose response resembles the good key's
  (similar length, real data) means the placeholder resolved to the real key —
  check that probe's credential field for the shared placeholder and verify
  the control by sending the invalid value literally before calling it a
  regression.
- **Statuses alone can't decide a retest — capture bodies and headers.** The
  generated script prints OK/DIFF and drops the rest, but auth verdicts hinge
  on the body (gateway-auth-pass → backend fault vs `Invalid API Key` are both
  'a response'). Import the generated module (`spec_from_file_location`;
  `main()` is `__main__`-guarded so import is safe) and wrap `PROBES`/`send()`
  with scrubbed JSONL logging. For any probe replayed outside `send()`, resolve
  `{{API_KEY}}` into headers/URLs yourself first — raw header dicts ship the
  literal placeholder and the resulting 400s masquerade as remediation.
- **`getpeercert()` returns an empty dict when verification is disabled** —
  under `verify_mode=CERT_NONE`, pull expiry via `getpeercert(True)` (DER)
  piped through `openssl x509 -inform der -noout -enddate`, not the dict cert
  fields.

## References

- `examples/gateway-url-map.json` — worked retrofit map for the commercial gateway/SAP
  engagement compact log (`pentest_log2.jsonl` pattern).
