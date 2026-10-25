# Penetration Testing

Authorized, non-destructive offensive assessment of systems the operator owns or
is contracted to test: API and web-application testing, authentication and
authorization proofs, hardening review. Severities are calibrated to the target's
real threat model, and every conclusion carries evidence.

## Skills

| Skill | Version | Purpose |
|---|---|---|
| [`api-pentest`](api-pentest/) | 1.2.0 | Non-destructive black-box API security assessment: recon → auth matrix → authz-scope proof → hardening → evidence-backed report, with OWASP API:2023 mapping and a 10-row coverage gate |
| [`api-retest-harness`](api-retest-harness/) | 0.1.1 | Turns a pentest evidence JSONL into a rerunnable probe script — remediation checks become one command with baseline deltas; credentials never enter generated artifacts |

## Ground rules

- **Written authorization precedes any live-target action.** No skill file implies
  pre-authorization on the operator's behalf.
- **Non-destructive by default:** no executable payloads against write paths, no
  bulk extraction, dry-run before fire.
- **Evidence logs stay on the operator's machine.** Only methodology ships here;
  client hosts, tokens, and findings never do.

## Adding a skill here

Assessment and verification work — pentest methodology, exploitability proof with
safe payloads, retest/regression harnesses, reporting standards. If a skill is
primarily detection or response, it belongs in [`../dfir`](../dfir/); if it is
adversary emulation or engagement design, [`../red-teaming`](../red-teaming/).
