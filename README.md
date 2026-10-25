# hermes-cyber-skills

A growing collection of cybersecurity skills for
[Hermes Agent](https://hermes-agent.nousresearch.com/docs) — reusable,
evidence-driven methodologies that load automatically when a task matches.
Skills are grouped by domain; each one is self-contained and follows the same
layout and quality conventions.

**Owner:** [0xanalyst](https://github.com/0xanalyst) · **License:** MIT

## Domains

| Domain | Focus | Skills |
|---|---|---|
| [Penetration Testing](skills/penetration-testing/) | Authorized, non-destructive offensive assessment | 2 |
| [DFIR](skills/dfir/) | Threat hunting, detection engineering, log forensics | 1 |
| [Red Teaming](skills/red-teaming/) | Adversary emulation, engagement scoping, opsec | — |

Layout: `skills/<domain>/<skill-name>/` — `SKILL.md` plus optional `references/`,
`scripts/`, `examples/`. The scaffold lives at [`skills/_template`](skills/_template/).

## Penetration Testing

| Skill | Version | Purpose |
|---|---|---|
| [`api-pentest`](skills/penetration-testing/api-pentest/) | 1.2.0 | Non-destructive black-box API security assessment: recon → auth matrix → authz-scope proof → hardening → evidence-backed report, with OWASP API:2023 mapping and a 10-row coverage gate |
| [`api-retest-harness`](skills/penetration-testing/api-retest-harness/) | 0.1.1 | Turns a pentest evidence JSONL into a rerunnable probe script — remediation checks become one command with baseline deltas; credentials never enter generated artifacts |

## DFIR

| Skill | Version | Purpose |
|---|---|---|
| [`php2shell-detection`](skills/dfir/php2shell-detection/) | 1.0.0 | Detects php2shell (CVE-2026-109618/109619) exploitation across request, outcome and execution planes — exact multipart signatures and body hashes, startup-OOM/crash discriminators that survive HTTP 200, webshell-fetch sweep, a stdlib log scanner, and SIEM/Elastic/Splunk/KQL/WAF queries with a triage decision tree |

## Red Teaming

No skills published yet — the first one lands here when it is built. Scope and
ground rules are in [`skills/red-teaming/README.md`](skills/red-teaming/README.md).

## Adding a skill

1. Author it in the Hermes profile (`~/.hermes/skills/<category>/<name>/`) — start
   from [`skills/_template`](skills/_template/SKILL.md). Keep `SKILL.md` lean; depth
   goes in `references/`, automation in `scripts/`.
2. Sync it into the right domain:
   `./scripts/sync_skill.sh <domain> <name> [profile-category]` — copies from the
   profile **and runs the anonymization gate**. Domains: `penetration-testing`,
   `dfir`, `red-teaming`.
3. Review `git status`, commit, push. The gate (`scripts/publish_scrub.py` +
   `publish-scrub.json`) rewrites client/vendor-specific names to generic
   placeholders and **fails the sync** if any forbidden pattern survives —
   deployment-specific notes stay private, public copies stay generic.
4. Update the domain's own README table **and** the root table above — one row per
   skill, version included; bump the domain count.

## Install into Hermes

```bash
git clone https://github.com/0xAnalyst/hermes-cyber-skills.git
mkdir -p ~/.hermes/skills/<category>
cp -r hermes-cyber-skills/skills/<domain>/<skill-name> ~/.hermes/skills/<category>/
```

## Credits & provenance

- `penetration-testing/api-pentest/references/owasp-api-playbook.md` — adapted from
  [narlyseorg/superhackers](https://github.com/narlyseorg/superhackers) (`skills/api-pentesting`,
  MIT © 2025 Zoey): authorization-bypass preamble and framework couplings removed;
  upstream notice retained in the file header.
- `penetration-testing/api-pentest/references/owasp-api-mapping.md` — category definitions and CWE
  mappings from the official OWASP API Security Top 10 (2023) pages (owasp.org).
- `dfir/php2shell-detection` — signature basis is the public
  [0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data) report series
  (attempt-only and confirmed-RCE captures, Oct 2026) plus public PoC and vendor
  research; no honeypot data is redistributed.
- Third-party skills are **not mirrored** in this repo by owner decision — they are
  linked instead (e.g. `red-team-engagement` from
  [briiirussell/cybersecurity-skills](https://github.com/briiirussell/cybersecurity-skills), MIT).
- Skill behaviors were developed during real, authorized engagements; findings,
  hosts, and vendors of those engagements never enter this repo (enforced by the
  anonymization gate).

## Use responsibly

Each skill defines its own domain rules and safety rails in its `SKILL.md` — read
them before use. Skills that interact with live systems require explicit
authorization from the target owner; no skill file implies pre-authorization on
your behalf.
