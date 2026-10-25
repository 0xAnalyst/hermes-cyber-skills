# hermes-skills

A collection of skills for [Hermes Agent](https://hermes-agent.nousresearch.com/docs) —
reusable, evidence-driven methodologies that load automatically when a task matches.

**Owner:** [0xanalyst](https://github.com/0xanalyst) · **License:** MIT

## Skills

| Skill | Version | Purpose |
|---|---|---|
| [`skills/api-pentest`](skills/api-pentest/) | 1.1.0 | Non-destructive black-box API security assessment: recon → auth matrix → authz-scope proof → hardening → evidence-backed report, with OWASP API:2023 mapping and a 10-row coverage gate |
| [`skills/api-retest-harness`](skills/api-retest-harness/) | 0.1.0 | Turns a pentest evidence JSONL into a rerunnable probe script — remediation checks become one command with baseline deltas; credentials never enter generated artifacts |
| [`skills/_template`](skills/_template/) | — | Scaffold for new skills — copy, rename, fill TODOs |

## Adding a skill

1. Author it in the Hermes profile (`~/.hermes/skills/<category>/<name>/`) — start
   from [`skills/_template`](skills/_template/SKILL.md). Keep `SKILL.md` lean; depth
   goes in `references/`, automation in `scripts/`.
2. Sync it in: `./scripts/sync_skill.sh <category> <name>` — copies from the profile
   **and runs the anonymization gate**.
3. Review `git status`, commit, push. The gate (`scripts/publish_scrub.py` +
   `publish-scrub.json`) rewrites client/vendor-specific names to generic
   placeholders and **fails the sync** if any forbidden pattern survives —
   deployment-specific notes stay private, public copies stay generic.

## Install into Hermes

```bash
git clone https://github.com/0xAnalyst/hermes-skills.git
mkdir -p ~/.hermes/skills/<category>
cp -r hermes-skills/skills/<skill-name> ~/.hermes/skills/<category>/
```

## Credits & provenance

- `api-pentest/references/owasp-api-playbook.md` — adapted from
  [narlyseorg/superhackers](https://github.com/narlyseorg/superhackers) (`skills/api-pentesting`,
  MIT © 2025 Zoey): authorization-bypass preamble and framework couplings removed;
  upstream notice retained in the file header.
- `api-pentest/references/owasp-api-mapping.md` — category definitions and CWE
  mappings from the official OWASP API Security Top 10 (2023) pages (owasp.org).
- `web-pentest` (MIT © Teknium, Hermes catalog) and `red-team-engagement`
  (MIT © 2026 Bri Russell,
  [briiirussell/cybersecurity-skills](https://github.com/briiirussell/cybersecurity-skills))
  are **not included by owner decision** — this repo carries only original
  content; third-party skills are linked, not mirrored.
- `api-pentest` auth-matrix/scope-proof behaviors and the gateway fault taxonomy
  were developed during real authorized engagements (SOAP services behind a
  commercial API gateway).

## Use responsibly

These skills encode **authorized-engagement** methodologies. Confirm written
authorization and scope before testing anything; no skill file implies
pre-authorization on your behalf.
