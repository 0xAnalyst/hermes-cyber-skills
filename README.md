# hermes-skills

A growing collection of skills for [Hermes Agent](https://hermes-agent.nousresearch.com/docs) —
reusable, evidence-driven methodologies that load automatically when a task matches.
New skills land here as they're built; every skill is self-contained and follows the
same layout and quality conventions.

**Owner:** [0xanalyst](https://github.com/0xanalyst) · **License:** MIT

## Skills

| Skill | Version | Purpose |
|---|---|---|
| [`skills/api-pentest`](skills/api-pentest/) | 1.2.0 | Non-destructive black-box API security assessment: recon → auth matrix → authz-scope proof → hardening → evidence-backed report, with OWASP API:2023 mapping and a 10-row coverage gate |
| [`skills/api-retest-harness`](skills/api-retest-harness/) | 0.1.1 | Turns a pentest evidence JSONL into a rerunnable probe script — remediation checks become one command with baseline deltas; credentials never enter generated artifacts |
| [`skills/php2shell-detection`](skills/php2shell-detection/) | 1.0.0 | Detects php2shell (CVE-2026-109618/109619) exploitation across request, outcome and execution planes — exact multipart signatures and body hashes, startup-OOM/crash discriminators that survive HTTP 200, webshell-fetch sweep, a stdlib log scanner, and SIEM/Elastic/Splunk/KQL/WAF queries with a triage decision tree |
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
4. Update the Skills table above — one row per skill, version included.

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
