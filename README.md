# api-pentest — Hermes Agent skill

Non-destructive, black-box security assessment of documented HTTP APIs (REST,
GraphQL, gRPC, WebSocket, SOAP) — designed for [Hermes Agent](https://hermes-agent.nousresearch.com/docs)
but the methodology is agent-agnostic markdown.

**Author:** [0xanalyst](https://github.com/0xanalyst) · **Version:** 1.1.0 · **License:** MIT

## What it does

Structured engagement workflow: inventory → recon (DNS/TLS/certs) → schema
exposure → auth matrix → authorization-scope proof → hardening checks →
evidence-backed report with severities calibrated to the deployment's actual
threat model (internally hosted vs internet-exposed).

Hard safety rails are built in: no valid payloads against write APIs (empty-body
auth-pass proofs only), no bulk data extraction (zero-row filter probes), full
request/response JSONL evidence logging, PII masking in chat output, and a
request budget (~40–60 requests per ~15-API inventory).

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Procedure, always-on rules, pitfalls |
| `references/non-destructive-probes.md` | Inert-request recipes: write-API auth proof, zero-row PII probes, XXE single-entity, rate-limit sizing, masking |
| `references/gateway-gateway.md` | gateway/CA gateway fault taxonomy, apikey placement behavior, SOAP probe crafting, WSDL leak patterns |
| `references/owasp-api-playbook.md` | Full OWASP API Top 10 technique playbook (REST/GraphQL/gRPC/WS/SOAP) |
| `references/owasp-api-mapping.md` | OWASP API:2023 engagement mapping — official CWEs, credential-set → testable-categories matrix, gateway detection signals, worked example, report coverage gate, 2019→2023 crosswalk |

## Install (Hermes)

Copy into the profile's skills directory:

```bash
git clone https://github.com/0xanalyst/api-pentest.git
mkdir -p ~/.hermes/skills/security
cp -r api-pentest/skills/api-pentest ~/.hermes/skills/security/
```

The skill loads automatically when an API security assessment is requested.

## Provenance & credits

- `references/owasp-api-playbook.md` is adapted from
  [narlyseorg/superhackers](https://github.com/narlyseorg/superhackers)
  (`skills/api-pentesting`, MIT © 2025 Zoey) — with the self-asserted
  authorization preamble and framework couplings removed, and Hermes-native
  tooling notes added. MIT notice retained in the file header.
- `references/owasp-api-mapping.md` CWE mappings are taken from the official
  OWASP API Security Top 10 (2023) pages (owasp.org), fetched 2026-10-25.
- Auth matrix, scope-proof and gateway behaviors were developed during a real
  authorized assessment of SAP SOAP services behind a gateway API gateway.

## Use responsibly

This skill encodes an **authorized-engagement** methodology: confirm written
authorization and scope before testing; the skill refuses to imply
pre-authorization on your behalf.
