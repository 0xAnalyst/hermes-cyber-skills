---
name: hunt-persistence
description: "Hunt Persistence (TA0003) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0003, persistence, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Persistence (TA0003)

Survival across reboot. Attackers are conventional here and defenders are noisy: the
discriminator is not the mechanism but the **location, the signer, and who created it** —
plus whether a change record explains it.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Persistence.

## When to Use

- A new autostart entry, service, driver, scheduled task or account appears.
- A file lands in a web root, module directory or package path and is then executed.
- A rebuild or patch cycle is followed by unexpected startup items.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | An autostart entry points into a user-writable path | T1547 / T1546 | Run keys, startup folder, systemd user units or LaunchAgents referencing temp/appdata |
| H2 | A service or driver was installed from an unsigned binary | T1543 | 7045 install whose ImagePath is outside system directories or whose signer is invalid |
| H3 | A scheduled task hides its action | T1053 | Task with encoded arguments, hidden flag, or a name masquerading as a vendor job |
| H4 | An account was created or granted privilege outside workflow | T1136 / T1098 | 4720/4728/4732 with no matching HR or change record |
| H5 | A server component was dropped into an application path | T1505 | New script/module in a web or app directory followed by requests to it |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Autoruns / persistence inventory** from EDR or a collector, with signer and path.
- **Service installs:** 7045 and Linux unit creation.
- **Account changes:** 4720/4728/4732, directory audit, IdP role assignments.
- **File integrity monitoring** on web roots and application directories.
- **Change and deployment records** — the deconfliction set for every hit.

## Procedure

1. **Inventory persistence per host role.** What legitimately starts on a web server, a DC,
   a build agent. *Done when each role has an expected-persistence list.*
2. **Filter to suspicious attributes.** User-writable path, unsigned binary, hidden action,
   recently created, or created by an identity that does not normally do so.
   *Done when the filtered list is written down with attributes.*
3. **Map to change records.** Deployment, patch, monitoring onboarding.
   *Done when each remaining item is either explained or flagged.*
4. **Confirm the persisted item executes.** Process start, network connection, or the file
   being served. *Done when every flagged item has an execution consequence.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1547 Boot or Logon Autostart | Registry/EDR autoruns | Run key value pointing into temp or appdata |
| T1543 Create or Modify System Process | 7045, systemd | service binary unsigned or outside system paths |
| T1053 Scheduled Task/Job | 4698, cron | encoded action or SYSTEM context from an unusual creator |
| T1136 Create Account | 4720, directory audit | account created outside onboarding workflow |
| T1505 Server Software Component | EDR file + web logs | new script in a served directory, then GET/POST to it |

## Detection-grade output

Default severity **high** (**73**) — a startup item nobody can explain survives reboots — that is working access.

Analytic type: first-seen (`new_terms`) on service, task and autostart names; KQL per mechanism.

Validation: deployment agents must match an allowlist entry, not a blanket suppression; a synthetic positive must fire before it ships.
Conventions — severity mapping, required metadata, query hygiene: `hunt-method/references/detection-quality.md`.

## Pitfalls

- **Patch and monitoring agents create services and tasks legitimately.** Compare to the
  deployment record before escalating; the mechanism alone proves nothing.
- **Developers create local accounts.** Check the HR/onboarding feed and the account's first use.
- **Web roots receive uploads by design.** The question is whether the dropped file is served
  as executable content — not whether it exists.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
