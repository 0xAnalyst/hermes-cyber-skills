---
name: hunt-impact
description: "Hunt Impact (TA0040) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0040, impact, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Impact (TA0040)

Destruction, encryption, denial. This tactic is time-critical: by the time the pattern is
unambiguous, the damage is underway. The observable is usually a **mass file operation or a
recovery-inhibition command minutes before a ransom note** — treat it as a page, not a report.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Impact.

## When to Use

- A mass file write, rename or deletion burst on a server or share.
- Shadow copies or backups are deleted, or recovery is disabled.
- Many services stop at once on one host or across a fleet.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | Data is being encrypted at volume | T1486 | Write burst plus extension or header changes plus recovery tampering |
| H2 | Recovery is being inhibited | T1490 | Shadow copy deletion, backup service stopped, boot configuration changed |
| H3 | Services are being stopped en masse | T1489 | Multiple service stops by one identity within minutes |
| H4 | Data is destroyed or a public site is defaced | T1485 / T1491 | Deletion burst on shares, or web-root content modified then served |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **EDR file telemetry** with write/rename rates and entropy where available.
- **File integrity monitoring** for critical paths and web roots.
- **Storage/hypervisor alerts** for datastore-level anomalies.
- **Backup job logs** — both the baseline and the target of H2.

## Procedure

1. **Detect the mass-write shape.** Rate of writes/renames per host against baseline.
   *Done when a candidate host and start time are identified.*
2. **Check recovery tampering immediately.** Shadow copy deletion, backup stop, boot config.
   *Done when recovery state is confirmed intact or compromised.*
3. **Census service stops.** One identity, many services, short window.
   *Done when the pattern is attributed or ruled out.*
4. **Escalate without waiting for completeness.** Preserve evidence, isolate the host, notify.
   *Done when containment is underway and the first report is out.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1486 Data Encrypted for Impact | EDR file | write burst plus extension change plus recovery tampering |
| T1490 Inhibit System Recovery | EDR process | shadow copy or backup deletion commands |
| T1489 Service Stop | Service logs | mass stop by one identity in minutes |
| T1485 Data Destruction | EDR file | deletion burst across shares |
| T1491 Defacement | FIM/web | web root modified then served publicly |
| T1498 Network Denial of Service | Netflow | volumetric traffic originating inside |

## Detection content

### Mass file writes on one host
Encryption is a write storm. Rate per host is the signal; the extension change is confirmation.

```esql
from logs-endpoint.events.file-*
| where event.type in ("creation", "change", "rename")
| stats n = count() by host.name, bucket = bucket(@timestamp, 5 minutes)
| where n >= 500
```

*Needs:* file events with `host.name`; compare with backup windows, which produce the same shape on
file servers.

### Recovery inhibition commands
A short, brutal list. If any of these runs outside a change window, escalate before confirming
anything else.

```kql
process.command_line : (
  "*vssadmin*delete*shadows*", "*wmic*shadowcopy*delete*", "*wbadmin*delete*catalog*",
  "*bcdedit*/set*recoveryenabled*no*", "*Win32_ShadowCopy*Delete*", "*schtasks*/delete*/tn*"
)
```

*Needs:* process command lines; this query should be paired with an immediate paging action, not a
queue.

## Pitfalls

- **Backup software performs mass file operations.** Compare to the job schedule; a backup
  window explains far more write bursts than an intrusion does.
- **Installers stop services.** Mass stop during a patch cycle is expected — check the change
  record, but not before checking the clock.
- **Test labs run destructive samples.** Isolate known lab hosts early; do not let them slow the
  response to a real one.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
