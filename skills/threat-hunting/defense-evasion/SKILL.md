---
name: hunt-defense-evasion
description: "Hunt Defense Evasion (TA0005) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0005, defense-evasion, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Defense Evasion (TA0005)

Hiding. The most serious hunt in this tactic is not obfuscation — it is **your own telemetry
being reduced**: sensors disabled, exclusions added, logs cleared. A quiet lane is the first
thing to explain, not the last.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Defense Evasion.

## When to Use

- A security agent is stopped, excluded or reconfigured.
- A log source clears or stops reporting without a network explanation.
- A signed system binary is used to launch something remote or scripted.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | Security tooling was disabled or excluded | T1562 | Agent stop, policy change, path/process exclusion added, protection disabled |
| H2 | Logs or artifacts were deleted | T1070 | 1102 log cleared, event source silence, evidence files removed |
| H3 | A system binary proxies execution | T1218 | rundll32, mshta, regsvr32, cscript fetching or loading remote content |
| H4 | A binary masquerades as a system component | T1036 / T1553 | Unsigned or wrongly signed binary in a system path, double extension, validation disabled |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **EDR/AV policy and tamper events** with actor identity.
- **Windows 1102/104** and per-source event volume/heartbeat.
- **File integrity** on system directories and web roots.
- **Change tickets** for troubleshooting that legitimately disables protection.

## Procedure

1. **Prove the lane is alive.** Heartbeat and event volume per source for the window.
   *Done when every silent source is either explained or flagged as a blind spot.*
2. **Review tamper events by identity.** Who disabled what, when, with which ticket.
   *Done when each tamper event is attributed or escalated.*
3. **Hunt proxy execution with network correlation.** LOLBins that also make a connection.
   *Done when each has a decoded command line and destination.*
4. **Check masquerading.** Unsigned binaries in system paths, invalid signature chains.
   *Done when each is attributed to a product or flagged.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1562 Impair Defenses | EDR/AV policy audit | exclusion or stop event with an actor identity |
| T1070 Indicator Removal | 1102/104, source silence | log cleared or source stops mid-window |
| T1218 System Binary Proxy Execution | EDR | LOLBin with remote URL or script argument |
| T1036 Masquerading | EDR file metadata | unsigned binary in a system directory |
| T1027 Obfuscated Files or Information | EDR command line | high-entropy payload or layered base64 |
| T1553 Subvert Trust Controls | EDR | signature validation disabled or trust store modified |

## Detection content

### Audit log cleared
Two event IDs, almost no benign population outside a documented maintenance window.

```kql
event.code : ("1102", "104") or event.action : "audit-log-cleared"
```

*Needs:* Security channel; document accepted maintenance windows instead of suppressing.

### Source went quiet
Silence is a finding only when compared with the same source's own history — this query makes the
comparison explicit rather than assuming it.

```esql
from logs-endpoint.events.process-*
| stats c = count() by host.name, bucket = bucket(@timestamp, 1 hour)
| where c < 10
```

*Needs:* any high-volume source with per-host-per-hour history; run against a 7-day window so
"quiet" has a denominator.

### System binary with an outbound connection
Proxy execution matters when the proxy also phones home.

```eql
sequence by host.name with maxspan=2m
  [process where event.type == "start" and
     process.name in ("rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")]
  [network where event.type == "start" and destination.ip != null]
```

*Needs:* process plus network events; add vendor allowlists for signed update paths only after
verifying them.

## Pitfalls

- **IT disables protection during troubleshooting.** Check tickets before escalating; the
  absence of a ticket is the finding, not the configuration change itself.
- **Installers use LOLBins.** Package managers and updaters legitimately call regsvr32/mshta.
- **Silence is often plumbing.** A stopped sensor usually means a network or capacity problem —
  confirm before calling it tampering.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
