---
name: hunt-execution
description: "Hunt Execution (TA0002) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0002, execution, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Execution (TA0002)

Code runs. The useful question is never "did a shell run" — it is which parent spawned it,
with which arguments, on which host role, and whether that shape exists in the baseline.
Execution is the most heavily logged tactic and therefore the one where baselining matters
more than detection content.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Execution.

## When to Use

- An encoded or obfuscated command line appears in process telemetry.
- An office suite, browser or web server spawns a script interpreter.
- A scheduled task, service or container starts something not in the deployment record.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | A script interpreter is spawned by an unexpected parent | T1059 | EDR: office, browser, web server or service parent → powershell/cmd/wscript/bash, especially with encoded arguments |
| H2 | A remote execution primitive runs commands on another host | T1047 / T1021 | wmic, winrs or PsExec-style service creation spawning children remotely |
| H3 | A scheduled task or service carries the payload | T1053 / T1543 | Task or service created with a binary in a user-writable or temp path |
| H4 | A container or CI runner executes something unexpected | T1610 / T1613 | Image pulled from an unknown registry, privileged pod, or binary absent from the build record |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **EDR process telemetry:** parent, command line, signer, hash, user, host role.
- **Windows security:** 4688 process creation, 4698 task creation, 7045 service install.
- **Linux:** auditd/execve, systemd unit changes.
- **CI/CD and Kubernetes audit logs** if containers are in scope.
- **Software inventory / allowlist** to define "expected" per host role.

## Procedure

1. **Build the parent→child baseline per host role.** Web servers, domain controllers,
   workstations and build agents have different normal shapes. *Done when each role has a
   written top-N parent/child map.*
2. **Find deviations.** Children outside the role baseline, ranked by rarity and signer.
   *Done when deviations are listed with full command lines.*
3. **Decode and attribute.** Base64/obfuscated arguments, signer validity, binary path.
   *Done when each deviation is decoded and attributed to a product, admin action or unknown.*
4. **Confirm with a second plane.** File write, network connection or child process from the
   same pid. *Done when each unknown has an execution consequence attached.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1059 Command and Scripting Interpreter | EDR process | parent is office/browser/web server; encoded arguments |
| T1047 WMI | EDR + WMI-Activity | wmic process call create targeting a remote host |
| T1053 Scheduled Task/Job | 4688/4698, cron | task action points at temp or user-writable path |
| T1204 User Execution | EDR | user-writable download directory followed by execution |
| T1106 Native API | EDR API telemetry | direct syscalls from binaries with no vendor lineage |

## Detection-grade output

Default severity **medium → high** (**47** for a lone odd child, **73** when the child also makes a network connection) — spawning a shell is common; spawning one and calling out is not.

Analytic type: EQL sequence (parent → child → connection); KQL for single-event role baselines.

Validation: admin platforms and installers must score below the threshold or the queue drowns; a synthetic positive must fire before it ships.
Conventions — severity mapping, required metadata, query hygiene: `hunt-method/references/detection-quality.md`.

## Pitfalls

- **Management platforms use the same primitives.** SCCM, PDQ, Ansible and monitoring agents
  spawn shells constantly — the parent and signer separate them from an intrusion.
- **Encoded PowerShell is common in vendor scripts.** Decode before escalating; provenance beats
  the word "encoded".
- **Estate-wide baselines hide role anomalies.** Baseline per host role or the important
  deviation disappears into the average.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
