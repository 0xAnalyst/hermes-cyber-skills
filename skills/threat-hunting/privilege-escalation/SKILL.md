---
name: hunt-privilege-escalation
description: "Hunt Privilege Escalation (TA0004) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0004, privilege-escalation, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Privilege Escalation (TA0004)

Gaining rights the account should not have: token abuse, elevation exploits, or legitimate
admin tooling driven by a non-admin identity. Often the shortest-lived tactic — the evidence
is a handful of events around an elevation moment.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Privilege Escalation.

## When to Use

- A process runs with another user's token or an unexpected integrity level.
- An unsigned driver loads, or a kernel fault coincides with exploitation artifacts.
- A privileged role or sudoers entry changes outside an approval.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | A process uses another identity's token | T1134 | EDR token events: token user differs from process owner, or SeDebugPrivilege enabled unexpectedly |
| H2 | A local elevation exploit was used | T1068 | Unsigned driver load, kernel crash, or exploitation-shaped syscall sequence on a patched-expectation host |
| H3 | An elevation-control bypass ran | T1548 | Auto-elevating binaries spawning children, or sudoers/setuid changes |
| H4 | Privilege was granted rather than taken | T1098 / T1078 | Role assignment or group add outside the approval workflow, followed by immediate use |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **EDR token and handle telemetry**, including integrity level and privilege use.
- **Windows security:** 4672 special privileges, 4673 privileged service use.
- **Linux:** sudo logs, setuid/sudoers file integrity.
- **Directory and cloud role changes** with approvals.
- **Driver load events** and their signers.

## Procedure

1. **Baseline privileged token use by host role.** Which services legitimately impersonate.
   *Done when the expected set is written down.*
2. **Find cross-identity tokens.** Processes whose token user differs from the session owner.
   *Done when each is attributed to a product, an admin action, or unknown.*
3. **Check driver loads and kernel events.** Unsigned drivers, crash-plus-artifact pairs.
   *Done when each load has a signer and purpose.*
4. **Review grants.** Role/group changes against approvals, then look for use within hours.
   *Done when every unexplained grant is flagged with a named approver question.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1134 Access Token Manipulation | EDR token events | token user differs from process owner |
| T1068 Exploitation for Privilege Escalation | EDR/driver load | unsigned driver or exploitation artifact on a patched host |
| T1548 Abuse Elevation Control Mechanism | EDR | auto-elevating binary spawning a child with higher integrity |
| T1098 Account Manipulation | Directory/cloud audit | role grant outside approval, then immediate use |
| T1055 Process Injection | EDR | remote thread into a privileged process |

## Detection content

### Service created by a user identity
Services run as SYSTEM. A service install whose creating identity is a normal user is elevation by
definition — no exploit signature required.

```kql
event.code : "7045" and not user.name : ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "*$")
```

*Needs:* System channel 7045 with the creating identity in `user.name`; verify your log pipeline
actually populates it, otherwise this query silently matches nothing.

### Elevation-control bypass
Auto-elevating binaries are allowlisted by Windows itself, which is exactly why they are abused.
The child is the signal.

```kql
process.parent.name : ("fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe")
  and process.name : ("cmd.exe", "powershell.exe", "mshta.exe")
```

*Needs:* process events with `process.parent.name`.

### Sudoers or setuid change
On Linux, privilege is usually granted by editing a file — watch the file.

```kql
file.path : ("/etc/sudoers", "/etc/sudoers.d/*") and event.action : ("change", "created", "modified")
```

*Needs:* file integrity monitoring or auditd `file.path` events.

## Pitfalls

- **Backup and security agents impersonate by design.** A cross-identity token from a signed
  service is expected; the same shape from an unsigned binary is not.
- **Admin scripts elevate routinely.** Deconflict with scheduled jobs before escalating.
- **Kernel faults have innocent causes.** Driver bugs crash too — require the exploitation
  artifact, not just the crash.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
