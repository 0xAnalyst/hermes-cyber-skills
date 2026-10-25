---
name: hunt-lateral-movement
description: "Hunt Lateral Movement (TA0008) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0008, lateral-movement, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Lateral Movement (TA0008)

Moving between hosts. The discriminator has three parts: **remote**, **new pair**, and
**credential-bearing**. A logon from A to B that has never happened, using an account that
should not be there, is the finding — the protocol is secondary.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Lateral Movement.

## When to Use

- A new source→destination pair appears for an administrative protocol.
- An executable is written to a share and a service starts shortly after.
- Authentication succeeds with material that has no interactive history.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | A remote service logon uses an unusual account or pair | T1021 | 4624 type 3/10 between hosts that never talk, or by an account with no history there |
| H2 | Tooling is copied over a share and executed | T1570 | Executable written to an admin share followed by service creation or remote process start |
| H3 | Alternate authentication material is used | T1550 | NTLM logon without prior interactive logon, or ticket reuse from another host |
| H4 | Peer-to-peer remote desktop appears | T1021.001 | 4624 type 10 between two workstations |
| H5 | A remote session is hijacked or reused | T1563 | Session takeover indicators, disconnected-then-reconnected RDP from a different source |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Windows security logs:** 4624 with logon type, 4648 explicit credentials, 4672.
- **EDR network and process telemetry** for remote execution and share writes.
- **East-west firewall / netflow** for pair discovery.
- **Host role matrix** — which pairs are architecturally expected.

## Procedure

1. **Build the allowed pair matrix.** Role to role, service account to role, jump hosts.
   *Done when the matrix exists for the window.*
2. **Find pairs outside it.** Rank by rarity and account novelty. *Done when each pair has a
   sample logon and an account name.*
3. **Look for tool transfer.** Share writes followed by service/task creation on the target.
   *Done when each write is matched to a subsequent execution.*
4. **Check authentication material.** NTLM without interactive history, duplicate ticket use.
   *Done when each suspicious logon has a credential explanation.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1021 Remote Services | 4624/4648 | new source→destination pair, off-hours |
| T1570 Lateral Tool Transfer | EDR/SMB | executable in ADMIN$ then service creation |
| T1550 Use Alternate Authentication Material | DC/EDR | NTLM logon with no interactive history |
| T1563 Remote Session Hijacking | VPN/EDR | session reconnection from a different source |
| T1021.001 Remote Desktop Protocol | 4624 type 10 | workstation-to-workstation RDP |

## Observed in public case reports

Paraphrased from The DFIR Report case studies; sources and full chains in
`hunt-method/references/casebook.md`.

- Remote execution whose child processes are spawned by the **WMI provider host** is the
  fingerprint of WMI-based lateral movement (**C1**).
- Remote-desktop logons using an account created minutes earlier (**C3**), and remote service
  execution via a framework across many hosts (**C2**).
- SMB sweeps from the beachhead beginning about an hour after initial access precede the lateral
  phase (**C2**) — the sweep is the early warning.

## Pitfalls

- **Management, backup and AV move laterally by design.** Their service accounts and pairs
  belong in the matrix, not in the findings.
- **Jump hosts concentrate traffic.** A bastion makes dozens of pairs normal; scope by account.
- **Logon types are easy to misread.** Type 3 network logons include file-share access, which
  is not lateral movement on its own.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
