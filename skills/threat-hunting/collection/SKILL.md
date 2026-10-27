---
name: hunt-collection
description: "Hunt Collection (TA0009) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0009, collection, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Collection (TA0009)

Gathering data before it leaves. Usually invisible until it touches mail, file shares or
archives — so hunt the **staging artifact**: a forwarding rule, a bulk read, an archive file
in a temp directory, a capture process on an endpoint.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Collection.

## When to Use

- A mailbox forwarding rule or delegate is created.
- A user or service account reads far more share data than usual.
- An archive tool runs on a server role outside the backup window.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | Mail is collected or forwarded | T1114 | Inbox rule creation, forwarding to an external address, mass message read |
| H2 | Share data is staged for removal | T1039 / T1074 | Bulk read by a non-owner followed by a staging directory growing |
| H3 | Data is archived on a server | T1560 | compress/rar/7z on a server role, large output, outside backup schedule |
| H4 | Screen or input capture runs on an endpoint | T1113 / T1056 | Capture APIs invoked by a binary with no collaboration lineage |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Mail platform audit** (Exchange/O365/Google): rule creation, forwarding, delegate grants.
- **File-server access logs** with identity and volume.
- **EDR process/file telemetry** for archive tools and staging directories.
- **Backup and archive schedules** — the baseline for H3.

## Procedure

1. **Audit mail rules.** Creation events, external forwarding, unusual delegates.
   *Done when every rule is attributed to a user action or flagged.*
2. **Rank share reads by identity.** Volume against that identity's own baseline.
   *Done when outliers have target paths and sizes.*
3. **Compare archive jobs to schedule.** Server-role archiving outside backup windows.
   *Done when each job is explained or flagged.*
4. **Watch staging.** Directory growth followed by compression or transfer.
   *Done when staged data is matched to an egress attempt.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1114 Email Collection | Mail audit | external forwarding rule or mass read |
| T1039 Data from Network Shared Drive | File audit | bulk read by a non-owner identity |
| T1074 Data Staged | EDR file | staging directory growth before transfer |
| T1560 Archive Collected Data | EDR process | archive tool on a server role outside schedule |
| T1113 Screen Capture | EDR | capture API in an unexpected binary |

## Detection content

### Mailbox rule forwarding externally
The rule itself is common; the external destination is the finding.

```kql
event.dataset : "o365.audit" and event.action : ("New-InboxRule", "Set-InboxRule")
  and winlog.event_data.Parameters : ("*ForwardTo*", "*RedirectTo*", "*ForwardAsAttachmentTo*")
```

*Needs:* M365/Exchange audit with rule parameters; compare the destination domain against your
tenant's own domains and partner list.

### Archive tool on a server role
Servers do not usually compress user data interactively; the tool plus the host role is the signal.

```kql
event.category : "process" and process.name : ("7z.exe", "7za.exe", "rar.exe", "winrar.exe", "tar")
  and host.name : ("*srv*", "*sql*", "*fs0*", "*app*")
```

*Needs:* process events; the host-name pattern is a placeholder for your real server naming
convention or asset lookup.

### Share read volume by identity
Collection before exfiltration looks like a user reading far more than they own.

```esql
from logs-filebeat-*, logs-windows.security-*
| where event.code == "5145"
| stats files = count(), distinct_files = count_distinct(file.name) by user.name, host.name
| where files >= 500
```

*Needs:* Windows 5145 detailed file share audit enabled — without it this hunt is unanswerable, so
say so rather than reporting zero.

## Pitfalls

- **Archiving is routine.** Log rotation, backups and packaging all compress; compare to the
  schedule and the account.
- **Inbox rules are common.** Mobile clients and delegation create them legitimately — check
  the destination address, not the existence of the rule.
- **Size is not intent.** A legitimate reporting job can move more data than an intruder.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
