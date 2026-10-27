---
name: hunt-exfiltration
description: "Hunt Exfiltration (TA0010) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0010, exfiltration, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Exfiltration (TA0010)

Data leaving. Volume is the weakest signal in this tactic; **channel purpose and data
sensitivity** are the strongest. The question is not "how many megabytes" but "what kind of
destination, from what kind of host, carrying what kind of data".

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Exfiltration.

## When to Use

- A server role uploads to personal storage, paste or transfer services.
- Egress volume from a host exceeds its baseline outside business hours.
- Cloud audit shows data copied to an external account or shared publicly.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | Bulk data is uploaded to a web service | T1567 | Large POST to storage, paste or file-transfer categories from a host that never does that |
| H2 | Data leaves over a non-web protocol | T1048 | Payload-size volume on DNS, SMTP, ICMP or an unusual port |
| H3 | A transfer tool runs on a host that should not have one | T1048.003 | rclone, curl upload, scp, ftp, 7z-then-upload on a server or workstation |
| H4 | Cloud data is copied to another account | T1537 | Snapshot share, cross-account copy, public bucket policy change |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Proxy with URL categories** and bytes sent.
- **Egress firewall and netflow**, including non-standard ports.
- **Cloud audit logs** for storage and identity actions.
- **DLP or data classification** to judge sensitivity.
- **Backup, replication and sync inventory** — the baseline that explains most volume.

## Procedure

1. **Rank egress by host role.** Bytes out per host against its own baseline.
   *Done when outliers are listed with destination and volume.*
2. **Categorise destinations.** Storage, paste, transfer, personal cloud, unknown.
   *Done when each outlier has a category and an owner question.*
3. **Identify the tooling.** Process behind the connection, plus archive activity before it.
   *Done when each transfer has a producing process.*
4. **Judge sensitivity with the data owner.** Classification beats byte counts.
   *Done when the owner has confirmed what the data was.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1567 Exfiltration Over Web Service | Proxy | upload to storage/paste category from a server role |
| T1048 Exfiltration Over Alternative Protocol | Firewall/netflow | large outbound on 53/25/123 or unusual ports |
| T1041 Exfiltration Over C2 Channel | Netflow | egress volume correlated with a known C2 session |
| T1537 Transfer Data to Cloud Account | Cloud audit | cross-account copy or public share |
| T1029 Scheduled Transfer | Netflow | recurring large transfers outside business hours |

## Detection content

### Outbound-dominant transfer by host role
Direction is the discriminator: a server that mostly sends is either replicating or leaking, and the
destination category decides which.

```esql
from logs-network_traffic-*
| stats out = sum(source.bytes), in = sum(destination.bytes)
        by host.name, destination.ip, bucket = bucket(@timestamp, 1 hour)
| where out > 100000000 and out > in * 10
```

*Needs:* flow or proxy byte counters per host; overlay your backup and replication jobs before
calling anything a finding.

### Upload to storage, paste or transfer services
Conventional channels are the most common exfiltration path because they are allowed.

```kql
http.request.method : "POST"
  and url.category : ("cloud storage", "file sharing", "webmail", "paste")
  and source.bytes >= 1000000
```

*Needs:* proxy logs with URL category and request/response byte fields.

## Pitfalls

- **Backups and replication look identical.** Large scheduled transfers are usually legitimate;
  compare to the job inventory before escalating.
- **SaaS sync is normal.** OneDrive, Teams, Drive and Box move data constantly at OS level.
- **Byte counts inflate.** Retransmits and compression distort volume comparisons — use flow
  records, not interface counters.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
