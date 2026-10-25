---
name: hunt-discovery
description: "Hunt Discovery (TA0007) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0007, discovery, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Discovery (TA0007)

Mapping the inside: accounts, hosts, services, permissions, cloud resources. Low fidelity on
its own and high fidelity when attached to an identity or host you already distrust. Hunt
identity-scoped bursts, not estate-wide ones.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Discovery.

## When to Use

- An identity queries the directory at unusual volume or breadth.
- One host sweeps ports or hosts it has no reason to talk to.
- A cloud principal enumerates resources it does not own.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | An identity enumerates accounts, groups or permissions | T1087 / T1069 | Directory queries or 4661/4662 volume far above that identity's baseline |
| H2 | A host performs network or service discovery | T1046 / T1018 | One source to many destinations or ports inside the same subnet, especially from a workstation |
| H3 | System information discovery clusters on a server | T1082 / T1057 | whoami, systeminfo, tasklist, uname bursts on hosts where that is rare |
| H4 | A cloud principal enumerates resources | T1526 / T1619 | Describe/List API bursts across services the principal never used |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Directory audit** with LDAP query logging where available.
- **Firewall and netflow** for internal east-west traffic.
- **EDR process telemetry** for discovery utility execution.
- **Cloud audit logs** with principal and API name.
- **Scanner and inventory-agent inventory** — the primary deconfliction set.

## Procedure

1. **Baseline enumeration per role and identity.** Admins, service accounts, scanners and
   inventory agents all enumerate. *Done when the expected enumerators are listed.*
2. **Find identity-scoped bursts.** Volume and breadth above that identity's own baseline.
   *Done when each burst has an identity, a target set and a time window.*
3. **Exclude sanctioned tooling.** Scanner ranges, agents, scheduled audit jobs.
   *Done when remaining bursts are unexplained.*
4. **Pivot to consequence.** What did the identity or host do next — logon, file access,
   connection? *Done when each burst is either benign or attached to a later tactic.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1087 Account Discovery | Directory audit | query volume far above the identity's baseline |
| T1046 Network Service Discovery | Firewall/netflow | one internal source, many ports, short window |
| T1018 Remote System Discovery | Netflow/EDR | sweep-shaped ICMP/ARP/SMB from a workstation |
| T1082 System Information Discovery | EDR process | discovery utilities on a server role where they are rare |
| T1526 Cloud Service Discovery | Cloud audit | Describe/List burst across unused services |

## Pitfalls

- **Vulnerability scanners and inventory agents do exactly this.** Range plus cadence plus
  service account identifies them; check first.
- **Admin scripts enumerate a lot.** A scheduled hygiene script can out-volume an attacker.
- **Host-based conclusions mislead.** Discovery from a compromised workstation is normal
  workstation noise — correlate to the identity instead.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
