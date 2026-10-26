---
name: hunt-credential-access
description: "Hunt Credential Access (TA0006) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0006, credential-access, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Credential Access (TA0006)

Credential theft. Every high-signal indicator here has a loud legitimate twin: security
agents read process memory, backup software authenticates with Kerberos all day, and users
mistype passwords in bursts. The discriminator is the **signer and purpose** of the actor,
plus what the stolen material is used for next.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Credential Access.

## When to Use

- A non-security process opens a handle to a credential store or process memory.
- Kerberos or NTLM authentication fails in an unusual pattern from one source.
- A credential file, key or token is read from an unexpected location.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | A non-security process reads credential memory | T1003 | Handle open to the credential process with read rights, or a dump file appearing on disk |
| H2 | Kerberos tickets are abused or forged | T1558 | RC4 downgrade on a modern estate, abnormal ticket volume or lifetime, service tickets for many services from one account |
| H3 | A password spray runs against an identity provider | T1110 | Many accounts, few attempts each, one source/ASN, usernames in alphabetical or directory order |
| H4 | Credentials are read from files, configs or metadata services | T1552 | Reads of credential-shaped files, or requests to instance metadata endpoints from non-cloud workloads |
| H5 | A browser or password store is accessed by an unexpected process | T1555 | Credential database read by a binary with no browser lineage |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **EDR handle/process telemetry** for credential processes, with signer.
- **Domain controller security:** 4768/4769/4771, plus NTLM audit if available.
- **Identity provider** sign-in failures and MFA results.
- **Cloud audit** for metadata/secret-manager access.
- **DLP or file-access logs** for credential stores, plus secret-scanning output.

## Procedure

1. **Census credential-process access by signer.** Security agents, backup tools, and
   legitimate diagnostics first. *Done when every accessing binary is named and signed.*
2. **Baseline Kerberos per account and host.** Encryption types, ticket volume, lifetimes.
   *Done when each anomaly has an account and a host.*
3. **Detect spray shape, not failure count.** Normalise by source ASN and account set.
   *Done when each candidate matches the many-accounts-few-attempts pattern.*
4. **Check secret-file and metadata access.** *Done when reads are attributed to an app or flagged.*
5. **Confirm with use.** A successful authentication from the targeted identity shortly after.
   *Done when each theft lead is linked to a subsequent session or dismissed.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1003 OS Credential Dumping | EDR handle/process | credential process accessed by unsigned or non-security binary |
| T1558 Steal or Forge Kerberos Tickets | DC 4768/4769 | RC4 downgrade, abnormal ticket lifetime or volume |
| T1110 Brute Force | IdP, VPN, DC | many users, low attempts each, single source |
| T1552 Unsecured Credentials | EDR/file/cloud | credential-shaped file reads, metadata endpoint access |
| T1555 Credentials from Password Stores | EDR | credential database touched by a non-browser process |

## Detection-grade output

Default severity **critical** (**99** when a dump is followed by use, **73** for the dump alone) — a dump plus subsequent authentication is working access; the dump alone is a strong lead.

Analytic type: EQL sequence (credential-process access → dump file → authentication); KQL for spray shape.

Validation: security products read credential memory by design; a synthetic positive must fire before it ships.
Conventions — severity mapping, required metadata, query hygiene: `hunt-method/references/detection-quality.md`.

## Pitfalls

- **Security products read credential memory by design.** Signer and product lineage decide;
  the access event alone is meaningless.
- **Backups authenticate heavily.** Service accounts generate ticket volume that looks like
  abuse — baseline per account before setting thresholds.
- **Helpdesk activity mimics spray.** Password resets and lockouts cluster; check the ticketing
  system for a cause before escalating.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
