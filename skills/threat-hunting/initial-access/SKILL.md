---
name: hunt-initial-access
description: "Hunt Initial Access (TA0001) activity: hypotheses, telemetry, discriminators."
version: 0.1.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-hunting, mitre-attack, ta0001, initial-access, detection]
    category: threat-hunting
    related_skills: [hunt-method]
---

# Hunt: Initial Access (TA0001)

The first foothold: an exploited edge service, stolen credentials, phishing, or an abused
remote-access path. The discriminator is almost never the request itself — scanners produce
exploit-shaped traffic all day — it is what happened **after**: a child process, a file write,
a session that behaves like a human.

Read `hunt-method` first — it defines the hypothesis loop, evidence rules and output
contract. This skill supplies what is specific to Initial Access.

## When to Use

- A vulnerability disclosure affects a product you expose (patch-diff or CVE feed).
- An identity or VPN sign-in looks anomalous in source, time or device.
- A user reports executing an attachment or entering credentials.

## Hunt hypotheses

| # | Hypothesis | ATT&CK | Observable that proves it |
|---|---|---|---|
| H1 | An internet-facing application was exploited | T1190 | Exploit-shaped request followed by a worker-child process, web-root file write, or outbound connection from the app host |
| H2 | Valid credentials were used from unfamiliar infrastructure | T1078 | Successful sign-in after a failure burst, new ASN/country, new device, MFA prompt storm |
| H3 | An external remote service was entered from an unusual source | T1133 | VPN/RDP/SSH session from a new country or ASN, off-hours, unusually long or concurrent |
| H4 | A phishing attachment was executed | T1566 / T1204 | Mail delivery → archive/office document open → script interpreter child process |

## Inputs required

Fill these in before running — the hunt is unanswerable without them:

- **Edge request logs** (WAF/CDN/reverse proxy) with body visibility if it exists — note when it does not.
- **EDR process trees** for the web tier and user endpoints, with parent, command line and signer.
- **Identity telemetry:** IdP sign-ins, MFA events, VPN/firewall sessions.
- **Mail gateway** delivery and attachment metadata.
- **App inventory:** which hosts run which runtime and version — the exposure map you hunt against.

## Procedure

1. **Map exposure first.** Which internet-facing apps run which product/version, and which of
   them are unpatched against a live disclosure. *Done when the exposed-version table exists.*
2. **Hunt exploit shape at the edge.** Requests matching the disclosure's signature, then join
   to process events on the same host in the next minutes. *Done when every candidate request has
   an outcome (blocked, redirected, or process observed).*
3. **Hunt identity anomalies.** New-ASN success, failure-then-success, impossible travel, MFA
   fatigue. *Done when each anomalous session is attributed to a user or an automation.*
4. **Confirm with a second plane.** A request alone is an attempt; request plus process, or
   session plus endpoint activity, is a compromise. *Done when each lead is one or the other.*

## Techniques in scope

| Technique | Primary telemetry | Discriminator |
|---|---|---|
| T1190 Exploit Public-Facing Application | WAF + EDR process | exploit request then worker-child shell or web-root write |
| T1078 Valid Accounts | IdP, VPN | success after failure burst, new ASN, new device |
| T1133 External Remote Services | VPN/firewall | new country plus off-hours plus long session |
| T1566 Phishing | Mail gateway | attachment delivered, then a process chain on the recipient host |
| T1195 Supply Chain | Vendor telemetry | largely out of internal view — track advisories instead |

## Detection-grade output

Default severity **medium → high** (**47** for attempts, **73** once a second plane confirms) — the request is cheap and constant; the join to execution is what proves a foothold.

Analytic type: EQL sequence (request → child process or file write on the same host); KQL for the auth filter.

Validation: blocked scanners stay at medium, edge-only exploit attempts must not page; a synthetic positive must fire before it ships.
Conventions — severity mapping, required metadata, query hygiene: `hunt-method/references/detection-quality.md`.

## Pitfalls

- **Scanners generate exploit-shaped 403s constantly.** Volume of exploit attempts is not
  compromise; the join to process/file evidence is what decides it.
- **Travel and new devices are normal.** Confirm with the account owner before calling a
  sign-in malicious; impossible travel is frequently a VPN egress change.
- **Body blindness.** If the edge cannot inspect POST bodies, request-plane exploitation is
  unobservable — state that instead of implying a clean result.

## Output contract

Verdict line scoped to window and telemetry, per-hypothesis signal table with decoded
samples, confidence by plane, blind spots, actions. Exact shape: `hunt-method` plus
`hunt-method/references/hunt-report-template.md`.
