# Threat Hunting

MITRE ATT&CK-mapped hunt skills. One skill per Enterprise tactic, plus a shared method skill
that every hunt runs inside. A hunt here answers a falsifiable question about a window of
telemetry — it is not a keyword sweep and not an alert review.

**Start with [`hunt-method`](hunt-method/SKILL.md).** It defines the hypothesis loop, the
evidence rules, the false-positive classes and the output contract that every tactic skill
inherits.

## Skills

| Skill | ATT&CK | The question it answers |
|---|---|---|
| [`hunt-method`](hunt-method/) | — | How to structure, evidence and report any hunt |
| [`reconnaissance`](reconnaissance/) | TA0043 | What did outsiders learn about our estate, and did the surface change? |
| [`resource-development`](resource-development/) | TA0042 | Is campaign infrastructure touching us — lookalike domains, staged payloads, offensive tooling? |
| [`initial-access`](initial-access/) | TA0001 | Did anyone get a foothold: exploited edge app, stolen credential, remote service, phishing? |
| [`execution`](execution/) | TA0002 | Did code run outside its normal parent/argument/role shape? |
| [`persistence`](persistence/) | TA0003 | Did something start that no change record explains? |
| [`privilege-escalation`](privilege-escalation/) | TA0004 | Did rights appear rather than get granted? |
| [`defense-evasion`](defense-evasion/) | TA0005 | Is our own telemetry being reduced, and who is using system binaries as proxies? |
| [`credential-access`](credential-access/) | TA0006 | Was credential material touched, sprayed or forged, and used afterwards? |
| [`discovery`](discovery/) | TA0007 | Is an identity or host mapping more than its role justifies? |
| [`lateral-movement`](lateral-movement/) | TA0008 | Which host-to-host pairs exist that architecture does not explain? |
| [`collection`](collection/) | TA0009 | Is data being staged — mail rules, bulk reads, archives outside schedule? |
| [`command-and-control`](command-and-control/) | TA0011 | Is a channel open whose destination, direction and process make no business sense? |
| [`exfiltration`](exfiltration/) | TA0010 | Is data leaving through a channel whose purpose does not fit the host? |
| [`impact`](impact/) | TA0040 | Is destruction or encryption underway — page now, report later? |

## How to feed a hunt

Every tactic skill carries an **Inputs required** section. Supply, per run:

1. **Window** — start and end in one timezone, with ingest lag accounted for.
2. **Telemetry** — the specific sources and field names in your estate (SIEM indices, EDR
   tables, proxy/DNS feeds, identity logs).
3. **Baseline** — the same data for a comparable quiet period, or an explicit statement that
   the hunt is unbaselined.
4. **Deconfliction** — sanctioned scanners, pentest calendar, lab hosts, change records.

Without 1–4 the hunt returns "unanswerable" rather than a guess. That is deliberate.

## Ground rules

- **No verdict without a plane.** "Clean" must name the telemetry it is clean within.
- **Every signal ships with its benign twin.** If you cannot say what the false positive looks
  like, the detection is not finished.
- **Two planes or it is a lead.** Process plus network, identity plus endpoint, request plus
  filesystem.
- **Deconflict before escalating.** Sanctioned scanning, labs and admin tooling explain most
  internal-looking activity.
- **Nothing environment-specific ships.** Hunt content is method and public technique mapping;
  hosts, identities and captured evidence stay local.
