# DFIR

Detection, hunting, and response methodology: threat hunting across SIEM, EDR and
network telemetry, exploit-specific detection signatures, log forensics and
timeline reconstruction, and incident triage that separates real signals from the
benign lookalikes that fire the same indicators.

## Skills

| Skill | Version | Purpose |
|---|---|---|
| [`php2shell-detection`](php2shell-detection/) | 1.0.0 | Detects php2shell (CVE-2026-109618/109619) exploitation across request, outcome and execution planes — exact multipart signatures and body hashes, startup-OOM/crash discriminators that survive HTTP 200, webshell-fetch sweep, a stdlib log scanner, and SIEM/Elastic/Splunk/KQL/WAF queries with a triage decision tree |

## Ground rules

- **Every verdict states the plane it was reached on and the blind spots.** "Clean"
  means clean within what that telemetry can observe — never more.
- **Indicators are verified in data, not asserted.** A signature ships with the
  query that finds it, or with the reason it cannot be queried somewhere.
- **Noise is a first-class finding.** If a detector fires on surveys, scanners, or
  lab traffic, the false-positive classes belong in the skill.
- **Victim data never ships.** Public IOCs and method only; client hosts, user
  names, and captured evidence stay local.

## Adding a skill here

Hunt playbooks, detection signatures, forensic analysis procedures, triage
decision trees, log-parsing recipes. If a skill is about breaking into a system,
it belongs in [`../penetration-testing`](../penetration-testing/) or
[`../red-teaming`](../red-teaming/).
