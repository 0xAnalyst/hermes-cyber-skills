---
name: php2shell-detection
description: "Detect php2shell exploitation: probes, crashes, webshells."
version: 1.0.0
author: 0xanalyst
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [php2shell, CVE-2026-109618, CVE-2026-109619, webshell, detection, threat-hunting]
    category: security
    related_skills: [siem-alert-review, log-forensics, web-pentest]
---

# php2shell detection Skill

php2shell (CVE-2026-109618 / CVE-2026-109619) is a PHP-engine request-startup memory corruption exploited through multipart POSTs: memory-pressure stages exhaust `memory_limit` before application code runs (fatal `in Unknown on line 0`), a disclosure stage leaks pointers through an oversized `PHPSESSID` response cookie, and a final stage performs a leak-guided ASLR bypass to spawn `/bin/sh` parented by the Apache worker. Fixed versions: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

This skill detects attempts and successes across three planes — request, outcome, execution — and separates them from the recurring benign lookalikes. Signature basis: 0x4D31 honeypot-data captures of 22–24 Oct 2026 (attempt-only report + confirmed packet-to-process RCE report), the public PoC family (9bie `exploit.py`), Wiz research, and NCSC-NL/php2shell.

## When to Use

- Hunting or triaging php2shell / CVE-2026-109618 / CVE-2026-109619 activity
- A PHP lane shows startup OOMs (`Unknown on line 0`), worker SIGSEGV/SIGABRT, or POST-size warnings
- Webshell hunt for `shell_<8hex>.{phtml,php5,php,phar}` in upload directories
- A web-exploit alert fired but HTTP status was 200 (this family returns 200 on OOM)

Don't use for: generic LFI/RCE triage (`web-pentest`), or serialization gadget chains (phpggc — different bug class).

## Prerequisites

- Request bodies or full-request logging (WAF body inspection, packet capture, proxy logs). Access-log-only detection reaches the outcome and execution planes only.
- Web error logs (`php_errors.log`, Apache error log) for the outcome plane.
- Optional: EDR/Tetragon process telemetry (worker → `/bin/sh`) and network flow byte counts.
- Tooling: `scripts/php2shell_scan.py` (stdlib-only) for log files; SIEM/KQL/WAF queries in `references/hunting-queries.md`.

## Detection model — three planes

| Plane | What proves it | Strength |
|---|---|---|
| Request | Multipart markers/boundaries, field-name floods, stage-sized bodies, fixed body hashes | High precision; needs bodies |
| Outcome | Startup OOM `in Unknown on line 0`, worker SIGSEGV/SIGABRT, POST-size warnings — all often with HTTP 200 | Medium: separates attempts from scanning |
| Execution | Apache-parent `/bin/sh`, 819,200-byte `PHPSESSID` cookie, missing access-log completion, webshell GETs | Confirms compromise |

## Procedure

1. **Baseline the PHP estate.** Map every internet-facing PHP endpoint to version and settings (`memory_limit`, `session.upload_progress.*`). Anything below 8.2.35/8.3.36/8.4.27/8.5.12 is exposed; `session.upload_progress.enabled=1` on a vulnerable build is the direct risk. *Done when: version table exists and the exposed-endpoint list is non-empty.*
2. **Request-plane sweep.** Search the exact literals in `references/signatures.md` — `PHP_SESSION_UPLOAD_PROGRESS`, `attacksessionid0001`, `k0`, `f0000ffff…`, `q0000000=v`, `files[R00000]`, `g0000`, `s0000`/`t0000`, boundaries `CCCCCCCCCC` / `----Php2Shell…` / `PHP2SHELL_CORE_` / `BNDRY12345` / `PROBE`. Decompose every nonzero by source and day before quoting totals. *Done when: per-literal counts recorded and each cluster read at message level.*
3. **Outcome-plane sweep.** Correlate startup OOMs (`Allowed memory size … in Unknown on line 0`), worker crashes (SIGSEGV/SIGABRT, `AH00051`), and POST-size warnings to source IPs and request paths. *Done when: crash counts are tied to request bodies and the 200-status OOM list is built.*
4. **Execution-plane sweep.** Hunt `GET` requests for `shell_<8hex>.{phtml,php5,php,phar}` in upload paths, `/tmp/php*` writes, Apache-parent shell spawns, and execution-stage POSTs with no normal access-log completion. *Done when: every hit is classified webshell or benign with named evidence.*
5. **Triage each cluster.** Label exploit attempt, recon/survey, or lab reproduction using the lookalike classes in Pitfalls. *Done when: every cluster has a label and a reason.*
6. **Respond.** Patch or isolate exposed PHP; disable `session.upload_progress` where the app does not need it; block oversized multipart POSTs at the WAF; freeze bodies, cookies, and worker PIDs for the incident record. *Done when: each item has an owner.*

## Quick Reference

| Signal | Literal |
|---|---|
| Exploit form fields | `PHP_SESSION_UPLOAD_PROGRESS` as a form field (constant-ish value: `k0`, `pwn`, `upload_progress\|a:2:{…}`) and `PHPSESSID` as a form field (`a`, NUL, or 32-hex) |
| Boundaries | `CCCCCCCCCC` (10-char C), `----Php2Shell<hex>`, `PHP2SHELL_CORE_`, `BNDRY12345`, `PROBE`, `----recon0xdeadbeef` |
| Field floods | `f0000ffff…` long names; `files[R00000][a][a]…` (nested); `g0000…`/`g0001…` sequential; `s0000`/`t0000`; `q0000000=v`…`q0000004=v` in the query string |
| Stage bodies (decoded) | A1 1,060,211 B · B1 33,128,677 B · A2 279,369 B · B2 451,384 B — hashes in `references/signatures.md` |
| Outcome | `in Unknown on line 0` OOM; SIGSEGV/SIGABRT; POST-size warnings; HTTP 200 on all OOMs |
| Execution | `/bin/sh` (uid 33) parented by Apache worker; 819,200-byte decoded `PHPSESSID`; missing access-log completion |

## Pitfalls

- **Status codes lie.** All 30 honeypot OOM requests returned HTTP 200; the execution stage often has no access-log completion at all. Never clear on status.
- **Token traps in phrase search.** `php2shell22fe580e9` is one token — a phrase match for `php2shell` misses it. Query the exact literals; use wildcard/prefix where the engine allows.
- **Benign lookalikes fire the same markers.** `internet-census.org` survey scans (`PHP_SESSION_UPLOAD_PROGRESS=internet-census`, python-requests); recon probes (`probe_recon`, `----recon0xdeadbeef`); newsletter/mail noise on the word php2shell (peaks the day after disclosure); sanctioned lab reproductions (loopback, `php2shell-lab`); dev-tooling `rawkey` hits; app OOMs with a named `file:line` (exploit-shaped OOMs say `Unknown on line 0`).
- **Truncated captures.** A 33-MB body can be cut by the sensor before the session cookie is logged; absence of the cookie is not absence of a leak.
- **Fixed bodies identify a family, not success.** B1's hash appears in both attempt-only and confirmed-RCE captures.
- **Join by process, not status.** Confirm execution by joining shell start to the request by time/port/worker identity (EDR/Tetragon), never by HTTP response alone.
- **Test the de-escalation path, not just detection.** A scanner that fires on `internet-census` survey bodies and recon probes "works" while being unusable in production. Fixtures must assert that benign survey/recon input returns CLEAN as well as that attack fixtures escalate — and tag survey/recon per record at parse time so a mixed batch (one real exploit plus survey noise) still escalates.

## Verification

- `scripts/php2shell_scan.py --selftest` passes (each plane's signatures fire on synthetic fixtures).
- Run against a known-clean production day: zero execution-plane hits.
- Re-run on the hunt window: request-plane literals appear only in the exploitation cluster.

References: `references/signatures.md` (full signature catalog), `references/iocs-2026-10.md` (IOCs and false-positive classes), `references/hunting-queries.md` (Elasticsearch-compatible SIEM gateway, Elastic DSL, Splunk, MDE KQL, WAF rules).
