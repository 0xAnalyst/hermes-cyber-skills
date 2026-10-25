# php2shell signature catalog (Oct 2026 captures)

Source: 0x4D31/honeypot-data — `reports/php2shell/2026-10-22-to-24-initial-attempts.md` and `2026-10-24-confirmed-rce.md`. Sizes are decoded body bytes (chunk framing excluded).

## The four-stage chain (confirmed RCE)

| Stage | Transport | Decoded body | Effect |
|---|---|---|---|
| A1 memory pressure | chunked multipart, boundary `CCCCCCCCCC`, `POST /?q0000000=v…q0000004=v` | 1,060,211 B — 973 parts, mostly `files*` fields | OOM `memory_limit` (4,096-B allocation) in `Unknown on line 0`; HTTP 200 in access log |
| B1 disclosure | chunked multipart, same boundary, `POST /` | 33,128,677 B — 918 parts, mostly `x*` fields | 819,200-B URL-decoded `PHPSESSID` response cookie (leaked pointers); session-startup warnings |
| A2 pressure | fixed-length multipart | 279,369 B — 997 parts, `files*` fields | OOM (20,480-B allocation), `Unknown on line 0`; HTTP 200 |
| B2 execution | fixed-length multipart | 451,384 B — 998 parts, 500 `s*` + 495 `t*` fields, address-like values + command string | `/bin/sh` (uid 33) parented by Apache worker, then worker SIGSEGV; **no normal access-log completion** |

The attacker may repeat A1/B1 before advancing. All four stages carry `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` form fields.

### Fixed decoded-body SHA-256 (A1/B1/A2 identical across sources/targets)

| Body | SHA-256 |
|---|---|
| A1 | `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6` |
| B1 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| A2 | `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236` |
| B2 (target-dependent; example) | `aab24fa5ec0df76f731c1ea4bac9fd36aa350eef9a42c33315e485178e1e5892` |

B2's digest changes with the target's leaked address range and the shell command — use it to cluster, not to identify.

## HTTP fingerprint (successful chains)

- HTTP/1.1, **no `User-Agent`** header, POST to `/` or `/index.php`.
- Multipart boundary of ten `C` characters (`CCCCCCCCCC`); some families use `----Php2Shell<hex>`, `BNDRY12345`, `PROBE`.
- Header order `Host → Content-Type → Transfer-Encoding → Connection` (chunked) or `Host → Content-Type → Content-Length → Connection` (fixed).
- First pressure request carries exactly five numbered query params `q0000000=v` … `q0000004=v`.

## Request-shape families (attempt report)

| Family | Markers | Body evidence |
|---|---|---|
| B1 leak-stage | `PHPSESSID=a`, `PHP_SESSION_UPLOAD_PROGRESS=k0`, long field `f0000ffff…` | 33,128,677 B complete; identical bodies → 10 segfaults |
| Distributed fixed-length | `attacksessionid0001`, progress `pwn`, boundary `BNDRY12345` | 93,685 B and 192 B probes; exact body reuse across 22 IPs in `14.102.84.0/24`; matches `eness/poc_109618.py` markers |
| Core/serializer wave | boundary `----Php2Shell22fe580e9`; cookie `PHPSESSID=p2sca…`; `PHP_SESSION_UPLOAD_PROGRESS=upload_progress\|a:2:{s:4:"name";s:25:"PHP2SHELL_CORE_ser_c75749";s:8:"handler";s:13:"php_serialize";}`; form field `session.serialize_handler=php_serialize`; filename `PHP2SHELL_CORE_ser_c75749_php_serialize.txt`; filler `Z`×64 | 8,755 B complete, SHA-256 `24e48ed82efcde4c48d48ce1bdfc47c3c41fb33ff95d60e1f3f001947df9b4e7` |
| Field-flood | boundary `SSSSSSSSSSSSSSSSS`; sequential long names `g0000xxxx…`, `g0001xxxx…`, `g0002…`, `g0003…`; values `vvvvvvvv` | chunked, sequential enumeration |
| Nested-file | boundary `PROBE`; field `files[R00000][a][a][a]…` (≈62 `[a]` levels deep), filename empty | 300,067 B complete, SHA-256 `f3c6533141734d3c5a7e781227542da4ceb5b06e0250b8c8ac3e36b79e946891` |
| Survey (benign) | `PHP_SESSION_UPLOAD_PROGRESS=internet-census`, file `internet-census.txt`, UA `python-requests/*`, PTR `*.internet-census.org` | 302 B |
| Recon probe (benign) | `PHP_SESSION_UPLOAD_PROGRESS=probe_recon`, boundary `----recon0xdeadbeef`, file `probe.txt` | 523 B |

## Response / outcome signals

- **Disclosure cookie:** decoded `PHPSESSID` of exactly **819,200 bytes**, containing repeated aligned pointer-like 64-bit words (a dominant word repeated ~1,095×). Ordinary session IDs are 32 hex chars.
- **Startup OOM:** `Allowed memory size of N bytes exhausted (tried to allocate M bytes) in Unknown on line 0` — allocation sizes seen: 4,096 B and 20,480 B. Pre-script, so it happens before application code.
- **Worker crashes:** SIGSEGV (ten) and SIGABRT (one) in the attempt window; a crash may occur between stages or immediately after the shell spawn.
- **POST-size warnings:** 29 in the attempt window (`POST Content-Length of N bytes exceeds the limit`).
- **HTTP 200 on every OOM request** — status is not an outcome signal in this family.
- **Success markers the PoC writes/expects** (useful when scanning response bodies or files): `PHP2SHELL_CHAIN_OK`, `PHP2SHELL_CHECK`, `p2s_v2_alive`, `shellflow_canary`, `uid=`. Their absence does not clear a target.

## Execution / post-exploitation signals

- `/bin/sh` (uid 33 / www-data) **parented directly by an Apache worker** (observed via Tetragon process events), often milliseconds after the B2 POST and accompanied by the worker's SIGSEGV.
- Shell commands observed: write `id` output to a temp proof file and web roots, then invoke `wget`, `curl`, or PHP CLI; later proof URLs embed `$(id -un)`, `$(hostname)`, `$(uname -m)` substitutions (dynamic identity checks).
- **Webshell fetch pattern:** `GET /shell_<8hex>.{phtml,php5,php,phar}` across many directories — `/`, `uploads/`, `upload/`, `files/`, `wp-content/uploads/`, `media/`, `images/`, `storage/`, `data/uploads/`, `public/uploads/`, `content/uploads/` — plus `/php_info.php`, `/test.php`, `/i.php`, `/phpinfo/`, `/p.php`, `/admin/phpinfo.php` reconnaissance.
- `/tmp/php…` path strings in permission-hook / file-write telemetry (1,234 events referencing 129 distinct paths in the attempt window) — correlates with successful upload writes and possible shell drops.

## Data-availability matrix

| You have | Planes reachable | Minimum viable detection |
|---|---|---|
| Full request bodies (WAF body inspection, PCAP, proxy) | Request + outcome + execution | Boundary/field-flood/hash match, then join to errors and process events |
| Access logs only | Outcome (5xx/crash completions) + execution (webshell GETs) | `shell_<hex>` GETs, POST bursts from one client, execution posts with no completion |
| Error logs only | Outcome | Startup OOM `Unknown on line 0`, SIGSEGV/SIGABRT, POST-size warnings |
| EDR process telemetry only | Execution | Worker-parented `/bin/sh`, `/tmp/php*` writes |
| Response body logging | Execution (leak) | 819,200-byte `PHPSESSID` |

## CVE mapping and fix levels

- **CVE-2026-109618** — upload-progress/session memory corruption chain; matches all observed traffic (leak-guided ASLR bypass via `PHPSESSID` disclosure, then shell).
- **CVE-2026-109619** — session-file path variant; not observed in these captures — do not assume it is absent elsewhere.
- Fixed: **PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12**. Backports exist only for maintained branches (7.4/8.0/8.1 are EOL).
- Public tooling referenced by the captures: `9bie/php2shell-bypass-aslr-exp` (`exploit.py`), `eness/poc_109618.py`, Wiz research on the upload-progress family.
