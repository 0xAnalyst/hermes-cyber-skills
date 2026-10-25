#!/usr/bin/env python3
"""php2shell log scanner — three-plane detection for CVE-2026-109618/109619.

Planes:
  request   multipart markers, boundaries, field floods, stage body sizes/hashes
  outcome   startup OOM ('in Unknown on line 0'), worker SIGSEGV/SIGABRT, POST-size warnings
  execution webshell GETs (shell_<8hex>.phtml|php5|php|phar), worker-parent shell hints

Reads nginx/Apache combined or common logs, W3C/IIS logs, PHP/Apache error logs,
and raw multipart body dumps. Stdlib only.

Usage:
    python php2shell_scan.py access.log error.log [--json OUT] [--bodies DIR] [--selftest]

Exit codes: 0 clean, 1 attempt-level indicators, 2 execution-plane indicators.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# --- request plane -----------------------------------------------------------
BOUNDARY_PATTERNS = [
    ("boundary_cccc", re.compile(rb"CCCCCCCCCC")),
    ("boundary_php2shell", re.compile(rb"----Php2Shell[0-9a-fA-F]{6,}", re.I)),
    ("marker_core", re.compile(rb"PHP2SHELL_CORE_", re.I)),
    ("boundary_bndry", re.compile(rb"BNDRY12345", re.I)),
    ("boundary_probe", re.compile(rb"\bPROBE\b")),
    ("boundary_recon", re.compile(rb"----recon0xdeadbeef", re.I)),
]
FIELD_PATTERNS = [
    ("progress_field", re.compile(rb"PHP_SESSION_UPLOAD_PROGRESS", re.I)),
    ("attacksession", re.compile(rb"attacksessionid0001", re.I)),
    ("nested_files", re.compile(rb"files\[R\d{5}\]", re.I)),
    ("field_flood", re.compile(rb'name="[fgsqtx]0{2,}[0-9a-zA-Z]{4,}', re.I)),
    ("qparam_flood", re.compile(rb"q000000[0-4]=v", re.I)),
]
SURVEY_RE = re.compile(rb"internet-census|probe_recon", re.I)

# --- outcome plane -----------------------------------------------------------
OOM_STARTUP = re.compile(r"Allowed memory size of \d+ bytes exhausted.*in Unknown on line 0", re.I)
OOM_ANY = re.compile(r"Allowed memory size of \d+ bytes exhausted|Allowed memory exhausted", re.I)
POST_LIMIT = re.compile(r"POST Content-Length of \d+ bytes exceeds", re.I)
CRASH = re.compile(r"segmentation fault|SIGSEGV|SIGABRT|exit signal Segmentation fault|AH00051", re.I)

# --- execution plane ---------------------------------------------------------
SHELL_GET = re.compile(r"\bGET\s+(?:https?://[^/\s]+)?(\S*shell_[0-9a-f]{8}\.(?:phtml|php5|php|phar))", re.I)
PHP_POST = re.compile(r'"POST\s+(\S*\.(?:php\d?|phtml|phar))(?:\?\S*)?\s+HTTP/[\d.]+"')
WEB_PARENT_SHELL = re.compile(
    r"(?:httpd|apache2|php-fpm|php-cgi|w3wp)[^\n]{0,80}(?:/bin/sh|/bin/bash|cmd\.exe|powershell)", re.I
)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def client_of(line: str) -> str:
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s", line)
    if m:
        return m.group(1)
    m = IP_RE.search(line)
    return m.group(1) if m else "-"


def scan_text(lines, kind):
    """kind: 'access' | 'error'. Returns list of detection dicts."""
    out = []
    posts = {}
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        client = client_of(line)
        survey = bool(SURVEY_RE.search(line.encode(errors="replace")))
        if kind == "access":
            m = SHELL_GET.search(line)
            if m:
                out.append(dict(line=n, plane="execution", check="webshell_fetch",
                                client=client, evidence=m.group(1)[:160], line_text=line[:300]))
            pm = PHP_POST.search(line)
            if pm:
                key = client
                posts[key] = posts.get(key, 0) + 1
                low = line.lower()
                if "php_session_upload_progress" in low or "ccc" in low and "multipart" in low:
                    out.append(dict(line=n, plane="request", check="marked_php_post",
                                    client=client, survey=survey, evidence=pm.group(1)[:120], line_text=line[:300]))
            if re.search(r'\s(?:500|502|503|504)\s', line) and pm:
                out.append(dict(line=n, plane="outcome", check="post_5xx",
                                client=client, evidence=pm.group(1)[:120], line_text=line[:300]))
        else:  # error log
            if OOM_STARTUP.search(line):
                out.append(dict(line=n, plane="outcome", check="startup_oom_unknown_line0",
                                client=client, evidence=line[:240]))
            elif OOM_ANY.search(line):
                out.append(dict(line=n, plane="outcome", check="app_oom",
                                client=client, evidence=line[:240]))
            if POST_LIMIT.search(line):
                out.append(dict(line=n, plane="outcome", check="post_size_warning",
                                client=client, evidence=line[:240]))
            if CRASH.search(line):
                out.append(dict(line=n, plane="outcome", check="worker_crash",
                                client=client, evidence=line[:240]))
            if WEB_PARENT_SHELL.search(line):
                out.append(dict(line=n, plane="execution", check="web_parent_shell",
                                client=client, evidence=line[:240]))
    for client, count in posts.items():
        if count >= 25:
            out.append(dict(line=0, plane="request", check="php_post_burst",
                            client=client, survey=False, evidence=f"{count} POSTs to PHP in file",
                            line_text=""))
    return out


def scan_body(path: Path, max_bytes: int):
    """Scan one raw body dump. Returns detections with matched literal names."""
    data = path.read_bytes()[:max_bytes]
    hits, survey = [], False
    for name, rx in BOUNDARY_PATTERNS:
        if rx.search(data):
            hits.append(name)
    for name, rx in FIELD_PATTERNS:
        if rx.search(data):
            hits.append(name)
    if SURVEY_RE.search(data):
        survey = True
    if not hits:
        return []
    return [dict(file=str(path), plane="request", check="body_markers",
                 evidence=",".join(hits), size=len(data),
                 sha256=hashlib.sha256(data).hexdigest(),
                 survey=survey, line_text="")]


def verdict(records):
    planes = {r["plane"] for r in records}
    checks = {r["check"] for r in records}
    if "execution" in planes:
        return "COMPROMISE INDICATORS PRESENT", 2
    if "request" in planes:
        survey_only = all(r.get("survey") for r in records if r["plane"] == "request")
        if survey_only:
            return "BENIGN SURVEY / RECON ONLY", 0
        return "EXPLOITATION ATTEMPTS", 1
    strong = checks & {"startup_oom_unknown_line0", "worker_crash"}
    if strong:
        return "ATTEMPT-SHAPED OUTCOME SIGNALS — TRIAGE", 1
    if "outcome" in planes:
        return "APPLICATION ERRORS ONLY — NOT php2shell-SHAPED", 0
    return "CLEAN", 0


def selftest():
    access = [
        '203.0.113.9 - - [24/Oct/2026:15:35:11 +0000] "POST / HTTP/1.1" 200 512 "-" "-"',
        '203.0.113.9 - - [24/Oct/2026:15:35:12 +0000] "GET /shell_deadbeef.phtml HTTP/1.1" 200 44 "-" "-"',
        '203.0.113.9 - - [24/Oct/2026:15:35:13 +0000] "POST /index.php?PHP_SESSION_UPLOAD_PROGRESS=k0 HTTP/1.1" 200 512 "-" "-"',
    ]
    errors = [
        "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
        "PHP Warning:  POST Content-Length of 33128677 bytes exceeds the limit of 8388608 bytes in Unknown on line 0",
        "[mpm_prefork:notice] [pid 8123] AH00051: child pid 9001 exit signal Segmentation fault (11), possible coredump in /tmp",
        "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/wp-content/plugins/x.php on line 88",
    ]
    a = scan_text(access, "access")
    e = scan_text(errors, "error")
    checks = {r["check"] for r in a + e}
    need = {"webshell_fetch", "marked_php_post", "startup_oom_unknown_line0",
            "post_size_warning", "worker_crash", "app_oom"}
    missing = need - checks
    if missing:
        print("SELFTEST FAIL — missing:", sorted(missing))
        return 1
    assert verdict(a) == ("COMPROMISE INDICATORS PRESENT", 2), verdict(a)
    v, _ = verdict(e)
    assert v.startswith("ATTEMPT-SHAPED"), v
    assert verdict([]) == ("CLEAN", 0)
    print("SELFTEST PASS — all three planes fire; clean input returns CLEAN")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("logs", nargs="*", help="access/error log files or directories")
    ap.add_argument("--bodies", action="append", default=[], help="raw body file or directory")
    ap.add_argument("--json", help="write JSON report here")
    ap.add_argument("--max-body", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()

    files = []
    for p in map(Path, args.logs):
        if p.is_dir():
            files.extend(sorted(f for f in p.iterdir() if f.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip (not found): {p}", file=sys.stderr)

    records = []
    for f in files:
        kind = "error" if re.search(r"err|php|apache|stderr", f.name, re.I) else "access"
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError as exc:
            print(f"skip {f}: {exc}", file=sys.stderr)
            continue
        for r in scan_text(lines, kind):
            r["file"] = str(f)
            r["kind"] = kind
            records.append(r)

    body_paths = []
    for b in map(Path, args.bodies):
        if b.is_dir():
            body_paths.extend(sorted(x for x in b.iterdir() if x.is_file()))
        elif b.is_file():
            body_paths.append(b)
    for b in body_paths:
        try:
            records.extend(scan_body(b, args.max_body))
        except OSError as exc:
            print(f"skip body {b}: {exc}", file=sys.stderr)

    label, code = verdict(records)
    by_check = {}
    for r in records:
        by_check[r["check"]] = by_check.get(r["check"], 0) + 1
    report = dict(verdict=label, exit_code=code, files_scanned=len(files),
                  bodies_scanned=len(body_paths), detections=len(records),
                  counts_by_check=by_check, records=records[:2000])

    print(f"php2shell scan — {len(files)} log file(s), {len(body_paths)} body dump(s)")
    if by_check:
        for check, count in sorted(by_check.items(), key=lambda kv: -kv[1]):
            print(f"  {check:<28} {count}")
    else:
        print("  no signatures matched")
    print(f"VERDICT: {label}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"JSON: {args.json}")
    return code


if __name__ == "__main__":
    sys.exit(main())
