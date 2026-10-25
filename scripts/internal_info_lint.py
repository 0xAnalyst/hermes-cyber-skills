#!/usr/bin/env python3
"""internal_info_lint.py — second gate: nothing internal ships to the public repo.

publish_scrub.py removes client/vendor *names*. This checks the other half:
personal paths, credentials, private-range addresses and internal-only suffixes.

Usage:
  internal_info_lint.py FILE [FILE...]
  internal_info_lint.py --warn-only FILE [...]

Exit codes: 0 clean (warnings allowed), 1 a hard failure was found.
"""
import json
import os
import re
import sys

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "publish-scrub.json")

FAIL = [
    ("personal path (macOS/Linux)", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+")),
    ("personal path (Windows)", re.compile(r"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("literal API key header", re.compile(r"X-API-Key:\s*[A-Za-z0-9]{12,}")),
    ("bearer token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("internal-only suffix", re.compile(r"\.(?:internal|intranet|intra|lan)\b", re.I)),
]

WARN = [
    ("private-range address", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("email address", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
]

ALLOW_EMAIL = re.compile(r"@(?:example\.[a-z]+|target\.com|test\.com|evil\.com|app\.com|localhost)\b", re.I)
ALLOW_IP = {"169.254.169.254"}          # cloud metadata endpoint — public knowledge
DOC_IP = re.compile(r"^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")   # TEST-NET ranges
TEXT_EXT = {".md", ".json", ".py", ".sh", ".txt", ".yaml", ".yml", ".cfg", ".ini", ""}


def forbidden_from_config():
    try:
        cfg = json.load(open(CFG))
        return [("forbidden pattern", re.compile(p, re.I)) for p in cfg.get("forbidden", [])]
    except Exception:
        return []


def main(argv):
    warn_only = "--warn-only" in argv
    paths = [a for a in argv if a != "--warn-only"]
    fails, warns, scanned = [], [], 0
    checks_fail = forbidden_from_config() + FAIL

    for path in paths:
        if not os.path.isfile(path):
            continue
        if os.path.splitext(path)[1].lower() not in TEXT_EXT:
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx in checks_fail:
                m = rx.search(line)
                if m:
                    fails.append((path, lineno, name, m.group(0)[:60]))
            for name, rx in WARN:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(0)
                if name == "email address" and ALLOW_EMAIL.search(val):
                    continue
                if name == "private-range address" and (val in ALLOW_IP or DOC_IP.search(val)):
                    continue
                warns.append((path, lineno, name, val[:60]))

    for f in fails:
        print(f"FAIL {f[0]}:{f[1]} — {f[2]}: {f[3]}")
    for w in warns[:40]:
        print(f"WARN {w[0]}:{w[1]} — {w[2]}: {w[3]}")
    if len(warns) > 40:
        print(f"... {len(warns) - 40} more warnings")
    print(f"internal-info lint: {scanned} files, {len(fails)} failure(s), {len(warns)} warning(s)")
    if fails and not warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
