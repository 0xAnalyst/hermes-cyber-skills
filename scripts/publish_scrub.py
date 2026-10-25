#!/usr/bin/env python3
"""publish_scrub.py — anonymize repo files before they ship publicly.

Applies the replacement table in publish-scrub.json (client/vendor names ->
generic placeholders), then scans for forbidden patterns and exits non-zero if
any survive. Idempotent. Run on every synced file (sync_skill.sh calls it).

Usage:
  publish_scrub.py FILE [FILE...]
  publish_scrub.py --check FILE [FILE...]   # scan only, no rewriting
"""
import json, os, re, sys

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "publish-scrub.json")

def main():
    argv = [a for a in sys.argv[1:] if a != "--check"]
    check_only = "--check" in sys.argv
    cfg = json.load(open(CFG))
    repl = cfg.get("replacements", [])
    forbidden = [re.compile(p, re.I) for p in cfg.get("forbidden", [])]
    cfg_abs = os.path.abspath(CFG)
    argv = [p for p in argv if os.path.abspath(p) != cfg_abs]  # never scrub the config itself
    failures = 0
    for path in argv:
        if not os.path.isfile(path):
            continue
        t = orig = open(path).read()
        if not check_only:
            for old, new in repl:
                t = t.replace(old, new)
                t = re.sub(old, new, t, flags=re.I)
            if t != orig:
                open(path, "w").write(t)
                print(f"scrubbed: {path}")
        hits = [p.pattern for p in forbidden if p.search(t)]
        if hits:
            print(f"LEAK in {path}: {hits}", file=sys.stderr)
            failures += 1
    if failures:
        sys.exit(f"{failures} file(s) still contain forbidden patterns — fix before push")
    print("scan clean" if check_only else f"done ({len(argv)} files, scan clean)")

if __name__ == "__main__":
    main()
