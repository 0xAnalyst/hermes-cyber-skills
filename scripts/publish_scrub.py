#!/usr/bin/env python3
"""publish_scrub.py — anonymize repo files before they ship publicly.

Applies the replacement table in publish-scrub.json (client/vendor names ->
generic placeholders) to file CONTENTS and to file NAMES (a repo copy whose
basename matches a replacement is renamed in place — profile sources are never
touched, only the paths passed in). Then scans content AND final filenames for
forbidden patterns and exits non-zero if any survive: a scrubbed file shipped
under a leaky name is still a leak. Idempotent. Run on every synced file
(sync_skill.sh calls it).

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
        # path scrub: same table applied to the basename of the repo copy
        base = os.path.basename(path)
        new_base = base
        for old, new in repl:
            new_base = re.sub(old, new, new_base, flags=re.I)
        if not check_only and new_base != base:
            new_path = os.path.join(os.path.dirname(path), new_base)
            os.replace(path, new_path)  # overwrites a stale same-named copy
            print(f"renamed: {base} -> {new_base}")
            path = new_path
        hits = [p.pattern for p in forbidden
                if p.search(t) or p.search(os.path.basename(path))]
        if hits:
            print(f"LEAK in {path}: {hits}", file=sys.stderr)
            failures += 1
    if failures:
        sys.exit(f"{failures} file(s) still contain forbidden patterns — fix before push")
    print("scan clean" if check_only else f"done ({len(argv)} files, scan clean)")

if __name__ == "__main__":
    main()
