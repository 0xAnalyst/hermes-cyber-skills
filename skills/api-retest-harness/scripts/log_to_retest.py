#!/usr/bin/env python3
"""log_to_retest.py — turn a pentest evidence log (JSONL) into a rerunnable retest script.

Input contract (one JSON object per line):
  - "sent" event:    {"ts", "phase", "url", "method"?, "headers_sent"?, ...}          status absent/None
  - "result" event:  {"ts", "phase", "tag"/"api"/"endpoint"?, "status": int, "class"?, "body_head"?}
  - v3 contract (preferred): ONE event per probe carrying url+method+status together.

Pairing rule: a result event binds to the most recent preceding sent event with the
same phase (results may also carry their own `url`, which wins). Events that yield
no URL are counted and reported — never guessed.

Optional `--url-map MAP.json` retro-fits compact logs: {"phase": {"<tag|api|endpoint|*>":
  {"url": "...", "method": "POST", "body": "<literal>", "content_type": "..."}}} —
`*` matches any label in that phase.

Output: a standalone Python retest script (stdlib only). Credentials NEVER appear
in the output — key-class header values become "{{API_KEY}}" read from the
API_KEY environment variable; the generator refuses to emit anything still
matching a 16+ hex-char secret pattern. Dry-run is the default; network sends
require --fire.

Usage:
  log_to_retest.py evidence.jsonl -o retest.py
  log_to_retest.py evidence.jsonl --url-map map.json -o retest.py
  python3 retest.py --plan          # show probes, send nothing
  python3 retest.py --fire          # execute probes
"""
import argparse, json, os, pprint, re, sys

# Credential-shaped: 24+ alnum chars containing at least one digit — covers pure-hex
# keys AND letter-prefixed variants (e.g. 'l70be...'). Letters-only words don't match.
SECRET_RE = re.compile(r"\b(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{24,}\b", re.I)
KEY_HEADERS = {"apikey", "x-api-key", "authorization", "token", "api-key", "x-auth-token"}
PLACEHOLDER = "{{API_KEY}}"

def load(path):
    events = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: print(f"  ! line {i}: not JSON, skipped", file=sys.stderr)
    return events

def scrub_headers(headers):
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in KEY_HEADERS or (isinstance(v, str) and SECRET_RE.search(v)):
            out[k] = PLACEHOLDER
        else:
            out[k] = v
    return out

def scrub_url(url):
    # credentials in query strings (the exact leakage class this skill tests for):
    # replace credential-shaped runs (24+ alnum w/ a digit) — letters-only words untouched
    return SECRET_RE.sub(PLACEHOLDER, url) if url else url

def label(ev):
    return " / ".join(str(ev.get(k)) for k in ("phase", "tag", "api", "endpoint") if ev.get(k)) or ev.get("phase", "?")

def extract(events, url_map):
    probes, pending, unmatched = [], [], 0
    for ev in events:
        phase = ev.get("phase", "?")
        status = ev.get("status")
        url = scrub_url(ev.get("url"))
        if url and isinstance(status, int):                      # v3: one-event probe
            probes.append({"label": label(ev), "url": url, "method": ev.get("method", "GET"),
                           "headers": scrub_headers(ev.get("headers") or ev.get("headers_sent")),
                           "body": ev.get("body_template"), "expect": status})
            continue
        if url and status is None:                               # sent event — keep pending
            pending.append({"phase": phase, "url": url, "method": ev.get("method", "GET"),
                            "headers": scrub_headers(ev.get("headers_sent")),
                            "body": ev.get("body") or ev.get("body_head")})
            continue
        if isinstance(status, int):                              # result event
            src = next((p for p in reversed(pending) if p["phase"] == phase), None)
            if src:
                probes.append({"label": label(ev), "url": src["url"], "method": src["method"],
                               "headers": src["headers"], "body": src["body"], "expect": status})
            elif url_map:
                m = (url_map.get(phase, {}).get(str(ev.get("tag") or ev.get("api") or ev.get("endpoint") or "*"))
                     or url_map.get(phase, {}).get("*"))
                if m:
                    hdrs = dict(m.get("headers", {}))
                    for hk in list(hdrs):
                        if hk.lower() in KEY_HEADERS: hdrs[hk] = PLACEHOLDER
                    probes.append({"label": label(ev), "url": m["url"], "method": m.get("method", "GET"),
                                   "headers": hdrs, "body": m.get("body"), "expect": status})
                else:
                    unmatched += 1
            else:
                unmatched += 1
    # dedupe on (label, url, method, expect)
    seen, out = set(), []
    for p in probes:
        k = (p["label"], p["url"], p["method"], p["expect"])
        if k not in seen: seen.add(k); out.append(p)
    return out, unmatched

RETEST_TEMPLATE = '''#!/usr/bin/env python3
"""Auto-generated retest script — from {n_probes} probes in {log_name}.
Dry-run by default; --fire sends real requests (authorized targets only).
Credentials: export API_KEY=<current key> before --fire.
Generated by api-retest-harness/log_to_retest.py."""
import argparse, http.client, json, os, ssl, sys
from urllib.parse import urlparse

PROBES = {probes_json}

def send(p, key):
    p_url = p["url"].replace("{ph}", key) if "{ph}" in p["url"] else p["url"]
    u = urlparse(p_url)
    if u.scheme == "https":
        c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=15, context=c)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)
    hdrs = {{k: (key if v == "{ph}" else v) for k, v in p["headers"].items()}}
    conn.request(p["method"], u.path + ("?" + u.query if u.query else ""), body=p["body"], headers=hdrs)
    r = conn.getresponse(); body = r.read(4000); conn.close()
    return r.status, dict(r.getheaders()), body

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fire", action="store_true", help="actually send (default: plan only)")
    ap.add_argument("--plan", action="store_true", help="dry-run (default); explicit for clarity")
    ap.add_argument("--only", help="substring filter on label")
    args = ap.parse_args()
    sel = [p for p in PROBES if not args.only or args.only.lower() in p["label"].lower()]
    if not args.fire:
        print(f"PLAN: {{len(sel)}} probes (dry-run — nothing sent)")
        for p in sel:
            print(f"  [{{p['label']}}] {{p['method']}} {{p['url']}} -> expect {{p['expect']}}")
        return 0
    key = os.environ.get("API_KEY")
    if not key:
        sys.exit("API_KEY env var required for --fire")
    hits = misses = 0
    for p in sel:
        try:
            st, _, _ = send(p, key)
            ok = st == p["expect"]
            hits += ok; misses += (not ok)
            print(f"[{{'OK ' if ok else 'DIFF'}}] {{p['label']}}: {{st}} (expected {{p['expect']}})")
        except Exception as e:
            misses += 1
            print(f"[ERR] {{p['label']}}: {{type(e).__name__}}: {{e}}")
    print(f"\\n{{hits}}/{{hits+misses}} matched the recorded baseline")
    return 0 if misses == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log"); ap.add_argument("-o", "--out", default="retest.py")
    ap.add_argument("--url-map", help="JSON retrofit map for compact logs")
    args = ap.parse_args()

    events = load(args.log)
    url_map = json.load(open(args.url_map)) if args.url_map else None
    probes, unmatched = extract(events, url_map or {})

    script = RETEST_TEMPLATE.format(n_probes=len(probes), log_name=args.log,
                                    probes_json=pprint.pformat(probes, width=100),
                                    ph=PLACEHOLDER)
    if SECRET_RE.search(script.replace(PLACEHOLDER, "")):
        sys.exit("REFUSED: generated script still contains secret-looking material")
    tmp = args.out + ".tmp"
    with open(tmp, "w") as f: f.write(script)
    os.replace(tmp, args.out)
    print(f"{args.log}: {len(events)} events -> {len(probes)} probes -> {args.out} (unmapped result events: {unmatched})")
    for p in probes[:8]: print(f"  [{p['label']}] {p['method']} {p['url']} -> expect {p['expect']}")
    if len(probes) > 8: print(f"  ... +{len(probes)-8} more")

if __name__ == "__main__":
    main()
