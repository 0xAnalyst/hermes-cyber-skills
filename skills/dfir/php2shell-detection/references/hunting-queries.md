# php2shell hunting queries — SIEM gateway, Elastic, Splunk, MDE, WAF

All examples assume the estate hunt window is set explicitly. Replace `logs-*` with the concrete index pattern for your lane, and keep the time filter on the platform's real timestamp field (`logDate`, `@timestamp`, `TimeGenerated`).

## Elasticsearch-compatible SIEM gateway (REST, verified)

Transport that works when the MCP client or urllib TLS is broken — serialized `curl`, key from a 0600 file, never inline:

```bash
curl -sk -X POST "https://<gateway>/<cluster>/logs-*/_count" \
  -H "X-API-Key: $(cat ~/.siem_key)" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"match_phrase":{"logMessage":"Unknown on line 0"}},{"range":{"logDate":{"gte":"2026-10-01T00:00:00","lt":"2026-10-25T00:00:00"}}}]}}}'
```

Gateway gotchas (cost hours if unknown):
- `GET .../_mapping` returns 403 — resolve field names from the field-translation map, then validate empirically.
- `_msearch` returns 404 — issue serial `_count`/`_search` calls.
- A `count` with multiple `match_phrase` clauses can return 0 where a sampled `_search` proves hits — cross-check any zero on a signal that matters.
- Token trap: phrase search matches whole tokens. `php2shell` does **not** match `php2shell22fe580e9` or `php2shellCVE2026109618`. Use `wildcard` on the relevant field, or query each literal exactly.
- IIS W3C rows arrive unparsed (`status`/`originIp` empty) — parse `logMessage` with the signature regexes instead of filtering on parsed fields.
- `_source` is stripped on this gateway: a `_search` with `"_source": [...]` or `"_source": true` returns hits with no fields. Use `"stored_fields": ["*"]` to read `logMessage` (and keep `size` small). `_count` rejects `size`/`stored_fields` — passing them silently returns an error body with no `count`, so keep count bodies to `{"query": …}` only.

Starter bodies (adapt field names per lane):

```json
{"query":{"bool":{"filter":[{"range":{"logDate":{"gte":"2026-10-01T00:00:00"}}},{"bool":{"should":[
  {"match_phrase":{"logMessage":"PHP_SESSION_UPLOAD_PROGRESS"}},
  {"match_phrase":{"logMessage":"attacksessionid0001"}},
  {"match_phrase":{"logMessage":"CCCCCCCCCC"}},
  {"match_phrase":{"logMessage":"PHP2SHELL_CORE_"}},
  {"match_phrase":{"logMessage":"BNDRY12345"}},
  {"wildcard":{"logMessage":"*Php2Shell*"}}
],"minimum_should_match":1}}]}}, "size":0}
```

Outcome plane:

```json
{"query":{"bool":{"must":[
  {"match_phrase":{"logMessage":"in Unknown on line 0"}},
  {"range":{"logDate":{"gte":"2026-10-01T00:00:00"}}}
]}}, "size":0}
```

Then the same shape for `"segmentation fault"`, `"SIGSEGV"`, `"SIGABRT"`, `"POST Content-Length"`, and `"shell_"` (shell_ is noisy — constrain to GET lines and `.phtml|.php5|.phar` with a client-side regex over fetched rows).

Execution plane (webshell fetches) — `_search` with `_source` and client-side filter:

```json
{"query":{"bool":{"must":[{"match_phrase":{"logMessage":"shell_"}},{"range":{"logDate":{"gte":"2026-10-01T00:00:00"}}}]},
 "_source":["logMessage","logDate"],"size":200}
```

Apply regex `GET\s+\S*shell_[0-9a-f]{8}\.(phtml|php5|php|phar)` in Python — do not trust a phrase match for a 20-char token.

## Elastic DSL (vanilla Elasticsearch / Kibana)

```json
{"size":0,"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-30d"}}}],
 "should":[{"match_phrase":{"message":"PHP_SESSION_UPLOAD_PROGRESS"}},
           {"wildcard":{"message":"*Php2Shell*"}},
           {"match_phrase":{"message":"in Unknown on line 0"}}],"minimum_should_match":1}},
 "aggs":{"by_client":{"terms":{"field":"client.ip","size":50}}}}
```

For webshell fetches use a `regexp` query on `url.path` (`shell_[0-9a-f]{8}\.(phtml|php[0-9]?|phar)`) if the field is a keyword; otherwise fetch and filter client-side.

## Splunk

```spl
index=web (sourcetype=access_combined OR sourcetype=apache_error)
| regex _raw="(?i)(PHP_SESSION_UPLOAD_PROGRESS|attacksessionid0001|CCCCCCCCCC|Php2Shell|PHP2SHELL_CORE_|BNDRY12345|in Unknown on line 0)"
| stats count min(_time) as first max(_time) as last values(clientip) as clients by host
```

```spl
index=web sourcetype=access_combined
| regex _raw="GET \S*shell_[0-9a-fA-F]{8}\.(phtml|php5|php|phar)"
| table _time clientip host uri status
```

## Microsoft Defender XDR — KQL

```kql
// shell spawned by a web worker (Linux or Windows)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("httpd","apache2","php-fpm","php-cgi","php","w3wp.exe","nginx")
| where FileName in~ ("sh","bash","dash","curl","wget","python3","perl","nc","socat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

```kql
// file drops into PHP temp space or web roots
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"(^/tmp/php|/var/www/.*/(uploads?|media|images|storage)/)"
| where FileName matches regex @"(shell_[0-9a-f]{8}\.(phtml|php5?|phar)|php_info\.php|i\.php|p\.php)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
```

```kql
// large outbound POSTs from a web server (leak or drop stage)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (80, 443)
| where BytesSent > 500000
| where InitiatingProcessFileName in~ ("php-fpm","php","httpd","apache2","w3wp.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, BytesSent, BytesReceived, InitiatingProcessFileName
```

## WAF / edge rules

- **Body inspection is mandatory** — CDN SIEM (e.g. Akamai) logs only matched-rule events and by default does not see POST bodies. A WAF that cannot inspect multipart field names cannot detect this family.
- Rule shape: `POST` + path ends `.php`/`.phtml` + `Content-Length > 200000` **or** chunked + body contains multipart field `PHP_SESSION_UPLOAD_PROGRESS` with a non-app value, boundary `CCCCCCCCCC`, or field names matching `^[fgsqtx]0{2,}\w{6,}$` / `files\[R\d{5}\]`. Challenge or block; log the body hash.
- Session-scale cap: reject `PHPSESSID` request cookies that are not 32 hex chars on endpoints that do not use session uploads.

## Triage decision tree

| Signal combination | Label | Action |
|---|---|---|
| Request markers only, no OOM/crash | Scanner/probe | Log, block source if repeated |
| Request markers + startup OOM (`Unknown on line 0`) | Pressure stage executed | Treat as attempt; check for follow-on B1 body |
| + worker crash, or 819,200-byte `PHPSESSID` in responses | Disclosure stage | Assume compromise in progress; isolate and capture |
| + `/bin/sh` worker-parent, `/tmp/php*` write, `shell_<hex>` GET 200 | Execution | Incident; hunt persistence and egress |
| `internet-census` UA/PTR, small fixed body, no crash | Survey | Close as benign |
| Loopback or developer workstation, `php2shell-lab` | Lab reproduction | Owner confirmation |

## False-positive classes seen in the wild (verified on a large estate)

- The word `php2shell` in newsletter/mail transport traffic — peaks the day after disclosure (tens of thousands of rows). Not web requests.
- App-level OOMs with a named `file:line` (WordPress plugins, GCP dev lanes) — legitimate memory pressure, not `Unknown on line 0`.
- `rawkey` / upload-progress markers in developer tooling and security-scanner signatures.
- Vendor WAF hits for `/search/PhP2shell` or `php2shell-incident-research/1.0` user agents — crawlers and researchers.
- Telemetry copies of alert emails that quote the exploit name — the word appears in email bodies, not requests.
