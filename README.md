# burp2api

Burp Suite Professional extension that exposes proxy traffic, scanner, scope,
session, and Collaborator workflows through a local REST and WebSocket API.
It is built to give an automated agent programmatic access to Burp during a
security test.

This is a Burp extension, not a standalone command-line program. It requires
Burp Suite Professional and should only be used in controlled environments.
The API can expose captured traffic, cookies, tokens, and active-scanning
operations. It binds to loopback (`127.0.0.1`) by default; do not expose its
port to untrusted networks, and set an authentication token before binding to
any non-loopback interface.

## Features

- Search, filter, replay, send, tag, comment on, and export captured HTTP traffic
- Send arbitrary HTTP requests with custom headers and capture the response
- Start scans and retrieve scanner findings
- Manage Burp scope and project configuration
- Work with Collaborator payloads and interactions for out-of-band testing
- Reconstruct a host's live browser session cookies from captured proxy
  traffic (`GET /auth/cookies?host=<host>`) so an existing authenticated
  session can be reused without re-running the login flow
- Extract cookies and configure token injection for authenticated testing
- Stream traffic events over WebSockets
- Export JSON, CSV, HAR, cURL, OpenAPI, and Postman representations
- Store traffic in a per-Burp-project SQLite database (beside the `.burp` file,
  or under `~/.burp2api/` for temporary projects) with
  full-text search; unlike Burp's in-memory Logger tab it survives restarts, and
  nothing is pruned automatically
- Loopback-only binding plus optional bearer-token authentication

## Requirements

- Burp Suite Professional with Montoya API support
- OpenJDK 21
- Maven 3.6 or newer
- Port `7850` available, unless reconfigured

## Build and install

```bash
git clone https://github.com/lwierzbicki/burp2api.git
cd burp2api
mvn clean package
```

The shaded extension JAR is written to
`target/burp2api-1.1.0.jar`. In Burp Suite Professional, open
**Extensions → Installed → Add**, select **Java**, and choose that JAR.

Burp loads the JAR directly; there is no command-line entry point to install.

## Configuration

The extension listens on `127.0.0.1:7850` by default and stores its
configuration under `~/.burp2api/`. The per-project SQLite database is placed
beside the open `.burp` project file, falling back to `~/.burp2api/` for
temporary projects or when a database path is explicitly configured (see
[Traffic persistence](#traffic-persistence)).

Environment variables:

- `BURP2API_PORT` — listen port (default `7850`)
- `BURP2API_BIND` — bind interface (default `127.0.0.1`; use `0.0.0.0` only with a token)
- `BURP2API_TOKEN` — optional bearer token; when set, every route except
  `/health` requires `Authorization: Bearer <token>`
- `BURP2API_DB_PATH`
- `BURP2API_VERBOSE` — set `true` to lower the extension log level to `DEBUG`
  (per-request access logs, SQL, orphaned-response handling). Default `false`
  keeps the console quiet, emitting only warnings and errors.
- `BURP2API_MAX_STORED_CONTENT_CHARS` — per-column ceiling, in characters, on a
  stored header block or body (default `10485760`, 10 MiB). Content below it is
  stored verbatim; a longer value is trimmed to exactly this length, logged at
  WARN, and flagged with `body_truncated` / `response_body_truncated` on the
  record. Nothing is ever written into the content itself. HAR export marks a
  capped body with a HAR `comment` on its `content` / `postData` object so the
  exported artifact never reads as a complete capture when it is a prefix (#23).
- `BURP2API_SESSION_TAG`
- `BURP2API_REST_URL` — Burp built-in REST API base for the scan backend
  (default `http://127.0.0.1:1337`)
- `BURP2API_REST_KEY` — Burp REST API key; leave unset for keyless loopback
  access ("Allow access without API key"). Treated as a secret; never logged.
- `BURP2API_RESOURCE_POOL` — default Burp resource pool applied to auto/REST
  scans that do not name one (default `Default resource pool`, which the
  project-options template presets to 1 concurrent request / 1000ms throttle).
  Set to an empty string to scan without a named pool.
- `BURP2API_SCAN_CONFIG` — default audit configuration for auto/REST scans
  (default `b2a-light-fuzz`, a custom config that keeps param-fuzzer's checks).
  The value is either a **library name** or a **path to a config JSON** exported
  from the Burp UI. A bare name is resolved against the Burp configuration
  library (if absent, the scan falls back to a Montoya audit). A path is shipped
  inline as a `CustomConfiguration`, so `backend=auto` works on a fresh install
  with an **empty** library — export the config once to
  `burp/config/b2a-light-fuzz.json` and point this at it. Set to an empty string
  to use Burp's default config.

Defaults also live in
[`src/main/resources/config/application.properties`](src/main/resources/config/application.properties).

### Authentication

Authentication is disabled by default for local single-user use. To require a
token:

```bash
export BURP2API_TOKEN="$(openssl rand -hex 24)"
# then load/reload the extension and call the API with:
curl -H "Authorization: Bearer $BURP2API_TOKEN" http://localhost:7850/proxy/search
```

## API usage

Once the extension is loaded:

```bash
curl http://localhost:7850/health
curl "http://localhost:7850/proxy/search?host=example.com&method=POST&limit=10"
curl http://localhost:7850/scanner/issues
```

`/health` is unauthenticated and echoes the live `port`, `bind`, and `version`,
so once you can reach it you can confirm you have the right instance:

```json
{"status":"healthy","database":"connected","port":7850,"bind":"127.0.0.1","version":"1.1.0","timestamp":1234567890}
```

The extension also logs the full base URL on load — look for
`>>> burp2api v1.1.0 listening on http://127.0.0.1:7850 (docs: .../docs) <<<`
in the Burp extension output if you are unsure which port it bound.

`GET /version` additionally reports `schema_version` alongside `api_version`, a
capability signal that does not depend on which database is open. Byte-exact raw
request/response capture (the `/proxy/history/{id}/raw` endpoint below) landed at
**schema v12**, so `schema_version >= 12` confirms a jar has the lossless-capture
fix — the reliable way to tell a current build from an older `1.0.1` one that
stored some responses lossily:

```json
{"api_version":"1.1.0","schema_version":12,"burp_version":{"name":"Burp Suite Professional","version_string":"2026.6","build_number":123456,"edition":"PROFESSIONAL"}}
```

### Searching captured traffic

`GET /proxy/search` queries burp2api's **own SQLite store**, not Burp's live
proxy history. Traffic sent through this API (e.g. `/proxy/send`) is recorded
automatically, but **pre-existing browser/proxy history is not searchable until
you import it once** with `POST /proxy/import-history`:

```bash
# One-time (per project): copy the current Burp proxy history into the API DB.
curl -X POST http://localhost:7850/proxy/import-history
# Now older browser traffic is searchable.
curl "http://localhost:7850/proxy/search?host=example.com&method=POST&limit=10"
```

Common filters: `url`, `match`, `method`, `host`, `hosts[]`, `status_code`,
`session_tag`, `tags`, `has_tags`, `has_comments`, `comment`,
`case_insensitive`, `start_time`, `end_time`, `since`, `until`, `limit`,
`offset`, `sort`, `order`.

**Time window.** `since` and `until` bound the request timestamp server-side,
before the row cap is applied, so a windowed query returns every in-window row
even when out-of-window noise (SPA polling, health checks) would otherwise fill
the cap. Both accept epoch milliseconds or ISO 8601; `since` is exclusive,
`until` is inclusive. Unparseable values are ignored, never treated as a
filter.

```
curl "http://localhost:7850/proxy/search?host=example.com&since=1759168800000&until=1759169700000"
```

The `url` filter is a **substring match by default**, so `url=/orders` also
returns `/orders/42`, `/api/orders`, and anything else containing that text. To
narrow it:

- `match=exact` pins one **full** URL exactly
  (`url=https://example.com/orders&match=exact`) — no substring, no wildcards.
- `*` and `?` wildcards in `url` give anchored `LIKE` matching
  (`url=https://example.com/orders*`).

**Ordering.** Results are **newest-first by default** (`ORDER BY timestamp DESC`),
so `offset=0` holds the newest rows and the oldest sit at the highest offset.
Control it with:

- `order=newest` (default) / `order=oldest` — newest or oldest capture first,
  regardless of any `sort`.
- `sort=<column>&order=asc|desc` — sort by `id`, `timestamp`, `method`, `host`,
  `status_code`, or `url` (unknown columns fall back to `timestamp`).

Rows are always tie-broken by `id` in the same direction, so paginating a large
history with `limit`/`offset` is stable even when many rows share a timestamp —
no row is dropped or duplicated across pages.

To reliably locate one **specific captured request**, tag it and filter by that
tag rather than by path: send or replay it with a distinct `session_tag` (or
`POST /proxy/tag` an existing record), then `?session_tag=VULN-014`. A path
substring alone is not a unique locator on a busy history.

The response is **always a JSON object** (never a bare array and never an
`items` key); results live under `results`:

```jsonc
{
  "results": [
    {
      "id": 123,
      "timestamp": 1782590998893,
      "session_tag": "default",
      "traffic_source": "API",          // originating tool: API, PROXY, IMPORTED, REPEATER, MANUAL, ...
      "method": "GET",
      "url": "https://example.com/path",
      "host": "example.com",
      "status_code": 200,
      "headers": "...",                  // request headers (flattened string)
      "headers_list": [ { "name": "User-Agent", "value": "..." } ], // structured, ordered
      "body": "...",                     // request body (see "Body encoding")
      "body_encoding": "utf-8",          // "utf-8" | "base64"
      "response_headers": "...",
      "response_headers_list": [ { "name": "Set-Cookie", "value": "..." } ], // structured, ordered
      "response_body": "...",            // captured response body (see "Body encoding")
      "response_body_encoding": "utf-8", // "utf-8" | "base64"
      "content_hash": "...",
      "request_http_version": "HTTP/2",
      "response_http_version": "HTTP/2",
      // timing (ms): may be 0 when not measured
      "request_time": 0, "response_time": 0, "total_time": 0,
      "dns_resolution_time": 0, "connection_time": 0, "tls_negotiation_time": 0
    }
  ],
  "count": 1,                            // results.length on this page
  "total_count": 1,                      // total matching rows (all pages)
  "filters": { "host": "example.com" },  // echoed, normalized query filters
  "pagination": {                        // present ONLY when limit or offset is set
    "limit": 10, "offset": 0,
    "total_pages": 1, "current_page": 1,
    "has_next": false, "has_previous": false
  }
}
```

To parse reliably, read `results` (defaulting to an empty array) and treat
`pagination` as optional. `count` is the size of the current page; use
`total_count` for the full match count.

Two response-shape surprises trip up new consumers, so they are worth stating
plainly:

- **The row status field is `status_code` (not `status`).** Every captured row
  carries the HTTP response code under `status_code`; there is no `status` key,
  and `status` is also the filter name (`?status_code=200`). Reaching for a
  bare `status` returns `undefined`.
- **`GET /proxy/history` returns its rows under a `history` key**, not the
  `results` key that `/proxy/search` uses. The two read endpoints deliberately
  differ: `/proxy/search` is the filtered store query wrapped as
  `{results, count, total_count, ...}`, while `/proxy/history` is the
  scope-filtered history view wrapped as `{history: [ ... ]}` with the same
  per-row shape shown above. Read `history` from one and `results` from the
  other; do not assume a shared envelope.

Across every read endpoint, prefer the structured `headers_list` /
`response_headers_list` arrays over the flattened `headers` / `response_headers`
strings (see [Reading response headers](#reading-response-headers)), and for a
citable byte-exact record use `GET /proxy/history/{id}/raw`
([below](#byte-exact-evidence-get-proxyhistoryidraw)).

### Traffic persistence

Burp's **Logger** tab holds traffic in memory and is not written to the project
file, so requests an extension sends are gone after a Burp restart. burp2api
does not depend on it. Everything it sends (`/proxy/send`, `/proxy/replay`,
`/proxy/replay-matched`) or captures from other tools is written to its own
per-project SQLite file (see below), which survives Burp restarts, extension
reloads, and reopening the project. Treat that store — not the Logger tab — as
the durable record.

**Request and response bodies are captured in full.** Every proxied transaction
is recorded by a single handler that snapshots both bodies synchronously as the
response is received, so an ordinary `200`/`201` capture stores its request body
(`body`) and response body (`response_body`) durably and retrievably — through
`/proxy/search`, `/proxy/history`, the export endpoints, and byte-exact via
`/proxy/history/{id}/raw`. A body is only ever a prefix when it exceeded
`BURP2API_MAX_STORED_CONTENT_CHARS`, and that case is flagged explicitly with
`body_truncated` / `response_body_truncated` on the row (see the raw endpoint for
the untrimmed bytes) — a stored body is never a silently empty string standing in
for content that was actually present (#53). An empty `body`/`response_body` in a
row therefore means the message genuinely had no body (a bodyless `GET`, a `204`,
a redirect), not a lost capture.

**One database per Burp project.** The filename is derived from the Burp
project name (sanitized for the filesystem), so a project named `acme-2026`
writes `burp2api_acme-2026.db`. When a disk-based Burp project (a `.burp` file)
is open, the database is placed **beside the `.burp` file** so it travels with
the project instead of accumulating in the home directory — opening
`/cases/acme/acme-2026.burp` writes `/cases/acme/burp2api_acme-2026.db`. A Burp
*temporary* project has no project file and falls back to
`~/.burp2api/burp2api_Temporary_Project.db`, which every temporary project then
shares. Open a named Burp project file before work whose traffic you intend to
keep or cite. An explicit database-path override (UI field or `BURP2API_DB_PATH`)
is always honored and disables co-location.

```bash
# Which database is active, plus every other .db in its directory.
curl http://localhost:7850/config/databases
```

**Nothing expires.** There is no retention window and no automatic pruning;
scheduled maintenance only runs `VACUUM`/`ANALYZE` and never removes rows.
Traffic goes away only when you delete it:

```bash
curl -X DELETE "http://localhost:7850/proxy/delete?session_tag=VULN-014"
curl -X DELETE "http://localhost:7850/proxy/delete?start_time=2026-01-01T00:00:00&end_time=2026-01-02T00:00:00"
curl -X DELETE "http://localhost:7850/proxy/delete?all=true"

# Drop a whole project's database (the active one is refused).
curl -X DELETE "http://localhost:7850/config/databases/burp2api_old-engagement.db"
```

### Exporting traffic as evidence

Tag each test case with `session_tag` when sending, then export by that tag
later. Every exporter below accepts the same filters as `GET /proxy/search`.

```bash
# 1. Send under an evidence tag.
curl -X POST http://localhost:7850/proxy/send \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"https://target.example/admin","session_tag":"VULN-014"}'

# 2a. Full request/response records, JSON or CSV. Exports every matching row -
#     limit/offset are stripped. JSON is wrapped as {export_metadata, data}.
curl -OJ "http://localhost:7850/proxy/search/download?session_tag=VULN-014&format=json"
curl -OJ "http://localhost:7850/proxy/search/download?session_tag=VULN-014&format=csv"

# 2b. HAR, for a browser-style timeline or a HAR-consuming report tool.
#     NOTE: limit defaults to 1000; pass an explicit limit for a full export.
curl -OJ "http://localhost:7850/proxy/har-export?session_tag=VULN-014&limit=100000"

# 2c. A reproducible curl command for one record, by id. The id is the public
#     proxy_traffic.id from /proxy/search; an internal traffic_meta_id (e.g. from
#     /proxy/search/request-body) is also accepted and resolved through its
#     proxy_traffic_id link. The response echoes request_id (the public id used),
#     requested_id, and resolved_via ("id" or "traffic_meta_id") (#22).
curl "http://localhost:7850/proxy/request/123/curl"

# 2d. Raw JSON to feed a screenshot or report generator directly.
curl "http://localhost:7850/proxy/search?session_tag=VULN-014"
```

Two things to handle in a report pipeline:

- Bodies may be Base64. Check `body_encoding` / `response_body_encoding` on each
  record before rendering it — see [Body encoding](#body-encoding).
- Traffic captured by the browser before the extension loaded is not in the
  store until you run `POST /proxy/import-history` once for the project.
- `POST /proxy/tag` and `POST /proxy/comment` take the same `proxy_traffic.id`
  every read endpoint returns and resolve it through the `proxy_traffic_id` link
  (schema v14), so the annotation lands on the request you are looking at even
  though tags and comments live in a separately numbered metadata table (issue
  #21). An id that names no captured request answers `404`; there is no longer a
  `409` id-space refusal. `GET /proxy/tags` and `GET /proxy/comments` report each
  hit under the public `id` (with the internal `traffic_meta_id` alongside), so a
  tagged id round-trips back into `/proxy/tag`, `/proxy/search` and `/proxy/replay`.

### Replaying by id (the public id space)

The id every read endpoint hands you (`/proxy/search`, `/proxy/history`,
`/proxy/send`) is a `proxy_traffic.id`, and that is the id `/proxy/replay`
resolves. Treat it as the one public id space — a search id round-trips into
replay and replays the same request (same method + URL).

`GET /proxy/search/request-body` is FTS-backed over an internal, separately
numbered table, so historically its `id` was **not** replayable — handing it to
`/proxy/replay` silently replayed a different request (#28). Each capture now
records the exact `proxy_traffic.id` it also wrote as a `proxy_traffic_id` link on
the normalized row (schema v14), and the search resolves through that link — not
a `content_hash` guess — so a request captured more than once resolves to the
exact instance rather than the newest lookalike. Each hit carries:

- `id` — the replayable `proxy_traffic.id` (or `null`), so a request-body hit can
  be handed straight to `/proxy/replay`.
- `traffic_meta_id` — the internal id, kept only for transparency; do not replay
  with it.
- `replayable` — `false` when the hit has no linked `proxy_traffic` counterpart
  (e.g. Repeater traffic, or a pre-v14 row whose `content_hash` mapping was
  ambiguous and left unlinked by the migration backfill). `id` is then `null`;
  reconstruct the request from the returned `request_headers` + `request_body` and
  send it via `POST /proxy/send`.

The `query` is a full-text FTS5 expression: bare terms, `"quoted phrases"`,
`prefix*`, and boolean `AND`/`OR`/`NOT` all work. (Before #29 the underlying
index was misconfigured and every query silently degraded to a literal
`LIKE '%query%'` substring scan; the FTS5 grammar now actually runs.)

`GET /proxy/search/response-body` is the symmetric endpoint for **response**
bodies (and response headers), with the same query grammar, the same hit shape
(`id`/`traffic_meta_id`/`replayable`), and the same public-id resolution. It
matches the `response_index` FTS5 table, which is trigger-maintained for every
normalized capture but previously had no endpoint querying it — so a
response-body search returned nothing (a 404) even though the evidence was
indexed (#12). Use it to find a captured response by a value it echoed, e.g. a
resource id surfaced by a blind IDOR:

```bash
curl -s "http://localhost:7850/proxy/search/response-body?q=account_9f3c1&limit=20"
```

Both body-search endpoints read the normalized capture (populated for every
tool's traffic, HTTP/1.1 and HTTP/2 alike), so a hit always carries the paired
`status_code`, `response_headers`, and `response_body`.

> **HTTP/2 evidence: prefer the body-search endpoints over raw `/proxy/search`
> history.** For proxy-listener HTTP/2 traffic, the flat `proxy_traffic` history
> can fragment a single exchange into more than one row — a correctly correlated
> row plus, occasionally, an orphaned request row left at `status_code: null`
> (the request-side capture whose response landed on a sibling row). This is the
> id-space/async-correlation divergence tracked in #21, not a lost capture: the
> normalized store that `/proxy/search/request-body` and
> `/proxy/search/response-body` read always has the correlated row with a
> populated `status_code` and both bodies. Search by a value from the exchange
> (a resource id, a marker) to land on that row directly rather than scanning
> raw history. Orphaned *response* rows now also carry
> `request_http_version`/`response_http_version` instead of null (#12).

`POST /proxy/replay` no longer silently drops ids it cannot resolve — every
unresolved id is returned under `not_found`. For a stronger guarantee, assert the
request you mean with an optional `expect`:

```bash
# Assert intent: replay id 12345 only if it really is that POST signin request.
curl -s -X POST http://localhost:7850/proxy/replay -H 'Content-Type: application/json' -d '{
  "request_ids": [12345],
  "expect": {"method": "POST", "url": "https://target.example/di/idp/dwa/signin"}
}'
```

`expect` accepts `method` and/or `url` (compare is case-insensitive for method,
exact for url) at the top level, or per id via the object form
`{"id": 12345, "expect": {...}}`. An id whose resolved row does not match is
**not** replayed; it is reported under `mismatched`, and a request where nothing
was replayable returns `409`.

### Body encoding

Every endpoint that returns a captured HTTP body emits RFC 8259-valid JSON that
parses with a plain client (no pre-processing). Each body field is paired with an
`*_encoding` discriminator:

- `utf-8` — the body is valid UTF-8 and is returned as a text string. Control
  characters (newline, tab, NUL, and the rest of `U+0000`–`U+001F`) are escaped
  by the serializer (`\n`, `\t`, `\u0000`, …), so the payload stays valid JSON.
- `base64` — the body is binary or not valid UTF-8, so it is Base64-encoded to
  avoid corrupting it. Decode `body` with a Base64 decoder to recover the exact
  bytes.

This applies uniformly to `POST /proxy/send`, `GET /proxy/search`,
`GET /proxy/search/download` (JSON), and `GET /proxy/history`. The discriminator
fields are `body_encoding` (request body) and `response_body_encoding` (response
body). For `GET /proxy/har-export`, binary response bodies use the standard HAR
`content.encoding: "base64"` marker instead. `POST /proxy/replay` does not return
captured body content (only status and length).

Captured bodies are stored **verbatim** — no character is removed on the way in,
so a binary or compressed body decodes to exactly the bytes the proxy received.
Each record also carries `body_truncated` / `response_body_truncated` and the
`max_stored_content_chars` ceiling that applied, so a trimmed body is always
distinguishable from a complete one without inspecting its content.

One consequence worth knowing: SQLite's own string functions stop at an embedded
NUL byte, so a `LIKE`-based body filter (and `length()`) sees only the part of a
body before its first NUL. This affects binary bodies, which were previously not
searchable in any meaningful sense either — their bytes were being dropped
entirely. Use `response_body_encoding` plus a client-side check for binary
content rather than SQL-side matching.

```bash
# Decode a base64 body from a search result
curl -s "http://localhost:7850/proxy/search?limit=1" \
  | jq -r '.results[0] | select(.response_body_encoding=="base64") | .response_body' \
  | base64 -d > body.bin
```

### Reading response headers

Alongside the flattened `headers` string, responses carry a structured
`headers_list` (and `response_headers_list` on captured records): an ordered
array of `{"name": ..., "value": ...}`. Order and duplicates are preserved, so
multi-value headers such as multiple `Set-Cookie` appear as separate entries and
comma-containing values (e.g. `Date`, `Expires`) are not split. The original
`headers` string is unchanged for back-compat.

`POST /proxy/send` builds `headers_list` directly from the live response, so it
is byte-exact. The DB-backed responders (`/proxy/search`, `/proxy/history`,
`/proxy/search/download`, `/proxy/har-export`, `/proxy/request/{id}/curl`) all
parse the stored header block through the same parser, so they agree.

That parse is best-effort by construction. Captured headers are stored as a
`[Name: Value, Name: Value]` list, which is ambiguous because a value may itself
contain `", "`. The parser resolves it by treating a fragment as a continuation
of the previous header unless the text before its first colon is a valid HTTP
field name — which recovers real-world traffic (`Cache-Control: private,
max-age=0`, `Expires: Fri, 24 Jul 2026 08:19:53 GMT`) but cannot be exact for a
value that happens to contain `", "` followed by something shaped like a header.
So the flattened `headers`/`body` columns and the derived `headers_list` are a
best-effort **search projection**, not the evidence source. For byte-exact
evidence, read the stored raw bytes (below).

```bash
# Pull a single header without re-parsing the blob
curl -s -X POST http://localhost:7850/proxy/send -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"https://example.com/"}' \
  | jq -r '.response.headers_list[] | select(.name|ascii_downcase=="server") | .value'
```

### Byte-exact evidence: `GET /proxy/history/{id}/raw`

Alongside the lossy projection columns, each captured row stores the **exact
wire bytes** of the request and response in BLOB columns. `GET
/proxy/history/{id}/raw` returns them base64-encoded, so a client decode
reproduces byte-for-byte what Burp sent and received — comma-valued headers
intact, response body whole (NUL bytes and all). This is the citable evidence
source; the stored row no longer needs a send-time `.http` side-capture.

```json
{
  "id": 4242,
  "request_raw_b64": "R0VUIC94IEhUVFAvMS4x...",
  "response_raw_b64": "SFRUUC8xLjEgMjAw...",
  "request_raw_present": true,
  "response_raw_present": true,
  "request_raw_omitted": false,
  "response_raw_omitted": false,
  "max_raw_bytes": 52428800
}
```

```bash
# Recover the exact response bytes for a captured row
curl -s http://localhost:7850/proxy/history/4242/raw \
  | jq -r '.response_raw_b64' | base64 -d > response.raw
```

A message larger than `max_raw_bytes` (env `BURP2API_MAX_RAW_BYTES`, default
50 MiB) is **omitted, not truncated**: its `*_raw_b64` is `null` and its
`*_raw_omitted` flag is `true`, so a partial raw message is never mistaken for a
complete one. Rows captured before this feature (schema < v12), and paths that
only ever had a reconstructed string, report `*_raw_present: false` with
`*_raw_omitted: false` and a `note` — they are not recoverable byte-exact and
say so rather than fabricating bytes.

### Out-of-band testing with Collaborator

`POST /collaborator/payloads` mints payloads from a shared, API-managed
Collaborator client, so blind/OOB findings can be confirmed through the API
alone. Use the returned `payload` in a probe, then poll for interactions by
payload — no `client_secret` to track:

```bash
# 1. Mint a payload (returns payload string and a poll_url)
curl -s -X POST http://localhost:7850/collaborator/payloads

# 2. Fire the payload at the target (SSRF, blind injection, etc.), then poll
curl "http://localhost:7850/collaborator/interactions?payload=<payload>"
```

Interactions are recorded against the shared client for the lifetime of the
loaded extension. The Collaborator secret is never logged or written to disk.
Pass `client_secret` to poll a separate client created via
`POST /collaborator/payloads/client`.

**These API-client payloads are not visible in Burp's interactive Collaborator
tab, and API polling consumes their interactions** (#12). Both
`POST /collaborator/payloads` and `POST /collaborator/payloads/client` mint from
a private API client — distinct from Burp's default (UI) client — so an operator
watching the Collaborator tab sees nothing even while the OOB is firing, and a
poll drains the interaction so a later UI/API read misses it. The responses flag
this with `"ui_visible": false` and a `note`. Choose the workflow that matches
who needs to see the hit:

- **API-only confirmation** (automation, unattended runs): use
  `POST /collaborator/payloads` and poll `GET /collaborator/interactions`. The
  tab stays empty by design; the API is the source of truth.
- **Operator-visible hit** (you are watching the Collaborator tab): mint the
  payload where the interactive client can see it. Either use
  `POST /collaborator/payloads/url` (single payload from Burp's **default**
  generator — it *does* surface in the tab; returned as plain text like "copy to
  clipboard"), or copy a payload straight from your Collaborator tab. Fire that
  value at the target, then poll your own tab — not the API — so the interaction
  is not consumed out from under the UI.

Montoya exposes no handle to read or mirror the interactive client's
interactions, so the tool cannot surface API-client hits in the tab or vice
versa; pick one side per payload up front.

### Sending requests and header formats

`POST /proxy/send` and `POST /scanner/scan-request` require `method` and `url`.
The `headers` field is optional and accepts three interchangeable shapes:

- a JSON object — `{"User-Agent": "x", "Referer": "https://example.com/"}`
- an array of `[name, value]` pairs — `[["Accept", "text/html"], ["X-Debug", "1"]]`
- a legacy CRLF string — `"User-Agent: x\r\nReferer: https://example.com/"`

Duplicate header names are last-wins. The object form is usually the most
convenient:

```bash
curl -s -X POST http://localhost:7850/proxy/send -H 'Content-Type: application/json' -d '{
  "method": "GET",
  "url": "https://example.com/",
  "headers": {"User-Agent": "x", "Referer": "https://example.com/"}
}'
```

#### HTTP/2-safe scripted probing (the `b2a_send` client)

Do **not** point a `python-requests` / `urllib3` client at an HTTP/2 origin
*through* the Burp proxy. `urllib3` speaks only HTTP/1.1, so the proxied
response aborts client-side with `('Connection aborted.',
UnknownProtocol('HTTP/2'))` — every probe errors and returns no status, so a
batch reads as "endpoint broken" when it is really a client limitation (#19).

Route scripted probes through `POST /proxy/send` instead. It issues the request
through Burp's own HTTP stack, which negotiates HTTP/2 natively, and returns the
parsed status/headers/body. The fuzzer only ever speaks plain HTTP/1.1 JSON to
burp2api on loopback, so `UnknownProtocol('HTTP/2')` cannot occur; the response
even reports the negotiated `http_version`.

`clients/b2a_send.py` is a dependency-free (stdlib-only) helper that wraps
`/proxy/send` with a small `requests`-like surface, so an existing fuzzer swaps
its client with a one-line change:

```python
from b2a_send import Session          # clients/b2a_send.py

http = Session()                       # http://127.0.0.1:7850
r = http.get("https://h2-origin.example/api/v1/resource")
print(r.status_code, r.http_version)   # 200 HTTP/2
data = r.json()                        # .text / .content / .headers also available
```

It is also a curl-lite CLI for one-off checks against an HTTP/2 origin:

```bash
python clients/b2a_send.py -i -X POST \
  -H 'Authorization: Bearer …' -d '{"q":1}' https://h2-origin.example/api
```

### Active scanning

`POST /scanner/scan-request` starts a Burp active audit of a single request
(`method` + `url` required; `headers`/`body`/`audit_config` optional).

**Scope preflight.** An audit against a target outside Burp's Target scope is
silently accepted but sends **zero payload variations** — no error. To prevent
that, burp2api checks scope before starting the audit:

- By default (`auto_scope` omitted or `true`) the target is added to scope if
  missing; the response reports `"scoped": true` and
  `"scope_action": "already_in_scope" | "added"`.
- With `"auto_scope": false`, an out-of-scope target is rejected with HTTP `409`
  and `"error": "scan_would_send_zero_payloads"` instead of starting a no-op
  scan.

**Observing progress.** Poll `GET /scanner/tasks/{id}` (the `task_id` is returned
by the scan-request). `status` reflects Burp's real state derived from the live
task — `PENDING` → `RUNNING` → `DONE` (also `PAUSED`/`CANCELLED`/`ERRORED`).
Load-bearing signals sit at the top level and under `progress`:

- `audit_traffic_started` — whether any audit request has been sent yet.
- `stalled` — still `PENDING` with zero traffic past the threshold, i.e. likely
  queued behind other work on a memory-starved JVM rather than merely slow.
- `elapsed_ms`, plus `request_count`, `error_count`, `insertion_points`, and
  `issues_found` under `progress`.

`DELETE /scanner/tasks/{id}` cancels a running audit via Burp's task
`delete()` (also frees the shared resource pool). Resulting findings are always
retrievable via `GET /scanner/issues`.

**Backends.** burp2api runs an active audit either through Burp's built-in REST
API (which can apply a **named scan configuration** + a **resource pool** the
Montoya API cannot set) or through a Montoya single-request audit. The default is
**REST-first**, so a scan is throttled and uses a lighter config out of the box.

> **Extension checks are config-gated, not backend-gated.** Verified live:
> param-fuzzer's SSRF/SSTI/code-injection checks run on **either** backend as long
> as the audit config includes them. Burp's default config and the custom
> `b2a-light-fuzz` (the default) include them; the built-in `Audit checks -
> light/medium active` presets **exclude** them. So the only way to lose
> param-fuzzer is to pass a built-in `Audit checks - ...` preset via
> `scan_configurations`.

- `backend`: `auto` (default) | `montoya` | `rest`. `auto` prefers REST with the
  default config + pool, and falls back to a Montoya audit when the REST service
  is unreachable **or** the request is non-GET / has a body (the REST `/scan` path
  scans by URL and can't replay a custom body). Force a backend with `montoya`
  (exact-request audit, always runs param-fuzzer) or `rest`.
- `scan_configurations` *(REST only)*: array of configuration names. Omitted →
  `BURP2API_SCAN_CONFIG` (default `b2a-light-fuzz`; a file path there is sent
  inline as a `CustomConfiguration`). Explicit `[]` → Burp's default config. e.g.
  `["b2a-light-fuzz"]` or `["Audit checks - light active"]` (the latter drops
  param-fuzzer).
- `resource_pool` *(REST only)*: name of a Burp resource pool (max concurrent
  requests + throttle). Omitted → `BURP2API_RESOURCE_POOL` (default `Default
  resource pool`, preset to 1 concurrent / 1000ms by the project template). Send
  `""` to run without a named pool. The Montoya fallback path is throttled by the
  same project pool (import it via `POST /scope/project-config`).

REST-backed tasks return a `rest_`-prefixed `task_id`; `GET /scanner/tasks/{id}`
proxies Burp's authoritative `scan_status`/`scan_metrics` under the same
`status` vocabulary. If REST is unreachable (or the named config is missing),
burp2api falls back to the Montoya audit and marks `rest_backend: unavailable`.
Enable the service via `POST /config/user-config` or Burp **Settings → Suite →
REST API** (see `../burp/config/rest-api-and-scan-tuning.md`). Build the default
`b2a-light-fuzz` config per `../burp/config/b2a-light-fuzz-build.md`.

```bash
# Default: throttled, light config, param-fuzzer included (auto -> REST + b2a-light-fuzz).
curl -s -X POST http://localhost:7850/scanner/scan-request -H 'Content-Type: application/json' -d '{
  "method": "GET",
  "url": "https://target/api/item?q=1"
}'
```

**Throttling on the Montoya path (`POST /scope/project-config`).** The Montoya
API cannot set a resource pool directly, so when you are not using the REST
backend, apply one by importing project options. `POST /scope/project-config`
wraps Burp's `importProjectOptionsFromJson`: send a project-options object (or a
`GET /scope/project-config` export to round-trip it) and Burp applies it to the
current project — e.g. a resource pool that caps concurrency and throttles
requests so an audit stays within a memory-constrained JVM. The body may be the
raw options or the export-shaped `{"project_configuration": {...}}` wrapper; the
response reports `sections_imported`. A repo template lives at
`../burp/config/project-options.template.json`.

```bash
# Apply a 1-concurrent / 1000ms-throttle resource pool before scanning.
curl -s -X POST http://localhost:7850/scope/project-config \
  -H 'Content-Type: application/json' \
  --data-binary @../burp/config/project-options.template.json
```

**User options (`GET`/`POST /config/user-config`).** The built-in REST API
service settings live in Burp's **user** options, not project options — under
`user_options.misc.api` (confirmed on Burp 2026.6; `enabled`, `insecure_mode` =
"allow access without an API key", `listen_mode`, `port`). `GET /config/user-config`
wraps `exportUserOptionsAsJson`; pass `?sections=user_options.misc.api` to capture
just that block for `../burp/config/user-options.template.json`.
`POST /config/user-config` wraps `importUserOptionsFromJson` to apply a captured
block, accepting the raw options or the export-shaped `{"user_configuration": {...}}`
wrapper. The exported body can contain an API key if one is configured, so it is
never logged.

```bash
# Capture the REST API service block from a running Burp.
curl -s 'http://localhost:7850/config/user-config?sections=user_options.misc.api'

# Enable keyless REST on loopback:1337 without touching the UI.
curl -s -X POST http://localhost:7850/config/user-config -H 'Content-Type: application/json' \
  -d '{"user_options":{"misc":{"api":{"enabled":true,"insecure_mode":true,"listen_mode":"loopback_only","port":1337,"keys":[]}}}}'
```

### Stateful flows with the session cookie jar

`/proxy/send` and `/proxy/replay` can share a server-side cookie jar keyed by
`session_tag`, so multi-step flows (redirect chains, OIDC/Clerk logins) can be
driven through the API. Set `cookie_jar` to `use` (apply the jar to the outgoing
`Cookie` header and ingest `Set-Cookie` from the response), `reset` (clear the
jar first, for a fresh login), or `off` (default — stateless, unchanged). The
jar is last-write-wins per cookie, so short-lived rotating tokens (e.g. Clerk's
`__session`, ~60s) reflect their freshest value on the next call. A caller-set
`Cookie` header always overrides the jar for that cookie name.

```bash
# Step 1: start a session, following the login redirect chain.
curl -s -X POST http://localhost:7850/proxy/send -H 'Content-Type: application/json' -d '{
  "method": "GET", "url": "https://app.example.com/login",
  "session_tag": "oidc1", "cookie_jar": "reset",
  "follow_redirects": true, "max_redirects": 5
}'

# Step 2: a later call under the same session_tag carries the rotated cookies.
curl -s -X POST http://localhost:7850/proxy/send -H 'Content-Type: application/json' -d '{
  "method": "GET", "url": "https://app.example.com/api/me",
  "session_tag": "oidc1", "cookie_jar": "use"
}'
```

Set `follow_redirects: true` (with optional `max_redirects`, default 5, max 10)
to follow 3xx `Location` chains, carrying and refreshing the jar each hop.
Redirected requests carry only the jar, not caller headers (so `Authorization`
is not forwarded across origins).

Manage the jar directly:

```bash
curl "http://localhost:7850/session/cookies?session_tag=oidc1"          # inspect
curl -X DELETE "http://localhost:7850/session/cookies?session_tag=oidc1" # reset
# Seed from an already-authenticated session browsed through the proxy:
curl -X POST http://localhost:7850/session/cookies -H 'Content-Type: application/json' \
  -d '{"session_tag": "oidc1", "seed_host": "app.example.com"}'
```

The jar lives in memory only and holds live authentication material; cookie
values are never logged or written to disk. There is no expiry-based eviction —
cookies persist until replaced, explicitly deleted by a `Set-Cookie` deletion,
`DELETE /session/cookies`, or extension restart.

Useful endpoints:

- API root: `http://localhost:7850/`
- Interactive docs: `http://localhost:7850/docs`
- OpenAPI: `http://localhost:7850/openapi`
- Postman collection: `http://localhost:7850/postman`
- WebSocket stream: `ws://localhost:7850/ws/stream`

A captured OpenAPI snapshot is available at
[`docs/openapi.json`](docs/openapi.json). The running extension generates its
current specification dynamically.

## Tests

Run the offline repository contract tests from the repository root:

```bash
python -m unittest tests.test_repository_contract -v
```

Run `mvn test` for Java compilation and Maven tests when Maven is installed.

## Limitations

- Requires Burp Suite Professional; several features depend on
  professional-only Burp APIs and the active project.
- Java unit tests cover pure logic only; endpoint behavior against live Burp
  Collaborator requires loading the built JAR into Burp Suite Professional.
- Operational validation requires loading the built JAR into Burp.
- Captured traffic and configured authentication material are sensitive.

## License

MIT — see [LICENSE](LICENSE).
