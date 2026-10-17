# burp2api TODO

- [x] Persist full request/response bodies on standard proxied captures (#53):
  ordinary `200`/`201` proxy captures intermittently came back with empty request
  and response bodies from `/proxy/search` and the request-detail endpoints,
  forcing header-only archaeology and a send-time `.http` workaround. Root cause:
  every proxied transaction was written to `proxy_traffic` **twice**. `AllToolsLogger`
  (an `api.http()` HTTP handler, which Montoya notifies for every tool including
  Proxy) captured it synchronously in the handler thread — both bodies snapshotted
  to Strings, one complete `content_hash`-deduplicated row, plus byte-exact
  `request_raw`/`response_raw` BLOBs. `ProxyLogger` (a proxy request/response
  handler) then captured the *same* traffic a second time on the background
  `TrafficQueue` thread: it read the intercepted message bodies lazily off-thread
  and correlated each response to its request with a `url`+`method`+60s-window
  heuristic. Under concurrent SPA traffic that heuristic mis-matched and orphaned
  request rows, which persisted with an empty `response_body` and a `NULL`
  `status_code` (this path never set `content_hash`, so it did not even dedupe
  against the good row). Both rows surfaced in `/proxy/search`/`/proxy/history`
  (which read `proxy_traffic.body`/`response_body`), so an operator intermittently
  hit the empty-bodied `ProxyLogger` duplicate of a capture `AllToolsLogger` had
  already stored in full. Fix: stop registering `ProxyLogger`'s DB capture and let
  the single synchronous `AllToolsLogger` writer own all Proxy capture — the exact
  decision already made for `RepeaterLogger`. This removes the empty duplicates and
  halves proxy history noise; truncation past the storage cap is still flagged with
  `body_truncated`/`response_body_truncated` at read time. Trade-off: a request that
  never receives a response is no longer logged as a status-`NULL` row (those were
  the same rows the heuristic mis-correlated); byte-exact evidence for completed
  transactions is unchanged. New test: `AllToolsLoggerProxyCaptureTest` drives a
  mocked proxied POST through the handler and asserts exactly one `proxy_traffic`
  row carrying both JSON bodies and both raw BLOBs. Documented the body-persistence
  guarantee in `README.md`. Bumped extension/pom to `1.1.6`.
- [x] Stop `/proxy/search` returning empty/closed responses and pin ordering (#52):
  the `url` filter intermittently returned a 0-byte closed-connection body under
  concurrent load (retry loops with sleeps as the field workaround), and paging a
  large history was undocumented and unstable. Root cause: `searchTraffic` and
  `getSearchCount` ran on the single shared `DatabaseService.connection`, but
  SQLite's JDBC driver is not safe for concurrent use of one physical Connection —
  overlapping reads (two searches, or a search alongside `/proxy/history`) aborted
  each other mid-query, and the bigger/slower the result set the wider the window
  (host-only filters, being faster, collided less). Fix: both read paths now take a
  per-thread pooled read connection via `acquireReadConnection()`/`releaseReadConnection()`
  (falling back to the shared connection only when no healthy pool exists), so
  concurrent searches never share a Connection. The `/proxy/search` handler is also
  wrapped so any failure surfaces as a JSON error (400 on a non-integer
  limit/offset, 500 otherwise) instead of a bare closed connection. Ordering: added
  `order=newest|oldest` aliases (default remains newest-first, `timestamp DESC`, so
  `offset=0` holds the newest rows), threaded `sort`/`order` through
  `extractSearchParams` (they were dropped before, so the API had no way to reorder),
  and added an `id` tiebreaker in the sort direction so `limit`/`offset` paging is
  deterministic when rows share a timestamp. Documented the ordering contract in
  `README.md`. New tests: `DatabaseServiceSearchOrderingTest` (default/newest/oldest
  ordering, tied-timestamp pagination stability, 16-thread concurrent `url` search
  over 6000+ rows). Bumped extension/pom to `1.1.5`.
- [x] UI-visible Collaborator payloads + index HTTP/2 bodies for search (#12):
  Two field-retrospective gaps. (1) Response-body search never existed —
  `response_index` was trigger-maintained for every normalized capture but had no
  consumer, so a response-body search returned nothing. Added
  `GET /proxy/search/response-body` + `DatabaseService.searchResponseBodies`
  (FTS5 over `response_index`, LIKE fallback, same public-id resolution as the
  request-body path); request/response HTTP/2 bodies are indexed and searchable
  by value with a populated `status_code`. Verified live 2026-08 against an
  HTTP/2 origin through the proxy listener. (2) API Collaborator payloads
  (`POST /collaborator/payloads`, `.../payloads/client`) are not visible in
  Burp's interactive tab and API polling consumes them — Montoya exposes no
  handle to the interactive client, so the achievable fix is to flag them
  (`ui_visible: false` + note) and document the operator-generated-payload
  workflow (mint via `POST /collaborator/payloads/url`, which uses the default
  generator and *does* surface in the tab, or copy from the tab, then poll the
  tab). Also fixed `storeOrphanedResponse` dropping
  `request_http_version`/`response_http_version` (null HTTP version on orphaned
  HTTP/2 responses). Deferred: the flat `proxy_traffic` history fragmenting an
  HTTP/2 exchange into a correlated row + an orphaned `status_code: null` request
  row — that is the async-correlation half of the #21 id-space divergence; the
  normalized body-search endpoints are the reliable evidence path meanwhile.
- [x] Make the request-body-search id link exact, not heuristic (#28 follow-up):
  the first #28 fix resolved a request-body hit to `proxy_traffic.id` with
  `MAX(pt.id) WHERE content_hash+method+url match`, which silently returned the
  newest duplicate when a request was captured more than once (same method+URL,
  so `expect` could not catch it). Root cause: `proxy_traffic` and `traffic_meta`
  are written by different loggers under independent AUTOINCREMENT counters and
  bridged only by `content_hash`. Fix: schema v14 adds `traffic_meta.proxy_traffic_id`,
  populated at capture time by threading the just-written `proxy_traffic.id` from
  `AllToolsLogger`/`RepeaterLogger` through `queueRawTraffic` ->
  `storeTrafficNormalized` -> `insertTrafficMeta`; `searchRequestBodies` (FTS and
  LIKE) now reads that exact link instead of the `MAX` subquery. Backfill for
  pre-v14 rows is conservative — link only when exactly one `proxy_traffic` row
  matches content_hash+method+url, leave ambiguous/none NULL (reported as
  `replayable:false`). Bumped extension/pom to `1.1.3`. NOTE: this column is also
  the foundation for resolving #21 exactly (see below) — the annotation path
  (`/proxy/tag`/`/proxy/comment`, `checkTrafficIdAlignment`, the `/proxy/search`
  tag/comment join at `ON p.id = tm.id`) still uses positional id equality and
  should be migrated onto `proxy_traffic_id` as the #21 fix.
- [x] Stop `/proxy/search/request-body` handing out an unreplayable id (#28):
  the FTS search returned a `traffic_meta.id`, which `/proxy/replay` resolved
  against `proxy_traffic.id` and silently replayed a different request. The
  search now resolves each hit back to the public `proxy_traffic.id` via
  `content_hash` and returns it as `id` (plus `traffic_meta_id` and a
  `replayable` flag; `id` is null when there is no proxy_traffic counterpart).
  `/proxy/replay` now reports unresolved ids under `not_found` instead of
  dropping them, and accepts an optional `expect` ({method?,url?}, top-level or
  per-id) that refuses (409, `mismatched`) rather than replaying a request the
  caller did not mean. Bumped extension/pom to `1.1.1`. NOTE: discovered a
  separate latent bug (#29), now fixed below.
- [x] Fix the dead request/response FTS5 indexes (#29): `request_index` (and
  `response_index`) were FTS5 external-content tables over `traffic_requests`/
  `traffic_responses` but declared columns (`request_headers`/`request_body`/
  `url`/`method`) absent from those content tables, so every `MATCH` raised
  "no such column" and the search silently fell back to `LIKE '%q%'` — the FTS5
  grammar (prefix/phrase/boolean) was never reachable. Migration V13 rebuilds
  both as self-contained FTS5 tables (schema `12 -> 13`); it rebuilds only the
  legacy external-content tables and skips freshly-created self-contained ones,
  which also avoids a same-transaction drop/recreate of a just-created virtual
  table (SQLite rejects that once V12's `ALTER TABLE` has run in the txn). The
  triggers now pin the FTS `rowid` to `traffic_requests.id` so the previously
  no-op delete/update triggers keep the index in sync. `response_index` was
  fixed too though its only consumer (`searchTrafficFullText`) is currently dead
  code. Bumped extension/pom to `1.1.2`.
- [ ] Fix the diverged `proxy_traffic` / `traffic_meta` id spaces (#21):
  `/proxy/tag` and `/proxy/comment` take a `proxy_traffic.id` from
  `/proxy/search` but update `traffic_meta` keyed on its own AUTOINCREMENT id,
  so annotations land on a different captured request and still report
  `success: true`. `/proxy/replay/lineage/{id}` and the WebSocket
  `traffic_capture` event resolve the same ambiguous id. The
  `proxy_traffic_id` column + migration this asks for now exists (schema v14,
  added for #28); remaining work is to repoint the annotation writes and reads
  onto it: `updateTrafficTags`/`updateTrafficComment` (`UPDATE traffic_meta ...
  WHERE id = ?`), `checkTrafficIdAlignment` (`ON tm.id = pt.id`), the
  `/proxy/search` tag/comment join (`ON p.id = tm.id`), lineage, and the WS
  `traffic_capture` id. Backfill for existing rows is heuristic (v14 links only
  unambiguous content_hash matches), so rows left NULL must be handled explicitly
  rather than silently mis-annotated.
- [x] Byte-exact raw request/response capture (#24): store the exact wire bytes
  (`request_raw`/`response_raw` BLOB + `*_omitted` flags, schema v12) at every
  `proxy_traffic` write, capped by `BURP2API_MAX_RAW_BYTES` (default 50 MiB,
  omit-not-truncate), and serve them base64 via `GET /proxy/history/{id}/raw`.
  The flattened `headers`/`body` columns are now a documented best-effort search
  projection, not the evidence source. Deferred: deriving `headers_list`/body
  from raw on read (approach C) and raw capture for intermediate redirect hops.
- [x] Make the lossless-capture fix identifiable and document the read-response
  shape (#26): bump the extension/pom version to `1.1.0` and expose
  `schema_version` on `GET /version` so an operator can confirm a jar has the
  byte-exact capture (schema >= 12) rather than an older `1.0.1` build that
  stored some responses lossily. Document in README/openapi that `/proxy/history`
  returns rows under a `history` key (not `results`), the row status field is
  `status_code` (not `status`), and consumers should prefer
  `headers_list`/`response_headers_list` over the flattened `headers` blob. The
  underlying capture bug was already fixed by #20 (read-side repair) and #24
  (raw BLOB evidence); this closes the remaining identifiability and docs gaps.
- [x] Flag body truncation in the HAR evidence artifact (#23): the JSON API
  (`body_truncated`/`response_body_truncated`) and cURL export already mark a
  capped body, but `har-export` emitted the stored prefix with no indicator, so
  a HAR pasted into a report read as a complete capture. When a stored request
  or response body reached `BURP2API_MAX_STORED_CONTENT_CHARS`
  (`StoredText.isCapped`), the HAR `content`/`postData` object now carries a
  `comment` truncation notice naming the cap. The pre-#20 65536-byte silent
  truncation is already gone (cap is 10 MiB, byte-exact raw at 50 MiB via #24).
- [ ] Add focused Java unit tests for pure services and utilities.
- [ ] Add a mocked Montoya integration test for extension initialization.
- [ ] Verify the shaded JAR manually in the supported Burp Suite Professional
  version after each Montoya API upgrade.
- [x] Bind to loopback by default and add optional bearer-token authentication
  (`BURP2API_BIND`, `BURP2API_TOKEN`). Re-review before any non-local exposure.
- [x] Session-scoped cookie jar for `/proxy/send` and `/proxy/replay`
  (`cookie_jar=use|reset|off`, keyed by `session_tag`, last-write-wins for
  rotating tokens), opt-in redirect following (`follow_redirects`,
  `max_redirects`), and `/session/cookies` inspect/reset/seed (#3).
- [x] Document `/proxy/search` response schema (always an object with a
  `results` array; conditional `pagination`) and the `/proxy/import-history`
  prerequisite for pre-existing browser traffic, in README and openapi.json (#4).
- [x] Emit RFC 8259-valid JSON for captured bodies: `BodyCodec` returns UTF-8
  text (control chars escaped) or Base64 for binary/non-UTF-8, with a
  `body_encoding`/`response_body_encoding` discriminator across `/proxy/send`,
  `/proxy/search`, `/proxy/search/download`, `/proxy/history`, and HAR
  `content.encoding` for `/proxy/har-export` (#7).
- [x] Accept `headers` as a JSON object or `[name, value]` array (in addition to
  the legacy CRLF string) on `/proxy/send` and `/scanner/scan-request` via the
  shared `HeaderInput` parser; object form no longer 500s, duplicates last-wins
  (#8).
- [x] Stop losing captured evidence (#20): parse the stored
  `[Name: Value, …]` header blob token-aware in `HeaderList` — which also
  repairs rows already in the database — and route HAR export, curl export, and
  response comparison through that one parser; store headers and bodies
  verbatim via `StoredText.content` instead of deleting control characters, and
  surface `body_truncated`/`response_body_truncated` plus
  `max_stored_content_chars` rather than writing `"..."` into a body. Raw
  `BLOB` columns and `GET /proxy/history/{id}/raw` deferred.
- [x] Add structured `headers_list`/`response_headers_list` (ordered
  `{name, value}` arrays, duplicates preserved) alongside the flattened `headers`
  string via the shared `HeaderList` util: exact on `/proxy/send` (live Montoya
  list), best-effort parse on `/proxy/search`, `/proxy/history`,
  `/proxy/search/download`. Optional `?fields=`/`?extract=title`/`headers_map`
  selectors deferred (#9).
