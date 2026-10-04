# Byte-Exact Raw Request/Response Capture Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** A request/response captured through burp2api is stored and re-read
byte-identical to what was sent/received, served from the stored row via a new
`GET /proxy/history/{id}/raw` endpoint, so the stored row is a faithful evidence
source without a send-time `.http` side-capture.

**Source:** GitHub issue
[#24](https://github.com/lwierzbicki/pentest-tools/issues/24) — "burp2api:
stored request/response is lossy". Continuation of
[#20](https://github.com/lwierzbicki/pentest-tools/issues/20), whose plan
(`docs/plans/2026-07-25-ticket-20-lossless-header-and-body-capture.md`)
explicitly deferred "raw `BLOB` columns, `GET /proxy/history/{id}/raw`, and
changing what the writers serialize". This plan picks up exactly that deferred
work.

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace). Sequence per `../AGENTS.md` new-feature path:
Architect → QA → Developer → QA → Docs.

**Architecture:** The lossy TEXT columns are *not* repaired — they are demoted.
The heuristic header parser (`HeaderList.fromStoredString`) cannot be exact by
construction (a header value may contain `", "`), and `body`/`response_body`
round-trip through an ISO-8859-1 `bodyToString()` TEXT column with a char cap and
a NUL-truncates-`LIKE` caveat. Rather than keep fighting a projection, capture
the exact wire bytes Montoya already exposes:

- `request.toByteArray().getBytes()` and `response.toByteArray().getBytes()` are
  the exact bytes on the wire. They are already used elsewhere in the codebase
  (`ScannerRouteRegistrar.java:149-150`).
- Store them verbatim in two new `BLOB` columns on `proxy_traffic` — the live
  evidence table that backs `/proxy/history` and `/proxy/search` (the normalized
  `traffic_meta`/`traffic_requests`/`traffic_responses` tables are secondary and
  out of scope here).
- Serve them back through a new endpoint as a **base64 JSON envelope** (lossless;
  the client decodes to recover exact bytes).

The existing `headers`/`body`/`response_headers`/`response_body` TEXT columns and
`headers_list`/`response_headers_list` stay unchanged and become documented
best-effort **search projections**. No existing reader changes, so back-compat
holds.

**Non-goals:**
- Repairing or backfilling raw bytes for rows captured before this change — they
  cannot be recovered and must report "no raw capture" cleanly.
- Reconstructing `headers_list`/`body` *from* raw on read (deferred approach "C").
- Touching the `traffic_meta`/`traffic_requests`/`traffic_responses` id-space
  (#21) — unrelated.
- A raw-bytes (non-JSON) binary download variant — the endpoint returns a JSON
  base64 envelope only.

## Background: confirmed root causes

Recorded so the executing agent does not re-derive them.

1. **Header ambiguity (unfixable read-side).** Every capture path stores
   `List<HttpHeader>.toString()` → `[Name: Value, Name: Value]`
   (`AllToolsLogger.java:232,237`, `RepeaterLogger.java:162,166`,
   `DatabaseService.java:565,610,635,662,697`). `HeaderList.fromStoredString`
   (`HeaderList.java:61`) guesses header boundaries and shreds a value that
   contains `", "` followed by something header-shaped. The README already
   documents this limitation (`README.md:310-318`).
2. **Body cap + encoding.** `StoredText.content` (`StoredText.java:59`) trims at
   `BURP2API_MAX_STORED_CONTENT_CHARS` (default 10 MB, `ApiConfig.java:53`) and
   the body is an ISO-8859-1 TEXT round-trip; SQLite string functions stop at an
   embedded NUL.

Raw `BLOB` capture sidesteps both: bytes are stored as-is and never parsed to be
served as evidence.

## Design decisions (resolved)

- **Storage:** two `BLOB` columns on `proxy_traffic`: `request_raw`,
  `response_raw`. NULL when absent or omitted.
- **Endpoint response:** JSON base64 envelope (see Interfaces).
- **Raw cap:** new independent knob `BURP2API_MAX_RAW_BYTES` /
  `storage.max_raw_bytes`, default `52428800` (50 MB). A message whose raw byte
  length exceeds the cap is stored as NULL with an `_omitted` flag — **never a
  partial raw message** (a truncated evidence artifact is worse than none).
- **Wiring:** capture sites already hold the Montoya objects and call
  `storeRawTrafficWithSource(...)`, which returns the new row id. To avoid
  changing all three overloads and the request/response split, add one dedicated
  `DatabaseService.setRawBytes(long id, byte[] requestRaw, byte[] responseRaw)`
  UPDATE, called by each logger immediately after the store returns `id > 0`.
  The proxy split path (request INSERT, later response UPDATE) calls
  `setRawBytes` with `responseRaw` non-null on the response side and a null
  `requestRaw` (COALESCE keeps the earlier request bytes — see Task 3).

## Touch Points

- Modify: `src/main/java/com/burp2api/database/schema/SchemaManager.java` —
  migration v12 adds `request_raw`/`response_raw` BLOB columns; bump
  `CURRENT_SCHEMA_VERSION` 11 → 12; add case labels/verify entries.
- Modify: `src/main/java/com/burp2api/config/ApiConfig.java` —
  `BURP2API_MAX_RAW_BYTES` / `storage.max_raw_bytes` (default 50 MB) +
  `getMaxRawBytes()`.
- Modify: `src/main/java/com/burp2api/database/DatabaseService.java` — add
  `setRawBytes(long, byte[], byte[])` (COALESCE UPDATE, honoring the cap →
  NULL + omitted); a raw fetch used by the endpoint returning bytes +
  present/omitted state.
- Modify: `src/main/java/com/burp2api/logging/AllToolsLogger.java`,
  `src/main/java/com/burp2api/logging/RepeaterLogger.java`, and the
  `/proxy/send`+`/proxy/replay` store path — extract `toByteArray().getBytes()`
  and call `setRawBytes` after store.
- Modify: `src/main/java/com/burp2api/handlers/RouteHandler.java` — register
  `GET /proxy/history/{id}/raw`; build the base64 envelope; surface
  `max_raw_bytes`.
- Test: `src/test/java/com/burp2api/config/ApiConfigTest.java` (or existing
  config test) — cap default + override.
- Test: `src/test/java/com/burp2api/database/DatabaseServiceRawCaptureTest.java`
  (new) — round-trip, cap-omit, NULL-raw, COALESCE-on-response-update.
- Docs: `README.md` (296-318) — flip guidance: stored row is now byte-exact via
  `/raw`; TEXT columns are best-effort projections.
- Docs: `docs/openapi.json` — new route, envelope schema, `max_raw_bytes`.
- Docs: `TODO.md` — mark the #24 raw-capture item done; note deferred approach C.

## Tasks

### Task 1: Schema migration v12 adds the raw BLOB columns

**Owner:** burp2api / SchemaManager
**Files:** `SchemaManager.java`, `DatabaseServiceIdSpaceTest.java` (or a new
`SchemaManagerRawColumnsTest.java` if the migration is exercised in isolation)
**Acceptance:** A fresh DB and a v11 DB both end at v12 with
`proxy_traffic.request_raw` and `proxy_traffic.response_raw` present as BLOB;
existing rows are untouched (NULL raw).

- [ ] Add a failing test asserting `columnExists(conn, "proxy_traffic",
      "request_raw")` and `"response_raw"` after `initializeSchema`.
- [ ] Run `mvn -q test -Dtest=SchemaManager*Test`; expect failure.
- [ ] Implement `applyMigrationV12_AddRawColumns`: guard each
      `ALTER TABLE proxy_traffic ADD COLUMN … BLOB` with `columnExists`
      (idempotent, matches existing migration style); register in
      `initializeMigrations`; bump `CURRENT_SCHEMA_VERSION` to 12; add the
      description case and any `verifySchemaIntegrity` entry.
- [ ] Re-run the target; expect pass.
- [ ] Refactor while green; re-run.

### Task 2: `BURP2API_MAX_RAW_BYTES` config knob

**Owner:** burp2api / ApiConfig
**Files:** `ApiConfig.java`, config test
**Acceptance:** `getMaxRawBytes()` returns 52428800 by default and honors the
env var / `storage.max_raw_bytes` property, mirroring
`getMaxStoredContentChars()`.

- [ ] Add a failing test for the default and an override.
- [ ] Run `mvn -q test -Dtest=ApiConfigTest`; expect failure.
- [ ] Add `DEFAULT_MAX_RAW_BYTES`, `MAX_RAW_BYTES_KEY`, field, load line, getter.
- [ ] Re-run; expect pass.

### Task 3: `DatabaseService.setRawBytes` + raw fetch, cap-aware

**Owner:** burp2api / DatabaseService
**Files:** `DatabaseService.java`, `DatabaseServiceRawCaptureTest.java` (new)
**Acceptance:** Storing a pair then `setRawBytes` persists both blobs
byte-identical; a message over the cap is stored NULL with the omitted flag; a
response-side `setRawBytes(id, null, respBytes)` sets `response_raw` without
clearing an existing `request_raw` (COALESCE); a row never written with raw
reports not-present.

- [ ] Add failing tests: (a) round-trip a request with a comma-valued header
      (`X-A: v, Retry-After: 5`) and a >cap-threshold binary body containing a
      NUL — assert fetched blobs equal the input byte arrays; (b) length > cap →
      stored NULL + `request_raw_omitted`/`response_raw_omitted` true; (c)
      COALESCE keeps prior request bytes on a response-only update; (d) NULL-raw
      row → present=false, omitted=false.
- [ ] Run `mvn -q test -Dtest=DatabaseServiceRawCaptureTest`; expect failure.
- [ ] Implement `setRawBytes(long id, byte[] requestRaw, byte[] responseRaw)`:
      each side, if bytes `!= null` and `length > getMaxRawBytes()` → set column
      NULL and its `_omitted` sentinel (tracked via a small in-memory/derived
      flag returned by the fetch, since there is no dedicated column — represent
      omission as "id has non-null raw absent although a capture occurred"; to
      keep it explicit, add boolean columns `request_raw_omitted`/
      `response_raw_omitted` in Task 1's migration instead of inferring).
      `UPDATE proxy_traffic SET request_raw = COALESCE(?, request_raw),
      response_raw = COALESCE(?, response_raw), … WHERE id = ?` using
      `setBytes`/`setNull(Types.BLOB)`.
- [ ] Add a fetch method returning `request_raw`/`response_raw` bytes and the
      omitted flags for one id.
- [ ] Re-run; expect pass. Refactor while green.

> Self-review note for the executor: Task 1 must also add
> `request_raw_omitted`/`response_raw_omitted` INTEGER columns (default 0) so
> omission is explicit rather than inferred from a NULL blob (NULL is
> indistinguishable between "pre-v12 row" and "omitted"). Update Task 1's
> acceptance test accordingly.

### Task 4: Loggers capture and store raw bytes

**Owner:** burp2api / logging
**Files:** `AllToolsLogger.java`, `RepeaterLogger.java`, the `/proxy/send`
+`/proxy/replay` store path
**Acceptance:** Every capture path that writes a `proxy_traffic` row also
persists the raw bytes for the sides it has.

- [ ] In `AllToolsLogger.storeTrafficWithSource` (both request+response present),
      after `recordId > 0`, call `databaseService.setRawBytes(recordId,
      actualRequest.toByteArray().getBytes(),
      response.toByteArray().getBytes())`.
- [ ] Mirror in `RepeaterLogger` and the send/replay store path (response-only
      updates pass a null request side).
- [ ] Guard null response (orphaned request) — pass null response bytes.
- [ ] Verify via the Task 3 DB tests plus a logger-level test if a mock
      Montoya request/response is available; otherwise rely on the DB round-trip
      test and manual JAR smoke (Final Verification).

### Task 5: `GET /proxy/history/{id}/raw` endpoint

**Owner:** burp2api / RouteHandler
**Files:** `RouteHandler.java`, endpoint test if the harness supports it
**Acceptance:** For a captured id, returns the base64 envelope decoding
byte-identical to the stored bytes; a pre-v12 / omitted id returns the envelope
with `*_present: false` (and `*_omitted` where applicable) and a `note`, HTTP
200 — never 500, never fabricated data; unknown id → 404.

- [ ] Add a failing test (or contract-level expectation) for the envelope shape.
- [ ] Register the route; fetch via Task 3; build:
      `{ "id", "request_raw_b64", "response_raw_b64", "request_raw_present",
      "response_raw_present", "request_raw_omitted", "response_raw_omitted",
      "max_raw_bytes", "note"? }`. Base64-encode present blobs; null b64 when
      absent.
- [ ] Re-run; expect pass.

### Task 6: Docs

**Owner:** Docs Writer
**Files:** `README.md`, `docs/openapi.json`, `TODO.md`
**Acceptance:** README evidence section states the stored row is byte-exact via
`/proxy/history/{id}/raw` and demotes the TEXT columns / `headers_list` to
best-effort search projections; openapi documents the route + envelope +
`max_raw_bytes`; TODO reflects completion.

- [ ] Rewrite `README.md:296-318` guidance; add a `/raw` usage example (base64
      decode to a file).
- [ ] Add the route and schema to `docs/openapi.json`.
- [ ] Update `TODO.md`.

## Final Verification

- [ ] Run `mvn clean package` (full build + all unit tests, green).
- [ ] Run `python -m unittest tests.test_repository_contract -v` (offline
      contract test).
- [ ] Manual JAR smoke in Burp Suite Professional: capture a response with a
      comma-valued header and a large binary body, call
      `GET /proxy/history/{id}/raw`, base64-decode both fields, and diff against
      the bytes Burp shows in Repeater — expect byte-identical. Confirm an
      over-cap body yields `response_raw_omitted: true` with NULL blob, and a
      pre-migration row yields `response_raw_present: false`.
