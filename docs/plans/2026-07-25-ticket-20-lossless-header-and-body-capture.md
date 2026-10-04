# Lossless Header and Body Capture Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** A stored traffic row round-trips headers and body without loss, and
every reader parses that row the same correct way.

**Source:** GitHub issue
[#20](https://github.com/lwierzbicki/pentest-tools/issues/20) — "burp2api:
`/proxy/search` stores multi-value headers comma-split and truncates response
bodies". Engagement-side `evidence.py` currently repairs comma-split headers
best-effort and exits non-zero rather than render a wrong frame; that workaround
should become unnecessary.

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace). Sequence per `../AGENTS.md` bug-fix path: QA regression test →
Developer → QA → Docs.

**Architecture:** The two reported defects are not the same kind of bug and do
not get the same kind of fix.

- *Headers are a read-side parsing bug.* Nothing is destroyed at write time —
  the stored blob still contains every byte. One shared, token-aware parser
  fixes every consumer and repairs **rows already in the database**.
- *Bodies are a write-side data-destruction bug.* `sanitizeString` deletes
  bytes before the INSERT, so no reader can recover them. The fix is to stop
  editing captured content, and to make any size limit visible instead of
  silent.

Neither needs a schema migration, a new column, or a new endpoint.

**Non-goals (deferred, see "Deferred work" below):** raw `BLOB` columns,
`GET /proxy/history/{id}/raw`, and changing what the writers serialize. The
ticket lists the raw endpoint as *"Optionally expose…"*; the acceptance
criteria are met without it.

## Background: confirmed root causes

Recorded so the executing agent does not re-derive them.

### Headers — stored intact, parsed wrongly

Every capture path serializes with `message.headers().toString()` on a
`List<HttpHeader>`, i.e. `AbstractCollection.toString()`:

```
[Expires: Fri, 24 Jul 2026 08:19:53 GMT, Cache-Control: private, max-age=0]
```

Bracket-wrapped and `", "`-joined — but **every byte is present**. The loss
happens in `utils/HeaderList.java:53`, which finds no `\n`, falls back to
`split(", ")`, and shreds the values; fragments with no colon (`max-age=0`) are
then discarded at `:57`. Simulated against the response in the ticket, this
reproduces the reported output exactly.

Three other readers share the assumption and the bug, all fed from stored rows:

| Reader | Site | Route |
|---|---|---|
| `RouteHandler.parseHeadersForHar` | `:4439`, called `:4345,4374` | `/proxy/har-export` |
| `CurlGenerator` header split | `utils/CurlGenerator.java:115`, fed at `RouteHandler:4971` | `/proxy/request/{id}/curl` |
| `ResponseAnalysisService.parseHeaders` | `services/ResponseAnalysisService.java:277` | response comparison (`RouteHandler:3739,3776`) |

`parseHeadersForHar` splits on `\n` only, so the whole blob is one line and HAR
export emits a single bogus header (`[Expires`) per record — worse than the
ticket reports.

Ambiguity is bounded in practice: a continuation fragment either has no colon
at all, or its pre-colon text is not a valid RFC 9110 token (`24 Jul 2026 08`
contains spaces). A token-aware re-join recovers real-world traffic. It cannot
be perfect in principle, which is why the writer change is worth doing later —
but the parser is needed either way, because legacy rows keep this format
forever.

### Bodies — bytes deleted at INSERT

`DatabaseService.sanitizeString:717` runs on every column:

```java
input.replaceAll("[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F]", "")
```

Burp's `bodyToString()` maps one raw byte to one latin-1 char, so for binary
content this *deletes* bytes — ~11.7% of uniform random data, far more for
compressed data. The reported 2048 → ~1674 is deletion, not the 65536 cap.
`\r` (0x0D) is not in the set, so CRLF is unaffected. Above 65536 chars, `:726`
truncates and writes `"..."` **into the body itself**, so the corruption is
indistinguishable from captured content.

The strip has no recorded rationale — it arrived with the initial import
(`31585ad`) and is applied indiscriminately to every column. It is not needed
for storage integrity. Measured against the pinned driver
(`org.xerial:sqlite-jdbc:3.44.1.0`), writing all 256 byte values as a latin-1
string into a `TEXT` column:

```
TEXT  setString/getString : 256 chars, equal=true     <- exact, NUL included
BLOB  setBytes/getBytes   : 256 bytes, equal=true
SQL   length(body)        : 0                         <- SQL string funcs stop at NUL
```

Whatever JSON-validity concern it may have guarded was solved correctly
downstream by `BodyCodec` in #7 (escape or Base64 at the read layer with an
explicit `*_encoding` discriminator), so the strip is now redundant with a
working solution.

The one real consequence of keeping bytes is that third line: an embedded NUL
truncates SQLite's *SQL-level* string functions, so `LIKE`/`length()` over a
body stop at the first NUL. That is a strict improvement over today, where
those bytes do not exist at all and the search is silently wrong — but it must
be documented rather than discovered.

## Design decisions

- **One parser, four call sites.** `HeaderList.fromStoredString` becomes the
  only place a stored header blob is parsed. `parseHeadersForHar` is deleted and
  its callers map `HeaderList` output into the HAR shape; `CurlGenerator` and
  `ResponseAnalysisService` take a parsed list.
- **Bodies stay `TEXT`.** The latin-1 round-trip is proven exact above, so
  `BLOB` would buy nothing here while forcing every `rs.getString("body")` read
  site to change. `BLOB` belongs with the deferred raw columns, if ever.
- **Sanitization splits by column kind.** `scalar()` keeps today's behavior for
  `method`, `url`, `host`, `session_tag`, `*_http_version` — harmless hygiene on
  short fields. `content()` never removes a character.
- **Size limits become visible, not silent.** `content()` never writes a marker
  into the data. It logs a WARN, and the record carries `body_truncated` /
  `response_body_truncated` plus the cap that applied.
- **No schema migration.** The truncation flags are derived at read time by
  comparing the stored length to the configured cap, so nothing is added to the
  schema.

## Touch Points

- Create: `src/main/java/com/burp2api/utils/StoredText.java` — `scalar()` /
  `content()`, extracted pure so it is testable without a database.
- Create: `src/test/java/com/burp2api/utils/StoredTextTest.java`.
- Create: `src/test/java/com/burp2api/utils/CurlGeneratorTest.java`.
- Modify: `src/main/java/com/burp2api/utils/HeaderList.java` — gate the comma
  fallback on a legacy bracket blob; token-aware re-join of shredded fragments.
- Modify: `src/test/java/com/burp2api/utils/HeaderListTest.java`.
- Modify: `src/main/java/com/burp2api/handlers/RouteHandler.java` — delete
  `parseHeadersForHar:4439`, route `:4345,4374` and `:4971` through
  `HeaderList`; add truncation flags in `annotateRecords:4265`.
- Modify: `src/main/java/com/burp2api/utils/CurlGenerator.java` — accept parsed
  headers instead of re-splitting.
- Modify: `src/main/java/com/burp2api/services/ResponseAnalysisService.java` —
  drop `parseHeaders:277` in favour of `HeaderList`.
- Modify: `src/main/java/com/burp2api/database/DatabaseService.java` —
  `sanitizeString` delegates to `StoredText`; content columns use `content()`.
- Modify: `src/main/java/com/burp2api/config/ApiConfig.java` —
  `BURP2API_MAX_STORED_CONTENT_CHARS`.
- Docs: `README.md`, `TODO.md`, `docs/openapi.json`.

Canonical commands: `mvn -o -B test` (targeted with `-Dtest=<Class>`),
`mvn -o -B clean package` (full gate),
`python -m unittest tests.test_repository_contract -v` (route/doc contract).
Baseline before this plan: 89 tests, 0 failures.

## Tasks

### Task 1: Token-aware stored-header parser

**Owner:** QA writes the test, Developer implements (utils).
**Files:** `src/main/java/com/burp2api/utils/HeaderList.java`,
`src/test/java/com/burp2api/utils/HeaderListTest.java`
**Acceptance:** The blob from the ticket parses to intact headers, and rows
already in the database are repaired without being rewritten.

- [ ] Add failing cases to `HeaderListTest`:
      - the exact ticket blob `[Expires: Fri, 24 Jul 2026 08:19:53 GMT,
        Cache-Control: private, max-age=0]` → two entries, values intact,
        nothing dropped;
      - `[Set-Cookie: a=1; Expires=Fri, 24 Jul 2026 08:19:53 GMT,
        Set-Cookie: b=2]` → two entries (a colon inside the continuation must
        not create a header);
      - a bare `Content-Type: text/plain, charset=utf-8` with no brackets → one
        entry, unsplit;
      - a newline blob → parsed exactly, unchanged from today;
      - null / blank / unparseable → empty list, unchanged from today.
- [ ] Run `mvn -o -B test -Dtest=HeaderListTest`; expect failures on the first
      three.
- [ ] Implement: apply the `", "` split **only** when the blob was
      bracket-wrapped; when splitting, append a fragment to the previous value
      unless its pre-colon text is a valid RFC 9110 token.
- [ ] Re-run `mvn -o -B test -Dtest=HeaderListTest`; expect pass.
- [ ] Correct the class javadoc, which currently calls newline "the canonical
      stored form" — no writer has ever produced it.

### Task 2: Route every stored-header reader through that parser

**Owner:** Developer (handlers, utils, services).
**Files:** `src/main/java/com/burp2api/handlers/RouteHandler.java`,
`src/main/java/com/burp2api/utils/CurlGenerator.java`,
`src/test/java/com/burp2api/utils/CurlGeneratorTest.java`,
`src/main/java/com/burp2api/services/ResponseAnalysisService.java`
**Acceptance:** HAR export, curl export, and response comparison show the same
correct headers as `/proxy/search`; no second header parser remains.

- [ ] Add a failing `CurlGeneratorTest`: a stored bracket blob produces one
      `-H` per header with intact comma values, and still skips `Host:`.
- [ ] Run `mvn -o -B test -Dtest=CurlGeneratorTest`; expect failure.
- [ ] Delete `RouteHandler.parseHeadersForHar` and map
      `HeaderList.fromStoredString` output into the HAR `{name, value}` shape at
      `:4345` and `:4374`.
- [ ] Change `CurlGenerator.RequestData` to carry parsed headers, parsed by the
      caller at `RouteHandler:4971` (only caller, verified by grep).
- [ ] Replace `ResponseAnalysisService.parseHeaders` with `HeaderList`.
- [ ] Review remaining `split("\\r?\\n")` / `split("\n")` uses in `src/main` and
      confirm the two synthetic pseudo-header loops at `RouteHandler:2879,3164`
      (`Cookie-Name:` / `Token-Format:`) are out of scope — they parse
      internally generated strings, not captured headers.
- [ ] Re-run `mvn -o -B test`; expect pass.

### Task 3: Stop deleting bytes from captured content

**Owner:** Developer (database + utils).
**Files:** `src/main/java/com/burp2api/utils/StoredText.java`,
`src/test/java/com/burp2api/utils/StoredTextTest.java`,
`src/main/java/com/burp2api/database/DatabaseService.java`,
`src/main/java/com/burp2api/config/ApiConfig.java`
**Acceptance:** A 2048-char latin-1 string of arbitrary bytes survives storage
at full length; scalar columns keep today's hygiene.

- [ ] Add failing `StoredTextTest`: `content()` preserves every char in
      `U+0000`–`U+00FF` and returns the same length; `content()` above the cap
      truncates to exactly the cap and appends nothing; `scalar()` strips
      control characters and truncates with `"..."` as today; null → `""`.
- [ ] Run `mvn -o -B test -Dtest=StoredTextTest`; expect compilation failure.
- [ ] Implement `StoredText.scalar(String, int)` (moved verbatim from
      `DatabaseService.sanitizeString`) and `StoredText.content(String, int)`.
- [ ] Add `ApiConfig.getMaxStoredContentChars()` reading
      `BURP2API_MAX_STORED_CONTENT_CHARS`, default `10485760`.
- [ ] Point `DatabaseService.sanitizeString` at `StoredText.scalar`, and switch
      every headers/body bind to `StoredText.content` with the configured cap:
      `:565` `:604-605` `:632-633` `:659-660` `:694-698` `:1716-1719`
      `:1793-1796` `:1874-1877`, plus `insertTrafficRequest` /
      `insertTrafficResponse`. Scalar columns keep `scalar`.
- [ ] Re-run `mvn -o -B test -Dtest=StoredTextTest` then `mvn -o -B test`;
      expect pass.

### Task 4: Make truncation visible instead of silent

**Owner:** Developer (handlers).
**Files:** `src/main/java/com/burp2api/handlers/RouteHandler.java`,
`docs/openapi.json`
**Acceptance:** A client can tell a complete body from a capped one without
inspecting the content.

- [ ] Extend `annotateRecords:4265` to emit `body_truncated` /
      `response_body_truncated` (boolean) and `max_stored_content_chars`
      alongside the existing `*_encoding` fields, derived by comparing the
      stored length to the configured cap.
- [ ] Log a WARN in `StoredText.content` when it trims, naming the column and
      both lengths.
- [ ] Add the fields to the `/proxy/search` result item schema in
      `docs/openapi.json`.
- [ ] Run `python -m unittest tests.test_repository_contract -v`; expect pass.

### Task 5: Documentation

**Owner:** Docs Writer.
**Files:** `README.md`, `TODO.md`, `docs/openapi.json`
**Acceptance:** No doc claims behavior the code does not have.

- [ ] Correct `README.md:275-284`: the "comma-containing values … are never
      split" guarantee is true for `/proxy/send` and, after this change, for
      DB-backed readers; rows captured before it are repaired best-effort and a
      comma inside a value can still be ambiguous in principle.
- [ ] Document `BURP2API_MAX_STORED_CONTENT_CHARS` and the `*_truncated` fields
      in the environment and body-encoding sections.
- [ ] Note in the persistence section that captured bodies are stored verbatim,
      and that `LIKE`-based body search stops at an embedded NUL byte because
      SQLite's string functions do.
- [ ] Add the `#20` entry to `TODO.md` in the style of the `#7`/`#9` entries.

## Final Verification

- [ ] `mvn -o -B clean package` — expect BUILD SUCCESS, no regression against
      the 89-test baseline.
- [ ] `python -m unittest tests.test_repository_contract -v`.
- [ ] Live acceptance in Burp (offline tests cannot cover this; the ticket's
      criterion is about real traffic). Load the rebuilt JAR against a
      **scratch** Burp project, proxy one response with a comma-valued header
      and one binary/compressed body, then confirm:
      - `GET /proxy/search` — `response_headers_list` shows `Cache-Control` and
        `Expires` intact, no fragment entries;
      - the decoded `response_body` length equals `Content-Length`;
      - `GET /proxy/har-export` and `GET /proxy/request/{id}/curl` show
        individually parsed headers, not one `[Expires` entry.
      Also re-read a **pre-existing** row and confirm its headers now parse
      correctly without having been rewritten.
      Do not run this against an engagement database; do not commit captured
      output.
- [ ] Confirm the engagement-side `evidence.py` header-repair workaround can be
      retired, and say so on #20 when closing.

## Deferred work

Not required for #20's acceptance criteria; raise separately if wanted.

- **Write a newline-separated header block.** Replacing the 10
  `headers().toString()` sites (`DatabaseService:564,604,632,659,694,697,
  3062,3072`, `AllToolsLogger:232,237`, `RepeaterLogger:162,166`) makes the
  stored format unambiguous for future rows. It does nothing for existing rows,
  and the Task 1 parser is needed either way, so it is robustness rather than a
  fix. It would also shift `generateContentHash:1437`, so rows captured before
  and after would stop deduping against each other.
- **Raw `BLOB` columns + `GET /proxy/history/{id}/raw`.** The ticket's own
  optional item. Beyond robustness, the only thing it adds is the response
  reason phrase, which is not stored today — a rebuilt status line currently
  needs `RouteHandler.getStatusText`. Cost: a schema migration on live
  engagement databases and roughly double per-row storage in a store that never
  prunes.

## Risks

- **Legacy rows stay best-effort.** Task 1 recovers real-world traffic, but a
  comma inside a value is genuinely ambiguous once serialized this way. Evidence
  cited from a pre-fix row should ideally be recaptured.
- **`LIKE` and `length()` on bodies containing NUL** stop at the first NUL once
  bytes are preserved. Strictly better than today (those bytes are absent
  entirely), but it changes observed search behavior and must be documented.
- **`CurlGenerator.RequestData` signature change** is public within the tool;
  `RouteHandler:4971` is the only caller, verified by grep.
