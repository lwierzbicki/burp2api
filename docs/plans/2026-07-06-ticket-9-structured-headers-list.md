# Structured `headers_list` on Responses Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** Clients can read individual response/request headers structurally
without re-parsing the flattened `headers` blob, while existing string consumers
keep working.

**Source:** GitHub issue [#9](https://github.com/lwierzbicki/pentest-tools/issues/9)
— "burp2api: structured `headers_list` on responses". Nice-to-have from the
Prosus engagement; siblings #7 and #8.

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace).

## Approach

- New shared util `com.burp2api.utils.HeaderList`:
  - `fromMontoya(List<HttpHeader>)` → ordered `List<{name, value}>`, exact
    (used by the live send path).
  - `fromStoredString(String)` → best-effort parse of a stored header blob:
    strip a surrounding `[...]`, split on newlines (the canonical stored form,
    exact even for comma-containing values), falling back to comma separation
    for a degenerate single-line blob.

- Wire in:
  - `/proxy/send` response block: add `headers_list` from
    `response.response().headers()` (byte-exact). `headers` string unchanged.
  - DB-backed responders — extend the existing record annotator (renamed
    `annotateRecordBodies` → `annotateRecords`) to add `headers_list` and
    `response_headers_list` on `/proxy/search`, `/proxy/history`, and
    `/proxy/search/download` (JSON). Original string fields untouched.

## Non-goals (deferred)

- Optional `?fields=` response trimming, `?extract=title` HTML convenience, and
  a lowercased `headers_map` — the ticket marks these "defer/split if it grows".
- `/proxy/replay` returns only status/length (no headers), and there is no
  non-curl `GET /proxy/request/{id}` responder, so neither is touched. HAR export
  already emits structured headers via `parseHeadersForHar`.

## Tests

`HeaderListTest` (JUnit 5 + AssertJ + Mockito, offline): `fromMontoya` preserves
order, duplicate `Set-Cookie`, and a comma-containing `Date` value as separate
untruncated entries; null/empty; `fromStoredString` exact newline parse, bracket
strip + comma fallback, null/blank/unparseable.

## Docs

- README: `headers_list`/`response_headers_list` in the search schema plus a
  "Reading response headers" section with a `jq` example.
- `docs/openapi.json`: `headers_list` on the `/proxy/send` response and
  `headers_list`/`response_headers_list` on the `/proxy/search` result items.
