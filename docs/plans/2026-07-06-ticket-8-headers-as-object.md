# Accept `headers` as a JSON Object Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** `headers` accepts a JSON object (name→value) and an array of
`[name, value]` pairs in addition to the existing CRLF string, on every endpoint
that takes request headers. The object form no longer returns HTTP 500.

**Source:** GitHub issue [#8](https://github.com/lwierzbicki/pentest-tools/issues/8)
— "burp2api: accept `headers` as a JSON object on /proxy/send and
/scanner/scan-request". Sibling of #7 from the Prosus engagement.

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace).

## Root cause

Both handlers blind-cast the deserialized value:
`String headers = (String) requestData.getOrDefault("headers", "")`. A JSON
object deserializes to `LinkedHashMap`, so the cast throws
`ClassCastException` → HTTP 500. `/scanner/scan-request` additionally never
applied the parsed headers to the scanned request (it only concatenated the raw
string into the stored DB record).

## Approach

- New shared util `com.burp2api.utils.HeaderInput`:
  - `parse(Object)` → ordered `List<Header>`, type-branching over:
    - `Map` (JSON object, insertion order, no duplicate names possible),
    - `List` of `[name, value]` pairs (escape hatch for ordering / repeats),
    - `String` (legacy CRLF; split on line break then first colon).
    Blank names are skipped; non-string values are coerced with `String.valueOf`.
  - `applyTo(HttpRequest, List<Header>)` → last-wins per name
    (`withUpdatedHeader` if present, else `withAddedHeader`), matching how the
    send path has always overridden auto-generated headers (`Host`, etc.).
  - `toBlock(List<Header>)` → canonical CRLF `"Name: Value"` block stored with
    captured traffic.

- Wire into both handlers:
  - `RouteHandler` `/proxy/send`: parse → `applyTo` the outbound request →
    `toBlock` for the stored `headers` string (downstream storage / redirect
    logic unchanged).
  - `ScannerRouteRegistrar` `/scanner/scan-request`: parse → `applyTo` the
    scanned request (fixes the latent drop) → `toBlock` for the stored record.

## Non-goals

- Duplicate header names collapse last-wins (JSON objects cannot express
  duplicates anyway); the array form preserves caller order but still applies
  last-wins on repeated names. True multi-value emission is out of scope.
- `/proxy/replay` takes its headers from stored DB records (already strings),
  not from a request-body `headers` field, so it is unaffected.

## Tests

`HeaderInputTest` (JUnit 5 + AssertJ + Mockito, offline): object form (order),
CRLF string (first-colon split, `Host: host:port`), array-of-pairs, non-string
value coercion, blank-name skip, empty/`null`/empty-object → no headers,
`toBlock` round-trip, and `applyTo` add-vs-update last-wins via a mocked
`HttpRequest` (Montoya requests cannot be built offline).

## Docs

- README: new "Sending requests and header formats" section documenting the
  three shapes, last-wins, and an object-form example.
- `docs/openapi.json`: `/proxy/send` and `/scanner/scan-request` gain a
  `requestBody` schema with `headers` as `oneOf` (object | array-of-pairs |
  string); descriptions/summaries updated.
