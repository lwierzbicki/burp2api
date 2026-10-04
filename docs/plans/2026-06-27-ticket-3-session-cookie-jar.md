# Session-Scoped Cookie Jar for /proxy/send Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** Give `/proxy/send` (and `/proxy/replay`) an opt-in, `session_tag`-keyed
cookie jar that carries and rotates cookies across calls and across followed
redirects, so stateful flows (e.g. OIDC / Clerk logins with ~60s rotating
`__session` tokens) can be driven through the API.

**Source:** GitHub issue [#3](https://github.com/lwierzbicki/pentest-tools/issues/3)
— "burp2api: session-scoped /proxy/send with persistent cookie jar".

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace). Developer + QA per `../AGENTS.md` roster.

**Architecture:**
- New pure util `com.burp2api.utils.SessionCookieJar` holds all jar state and
  cookie logic — fully offline unit-testable, mirroring `CookieReconstructor`.
  RouteHandler owns one instance.
- Parsing reuses `CookieReconstructor.parseSetCookieHeaders` /
  `parseRequestCookieHeader` / `SetCookieAttrs`. Do not duplicate header
  parsing.
- `RouteHandler` send/replay handlers and the new `/session/cookies` endpoints
  stay thin: they marshal HTTP <-> jar and contain no cookie matching logic.
- Jar is **process-local in-memory** state. No new persistence; no cookies
  written to the DB beyond traffic already stored. Keyed by `session_tag`.
- **Last-write-wins** per `(name, domain, path)`: every `Set-Cookie` (including
  mid-redirect-chain) overwrites the prior value; deletion markers remove it.

**Non-goals:**
- No `Expires`/`Max-Age` TTL-based eviction. Only explicit deletion markers
  (`Max-Age=0` or empty value, as `CookieReconstructor` already detects) remove
  a cookie. Rotation — the Clerk driver — is value replacement, not expiry, so
  this is sufficient. Document the limitation.
- No use of Burp's global `api.http().cookieJar()` for the per-session jar
  (Montoya `sendRequest` does not apply it and it cannot be enumerated). Leave
  `/auth/cookies` untouched except as a seed source.
- Cookie continuity stays **off by default**; absent `cookie_jar` = today's
  byte-for-byte stateless behavior.
- No cross-`session_tag` sharing; no disk durability across extension restarts.

## Touch Points

- Create: `src/main/java/com/burp2api/utils/SessionCookieJar.java` — per-tag
  cookie store; apply/merge, update, reset, snapshot, seed.
- Create: `src/test/java/com/burp2api/utils/SessionCookieJarTest.java` — offline
  unit tests for all jar behavior.
- Modify: `src/main/java/com/burp2api/handlers/RouteHandler.java` —
  `/proxy/send` and `/proxy/replay` jar wiring + `follow_redirects`; instantiate
  the jar; register `GET`/`DELETE /session/cookies` and seed-from-host.
- Modify: `docs/openapi.json` — document `cookie_jar`, `follow_redirects`,
  `max_redirects` on `/proxy/send`; add `/session/cookies` paths.
- Docs: `README.md`, `TODO.md` — feature note + example; mark ticket #3 work.
- Test: `tests/test_repository_contract.py` — unchanged code, but must stay
  green after openapi edits (validates required paths + snapshot version).

## Behavioral Contract (resolved decisions)

- **Activation field** (`/proxy/send`, `/proxy/replay` body): `cookie_jar` ∈
  `{"use","reset","off"}`. Absent or `"off"` → stateless. `"use"` → apply jar
  to outgoing `Cookie`, then update jar from response `Set-Cookie`. `"reset"` →
  clear this `session_tag`'s jar first, then behave as `"use"`.
- **Jar key:** the request's effective `session_tag` (existing field /
  `config.getSessionTag()` default).
- **Caller precedence:** a `Cookie` name supplied in the caller's `headers`
  wins over the jar's value for that name; jar contributes the remaining names.
- **Domain match:** stored cookie applies to request host `h` when host-only and
  `h` equals the cookie domain (case-insensitive), or when domain-scoped and `h`
  equals or is a subdomain of the cookie domain. Default domain = request host
  (host-only) when `Set-Cookie` omits `Domain`.
- **Path match:** request path equals the cookie path or has it as a prefix
  boundary (`/a` matches `/a`, `/a/b`; not `/ab`). Default path `/`.
- **Secure:** cookies marked `Secure` are only sent over `https` URLs.
- **Redirects:** `follow_redirects` (bool, default `false`) + `max_redirects`
  (int, default `5`, hard cap `10`). On 3xx with `Location`, resolve against the
  current URL and re-issue; jar is updated and re-applied each hop. 303 → GET
  with empty body; 301/302/307/308 preserve method/body per usual rules. The
  final response is returned; each hop is stored to the DB under the session tag.
- **Management:** `GET /session/cookies?session_tag=…` returns the jar snapshot;
  `DELETE /session/cookies?session_tag=…` resets it; `POST /session/cookies`
  with `{session_tag, seed_host}` primes the jar from reconstructed proxy
  traffic for `seed_host` (reusing the `handleLiveCookiesForHost` path).

## Canonical Commands

- Targeted Java unit test: `mvn -q -Dtest=SessionCookieJarTest test`
- Full Java gate (compile + all tests + shade): `mvn clean package`
- Offline contract test: `python -m unittest tests.test_repository_contract -v`

## Tasks

### Task 1: SessionCookieJar — update, last-write-wins, deletion

**Owner:** burp2api / Developer
**Files:** `src/main/java/com/burp2api/utils/SessionCookieJar.java`,
`src/test/java/com/burp2api/utils/SessionCookieJarTest.java`
**Acceptance:** Feeding response header blocks updates a per-tag store; a later
`Set-Cookie` for the same name+domain+path replaces the earlier value; a
deletion marker removes it; tags are isolated.

- [ ] Add failing `SessionCookieJarTest` covering: store a cookie from
      `Set-Cookie`; a second update with a new value (rotation) replaces it;
      `Max-Age=0`/empty value removes it; cookies under tag `A` are invisible
      under tag `B`.
- [ ] Run `mvn -q -Dtest=SessionCookieJarTest test`; expect compile/test failure
      (class absent).
- [ ] Implement `SessionCookieJar` with an internal
      `Map<String /*tag*/, Map<CookieKey, StoredCookie>>`, a `StoredCookie`
      record (name, value, domain, path, secure, httpOnly, hostOnly), and
      `void update(String sessionTag, String requestHost, String responseHeaders)`
      delegating to `CookieReconstructor.parseSetCookieHeaders`. Last-write-wins
      keyed by `(name, domain, path)`; `attrs.deleted` removes the key.
- [ ] Re-run the target; expect pass.
- [ ] Refactor (extract `CookieKey`, helpers) while green; re-run.

### Task 2: SessionCookieJar — apply/merge with domain, path, secure, caller precedence

**Owner:** burp2api / Developer
**Files:** same as Task 1
**Acceptance:** `buildCookieHeader` returns the correctly scoped, merged
`Cookie` header for a request; caller cookies override jar cookies; non-matching
domain/path/secure cookies are excluded; result is deterministic.

- [ ] Add failing tests: host-only cookie sent only to exact host, not
      subdomain; domain cookie sent to subdomain; path prefix honored
      (`/app` cookie not sent to `/`); `Secure` cookie omitted on `http`;
      caller-supplied `Cookie: x=override` beats jar `x=stored`; empty jar +
      caller cookie returns caller value unchanged.
- [ ] Run `mvn -q -Dtest=SessionCookieJarTest test`; expect failure.
- [ ] Implement
      `String buildCookieHeader(String sessionTag, String host, String path,
      boolean https, String callerCookieHeader)`: parse caller cookies via
      `CookieReconstructor.parseRequestCookieHeader`, select matching stored
      cookies (domain/path/secure rules from the contract), merge with caller
      names winning, emit `name=value; …` in stable order.
- [ ] Re-run the target; expect pass.
- [ ] Add `reset(tag)`, `List<StoredCookie> snapshot(tag)`, and
      `int seed(String tag, List<CookieReconstructor.Cookie> cookies)`; cover
      reset clears and snapshot reflects inserts; re-run green.

### Task 3: Wire jar into /proxy/send (`cookie_jar` use|reset|off)

**Owner:** burp2api / Developer
**Files:** `src/main/java/com/burp2api/handlers/RouteHandler.java`
**Acceptance:** With `cookie_jar:"use"`, a send applies the tag's jar to the
outgoing `Cookie` header and ingests `Set-Cookie`; a subsequent send under the
same tag carries the cookie. Absent/`"off"` leaves the request unchanged.
RouteHandler is not offline-unit-tested (Burp dependency); verify by compile +
the manual smoke below.

- [ ] Instantiate one `SessionCookieJar` field on `RouteHandler`.
- [ ] In `/proxy/send` (around `RouteHandler.java:1055`): read `cookie_jar`
      mode; on `"reset"` call `jar.reset(tag)`; on `"use"`/`"reset"` derive
      host/path/https from `url`, set the merged header via
      `httpRequest.withUpdatedHeader("Cookie", jar.buildCookieHeader(...))`
      (only when non-empty), send, then `jar.update(tag, host,
      response.headers().toString())`. Apply jar before existing intercept-rule
      application so rules see final headers. Include the active `cookie_jar`
      mode in the JSON response for observability.
- [ ] Run `mvn clean package`; expect compile + existing tests pass.
- [ ] Smoke (manual, documented in PR/commit, not committed as a test):
      two `cookie_jar:"use"` sends to a local server that sets then echoes a
      cookie show the second request carrying it; `"off"` does not.

### Task 4: Redirect following in /proxy/send

**Owner:** burp2api / Developer
**Files:** `src/main/java/com/burp2api/handlers/RouteHandler.java`
**Acceptance:** With `follow_redirects:true`, a 3xx+`Location` response is
followed up to `max_redirects`, the jar is updated and re-applied each hop, and
the final (non-3xx or cap-reached) response is returned with a hop trail.

- [ ] Factor the single send into a loop: resolve `Location` against the current
      URL, enforce `max_redirects` (default 5, cap 10), apply 303→GET and
      302/301 method rules, re-apply/update the jar per hop when `cookie_jar`
      active, store each hop under the session tag.
- [ ] Add a `redirects` array (status, location, request_id per hop) to the
      response; preserve existing single-response fields for the final hop so
      non-redirect callers see no shape change.
- [ ] Run `mvn clean package`; expect pass.
- [ ] Smoke: a login-style 302 chain that rotates a cookie mid-chain ends on
      200 carrying the rotated cookie value (Clerk-style last-write-wins).

### Task 5: /proxy/replay jar participation + management endpoints

**Owner:** burp2api / Developer
**Files:** `src/main/java/com/burp2api/handlers/RouteHandler.java`
**Acceptance:** `/proxy/replay` honors the same `cookie_jar` mode per request;
`GET`/`DELETE /session/cookies` and `POST /session/cookies` seed work against
the tag's jar.

- [ ] Apply the same jar apply/update around the `httpService.sendRequest` in
      `/proxy/replay` (`RouteHandler.java:451`), gated on `cookie_jar` mode.
- [ ] Register `GET /session/cookies?session_tag=…` → `jar.snapshot(tag)` as
      JSON (name/value/domain/path/secure/http_only); `DELETE
      /session/cookies?session_tag=…` → `jar.reset(tag)` + count cleared;
      `POST /session/cookies` `{session_tag, seed_host}` → reconstruct via the
      existing `handleLiveCookiesForHost` logic and `jar.seed(...)`, returning
      seeded count. Default `session_tag` to `config.getSessionTag()`.
- [ ] Run `mvn clean package`; expect pass.
- [ ] Smoke: seed from a browsed host, `GET` shows the cookies, a `cookie_jar`
      send carries them, `DELETE` empties the jar.

### Task 6: Documentation + OpenAPI

**Owner:** burp2api / Docs
**Files:** `docs/openapi.json`, `README.md`, `TODO.md`
**Acceptance:** Docs match implemented behavior and the offline contract test
passes. `/proxy/send` advertises `cookie_jar`, `follow_redirects`,
`max_redirects`; `/session/cookies` paths are present.

- [ ] Update `/proxy/send` description in `docs/openapi.json` and the inline
      catalog string at `RouteHandler.java:2942` to list the new optional
      fields; add `/session/cookies` (GET/DELETE/POST) entries.
- [ ] Add a README section: session-scoped jar, `cookie_jar` modes, redirect
      options, Clerk/rotating-session note, and the no-TTL-eviction limitation;
      include a short OIDC-style example sequence.
- [ ] Note ticket #3 completion in `TODO.md`.
- [ ] Run `python -m unittest tests.test_repository_contract -v`; expect pass
      (required paths intact, snapshot version unchanged unless intentionally
      bumped — keep `1.0.1` unless the contract test is updated in lockstep).

## Final Verification

- [ ] Run `mvn clean package` — full compile, unit tests, shaded jar.
- [ ] Run `mvn -q -Dtest=SessionCookieJarTest test` — jar unit suite green.
- [ ] Run `python -m unittest tests.test_repository_contract -v` — contract green.
- [ ] Manual smoke against a local server (Tasks 3–5) demonstrating: cookie
      carry across two sends sharing a tag (acceptance #1); redirect-following
      option exercised (acceptance #2); a rotating cookie reflects the freshest
      value; `cookie_jar:"off"` unchanged from current behavior.

## Risks & Notes

- **RouteHandler is not offline-unit-testable** (hard Burp `api` dependency and
  no existing harness). TDD evidence concentrates in `SessionCookieJarTest`;
  handler wiring is verified by compile + manual smoke. Keep all logic in the
  jar to maximize covered surface.
- **No TTL eviction** is a deliberate scope cut; rotating sessions rely on
  last-write-wins, not expiry. Stale non-rotating cookies persist until `reset`
  or extension restart — documented.
- **Sensitive material:** the jar holds live auth cookies in memory only. Never
  log cookie values, never persist them to the DB or fixtures, never echo them
  outside the explicit `GET /session/cookies` response (per repo policy).
- **Response-shape compatibility:** redirect `redirects` array and `cookie_jar`
  echo are additive; existing fields preserved so current callers are
  unaffected.
- **Rollback:** revert the RouteHandler wiring and delete `SessionCookieJar` +
  its test + openapi/README edits; no migrations or persisted state to undo.

## Handoff

Execute with the `executing-plans` skill, task by task in order, honoring TDD
red/green per task. Tasks 1–2 carry the unit-test evidence; Tasks 3–5 are
compile-plus-smoke; Task 6 is docs gated by the python contract test.
