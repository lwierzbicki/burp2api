# Active Scan Execution & Observable Status Implementation Plan

> Required skills: `executing-plans`, `test-driven-development`, `run-tests`.

**Goal:** Active scans dispatched through burp2api actually execute to completion
(even on a memory-constrained VM) and expose observable, truthful task state
(`PENDING`/`RUNNING`/`DONE`) with enough progress detail to tell whether audit
traffic has started or whether a task is stuck behind existing work. Resulting
issues remain retrievable via `GET /scanner/issues`.

**Source:** GitHub issue
[#13](https://github.com/lwierzbicki/pentest-tools/issues/13) — "Fix Burp active
scan not running when triggered via burp2api". Observed during Mirae engagement
T-026.

**Owners:** burp2api tool (OpenJDK 21 Maven Burp extension, `com.burp2api`
namespace). Companion config/docs work lives in the sibling `../burp` repo.

**Strategy:** Hybrid, maximum reuse, minimal new code. Reuse Burp's authoritative
scan machinery (built-in REST API for URL/crawl+audit + resource pools + native
status; Montoya for single raw-request audits) instead of rebuilding a task
engine. Delete the fragile custom status plumbing rather than extend it.

## Confirmed root causes (three, not one)

Grounded in the Montoya 2025.8 jar (decompiled), the burp2api source, and prior
live findings recorded in `../burp/NOTES.MD` and
`../burp/config/manual-validation-checklist.md`:

1. **Scope footgun — likely the dominant cause of "no audit traffic" in T-026.**
   With empty `target.scope.include` and
   `project_options.connections.out_of_scope_requests.scope_option = "suite"`,
   `Scanner.startAudit()` + `Audit.addRequest()` (exactly the
   `/scanner/scan-request` path) is silently accepted, appears on the Dashboard,
   and sends **zero payload variations** — no error, no warning. This alone
   explains "only passive scanner issues accumulated," independent of memory.
2. **Frozen fake status.** `ScanTaskManager.registerAudit()` writes a hardcoded
   `"PENDING"` to memory + DB and never updates it; `startTaskMonitoring()` is a
   disabled no-op; `getTaskStatus()` only attaches live progress when
   `status == RUNNING`, which never happens. `GET /scanner/tasks/{id}` therefore
   returns the literal `PENDING` forever, even for a finished audit.
3. **No throttle API in Montoya.** `AuditConfiguration.auditConfiguration(...)`
   accepts only two `BuiltInAuditConfiguration` enums; there is no resource
   pool / concurrency / thread control. An unthrottled audit queued behind a
   large scan starves on a ~160 MiB JVM.

## Verified API facts (Montoya 2025.8 + Burp built-in REST API)

- `ScanTask.delete()` **exists** (via `core.Task`) — real cancel. The current
  "Montoya API doesn't provide direct cancel" comment is wrong.
- Live audit signals: `statusMessage()`, `requestCount()`, `errorCount()`,
  `Audit.insertionPointCount()`, `Audit.issues()`. `requestCount() > 0` is the
  robust "audit traffic started" signal; `statusMessage()` refines terminal
  states and is passed through raw.
- `Audit.addRequest(HttpRequest[, List<Range>])` and `addRequestResponse(...)` —
  faithful single-request audit + insertion-point ranges. The built-in REST API
  cannot do this (it is `urls`-only; "Audit selected items" is desktop-UI-only).
- `BurpSuite.importProjectOptionsFromJson(String)` **exists** — lets burp2api
  apply a resource pool (concurrency + throttle) from
  `../burp/config/project-options.template.json` (1 concurrent / 1000ms)
  **without** the REST API. `exportProjectOptionsAsJson` is already used by
  `/scope/project-config`.
- `Scope.isInScope/includeInScope/excludeFromScope(String)` **exist** — basis of
  the scope preflight.
- Built-in REST API (`http://127.0.0.1:1337`, `/{key}/v0.1/...`, optionally
  keyless on localhost): `POST /scan` accepts `urls`, `scope`,
  `application_logins`, **`scan_configurations` (named/custom — the only
  programmatic lighter-config path)**, **`resource_pool`**; `GET /scan/{id}`
  returns authoritative `scan_status` (`initializing`/`crawling`/`auditing`/
  `paused`/`succeeded`/`failed`) + `scan_metrics` (`crawl_requests_made`,
  `audit_requests_made`, `audit_queue_items_completed`/`_waiting`,
  `audit_network_errors`, `issue_events`, `crawl_and_audit_progress`,
  `total_elapsed_time`) + `issue_events[]`. No cancel endpoint.

## Capability → cheapest existing mechanism

| Need | Mechanism (reuse) |
|---|---|
| Real scan states + metrics (URL scans) | Built-in REST API `GET /scan/{id}` — proxy + normalize |
| Throttle for low memory | Resource pool via `importProjectOptionsFromJson` (Montoya) |
| Lighter/named audit config, tuned checks | Built-in REST API `scan_configurations` (Montoya can't) |
| Audit one exact raw request + ranges | Montoya `audit.addRequest(req[, ranges])` |
| Live status of a Montoya audit | `Audit` pull: `statusMessage/requestCount/errorCount/issues` |
| Real cancel | `ScanTask.delete()` |
| Scope correctness | `api.scope().isInScope/includeInScope` |
| Keyless localhost REST | Burp user-option "Allow access without API key" |

## Approach

### Phase 1 — Correctness (delivers "runs to completion")
- **Scope preflight** in `POST /scanner/scan-request` and `/scanner/scan-url-list`:
  if `!api.scope().isInScope(url)`, by default `includeInScope(url)` and set
  `scoped: true` in the response; add opt-out param `auto_scope=false`, in which
  case an out-of-scope target returns `409` with
  `error: "scan_would_send_zero_payloads"` and a scope hint. Kills the silent
  no-op.
- **Live status pull** for Montoya audits: retain the `Audit` handle in
  `ScanTaskManager`; derive normalized `state` from `requestCount() > 0` +
  `statusMessage()` mapping (`finished/complete`→`DONE`, `cancel`→`CANCELLED`,
  `paused`→`PAUSED`, else `requestCount>0`→`RUNNING`, else `PENDING`). Always
  expose `status_message`, `request_count`, `error_count`, `insertion_points`,
  `issues_found`, `audit_traffic_started`, `elapsed_ms`, and a `stalled`
  heuristic (`PENDING` + elapsed over threshold + 0 requests). All Montoya calls
  guarded. Remove the disabled monitor stub and stop trusting the stored status
  literal (keep the DB row for history only).
- **Real cancel** via `Audit/Crawl.delete()`; rewrite `cancelTask()` and drop
  the incorrect "not supported" comments.

### Phase 2 — Hybrid REST backend (best coverage, minimal new code)
- Small localhost HTTP client to `http://127.0.0.1:1337` (keyless by default).
  `POST /scanner/scan-request` gains `backend: auto|montoya|rest` (default
  `auto`: a single raw request → Montoya; presence of `urls` / crawl+audit /
  `scan_config` / `resource_pool` → REST).
- Normalize REST `scan_status`/`scan_metrics` into the **same**
  `/scanner/tasks/{id}` schema (one caller-facing contract). REST-backed URL
  scans bypass the custom `ScanTaskManager` status machinery entirely.
- Config: `BURP2API_REST_URL` (default `http://127.0.0.1:1337`), optional
  `BURP2API_REST_KEY` (env/settings, **never logged**). Unreachable/disabled →
  `rest_backend: unavailable`, fall back to Montoya and say so.
- Pass through `scan_configurations` (e.g. "Audit checks - fast") and
  `resource_pool` names to `POST /scan`.

### Phase 3 — Throttle helper
- Add `POST /scope/project-config` (import) wrapping
  `importProjectOptionsFromJson`, so the repo's resource-pool template can be
  applied via API (memory mitigation available on the Montoya path too, not only
  via the REST resource pool).

## Non-goals / deferred
- No programmatic per-check selection on the Montoya path (Montoya exposes only
  2 built-in audit configs; finer control requires the REST `scan_configurations`
  path). Document this limitation rather than fake it.
- No cancel for REST-backed scans (the REST API has no cancel endpoint);
  `DELETE /scanner/tasks/{id}` cancels Montoya tasks only. Document.
- No new memory headroom — both APIs share the Burp JVM. The win is capped peak
  concurrency (resource pool) + a lighter config, not more RAM.
- No `application_logins`/authenticated-crawl passthrough in the first cut
  (scope + config + resource pool only); revisit if an engagement needs it.

## Tests (offline, mocked — no live Burp/network)
- JUnit5 + Mockito (already in `pom.xml`):
  - `ScanTaskManagerTest`: scripted mock `Audit` drives `state` PENDING→RUNNING
    →DONE; `stalled` detection; `cancelTask` calls `delete()`; guarded calls
    swallow `UnsupportedOperationException`.
  - Status-message mapping table (strings → normalized state).
  - Scan-request handler: scope-preflight branch (`includeInScope` called /
    `409` on opt-out); backend routing (`auto` picks Montoya vs REST); REST
    `scan_status`/`scan_metrics` → normalized schema (mock HTTP client).
- Python `tests/test_repository_contract.py`: require `/scanner/tasks` and
  `/scanner/tasks/{id}` present.

## Docs
- `README.md` + `docs/openapi.json`: task state machine + fields, `backend`
  selector, scope preflight semantics, cancel semantics, resource-pool import,
  and the honest Montoya-throttle limitation.

## Companion work — `../burp` repo (manual validation, no automated tests)
- Add the **REST API user-options block** ("running", port 1337, **allow access
  without API key**) to `config/user-options.template.json`; document enabling it
  in `README.md`/`NOTES.MD`.
- **Scan-config tuning spike** (param-fuzzer question): research a named/custom
  Burp scan configuration (audit-check selection + wordlists) for a lighter
  "fast fuzz," referenced via the REST `scan_configurations` field. Banked
  finding: param-fuzzer's OOB SSRF/SSTI/multi-language code-injection are custom
  checks a built-in config will **not** fully replace — a tuned config
  *complements* it and lets you dial payload volume (SQLi alone ≈76 payloads per
  insertion point). Deliver a validated config JSON + notes.
- After shipping, flip the "PENDING forever" and "empty scope silently does
  nothing" warnings in `NOTES.MD` / `manual-validation-checklist.md` /
  `extensions/README.md` to "fixed in burp2api vX".

## Acceptance mapping
- Executes to completion on a constrained VM → scope preflight + resource pool +
  fast config.
- Issue retrievable via `GET /scanner/issues` → unchanged (authoritative from
  `siteMap().issues()`).
- Observable `PENDING`/`RUNNING`/`DONE` → live Montoya pull + REST `scan_status`
  proxy, unified in `/scanner/tasks/{id}`.
- "Audit traffic started vs stuck behind work" → `audit_traffic_started` /
  `stalled` (Montoya) and `audit_requests_made` / `audit_queue_items_waiting`
  (REST).
- Mocked Montoya tests, updated docs → Tests + Docs sections above.
