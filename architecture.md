# burp2api Architecture

burp2api is an OpenJDK 21 Burp Suite Professional extension (entry point `com.burp2api.BurpApiExtension`) that exposes Burp's proxy, scanner, scope, session, and Collaborator workflows over a local REST and WebSocket API.

It runs **inside** a Burp Suite Professional JVM, talks to Burp through the Montoya API, serves its own HTTP/WebSocket API with an embedded [Javalin](https://javalin.io/) server bound to `127.0.0.1:7850` by default, and persists captured traffic in a per-project SQLite database. This document describes how the pieces fit together; the endpoint reference lives in [`README.md`](README.md).

## Component overview

The extension sits between API clients (an automated agent, a script, `curl`, `clients/b2a_send.py`, or a WebSocket consumer) and Burp's own tooling. Clients never touch Burp directly — every action is mediated by the extension, and all captured traffic is mirrored into the SQLite store so it survives Burp restarts.

```mermaid
flowchart LR
    subgraph clients["Clients"]
        agent["Agent / script"]
        curl["curl"]
        b2a["b2a_send.py"]
        wsc["WebSocket client"]
    end

    subgraph burp["Burp Suite Professional (JVM)"]
        subgraph ext["burp2api extension"]
            jav["Javalin HTTP/WS server<br/>127.0.0.1:7850"]
            rh["RouteHandler<br/>+ 5 route registrars"]
            atl["AllToolsLogger<br/>(Montoya HttpHandler)"]
            tq["TrafficQueue"]
            db["DatabaseService"]
            ws["WebSocketManager /<br/>EventBroadcaster"]
            ui["ConfigurationPanel<br/>(Suite tab)"]
        end
        montoya["Montoya API<br/>proxy · http · scanner ·<br/>scope · collaborator"]
    end

    sqlite[("Per-project<br/>SQLite DB")]
    rest["Burp built-in<br/>REST API :1337"]
    targets[("Target apps")]

    agent -->|REST| jav
    curl -->|REST| jav
    b2a -->|REST| jav
    wsc -->|WebSocket| jav

    jav --> rh
    rh --> db
    rh --> montoya
    montoya <-->|proxied / sent traffic| targets
    montoya -->|every tool's traffic| atl
    atl -->|synchronous write| db
    atl -->|broadcast only| tq
    tq --> ws
    ws -->|events| jav
    db --- sqlite
    rh -.->|active scan backend| rest
    rest <--> targets
```

## Startup and wiring

`BurpApiExtension.initialize(MontoyaApi)` builds the object graph in four ordered phases: core infrastructure (config, database, traffic queue), capture handlers, the API server and UI, then background maintenance and a one-shot proxy-history import. Each component is constructed once and handed its collaborators by the extension — there is no dependency-injection container.

```mermaid
flowchart TD
    ext["BurpApiExtension.initialize()"]
    cfg["ApiConfig"]
    db["DatabaseService"]
    sm["SchemaManager<br/>(schema v14)"]
    cp["ConnectionPool → PooledConnection"]
    tq["TrafficQueue"]
    atl["AllToolsLogger<br/>(active capturer)"]
    pl["ProxyLogger<br/>(DB capture disabled, #53)"]
    rl["RepeaterLogger<br/>(DB capture disabled)"]
    so["StartupOperations<br/>(history import)"]
    rh["RouteHandler"]
    reg["ScannerRouteRegistrar<br/>CollaboratorRouteRegistrar<br/>ConfigurationRouteRegistrar<br/>SessionRouteRegistrar<br/>BCheckRouteRegistrar"]
    wsm["WebSocketManager<br/>+ EventBroadcaster"]
    stm["ScanTaskManager"]
    jav["Javalin :7850<br/>(loopback)"]
    ui["ConfigurationPanel<br/>(Suite tab)"]
    dms["DatabaseMaintenanceService"]

    ext --> cfg
    ext --> db
    db --> sm
    db --> cp
    ext --> tq
    ext --> atl
    ext --> pl
    ext --> rl
    ext --> so
    ext --> rh
    rh --> reg
    rh --> wsm
    rh --> stm
    ext --> jav
    rh --> jav
    ext --> ui
    ext --> dms

    atl -->|synchronous| db
    atl -->|broadcast| tq
    tq -. "eventBroadcaster = rh.getEventBroadcaster()" .-> wsm
```

## Traffic capture pipeline

Every tool's traffic (Proxy, Repeater, Intruder, Scanner, and requests the API itself sends) reaches `AllToolsLogger`, registered as a single Montoya `HttpHandler`. It is the **only** component that writes captures to the database, and it does so **synchronously on the Montoya handler thread** — one content-hash-deduplicated `proxy_traffic` row with byte-exact `request_raw`/`response_raw` BLOBs.

The `TrafficQueue` is used **only** to fan out live events to WebSocket subscribers, not for the durable write. `ProxyLogger` and `RepeaterLogger` exist but their DB-capture paths are disabled: an earlier design wrote each proxied transaction twice and, under concurrent traffic, the second (asynchronous, heuristically correlated) writer orphaned empty-bodied rows. Collapsing all capture onto the one synchronous writer removed those duplicates (#53).

```mermaid
sequenceDiagram
    participant T as Burp tool<br/>(Proxy/Repeater/Scanner…)
    participant M as Montoya api.http()
    participant A as AllToolsLogger
    participant D as DatabaseService
    participant Q as TrafficQueue
    participant B as EventBroadcaster
    participant W as WebSocket clients

    T->>M: request / response
    M->>A: responseReceived (handler thread)
    A->>D: storeRawTrafficWithSource(...) [synchronous]
    Note over D: one content-hash-deduped proxy_traffic row<br/>+ byte-exact request_raw / response_raw BLOBs
    A->>Q: queueRawTraffic(...) [broadcast only]
    Q->>B: broadcastTrafficCapture(...)
    B->>W: traffic_capture event
```

## Request lifecycle

An inbound API request passes a timing-safe bearer-token check (skipped when no token is configured; `/health` is always exempt), matches a Javalin route owned by `RouteHandler` or one of the five registrars, and is served by a service or by `DatabaseService`. Reads take a pooled, per-thread read connection (`PRAGMA query_only=ON`); writes are serialized through a single `sharedWriteLock`, matching SQLite's single-writer model.

```mermaid
flowchart LR
    req["HTTP request"] --> before{"auth enabled?"}
    before -->|"yes — bad / missing token"| r401["401 Unauthorized"]
    before -->|"/health (exempt)"| route
    before -->|"valid token"| route["Javalin route match"]
    before -->|"auth disabled"| route
    route --> reg["RouteHandler /<br/>route registrar"]
    reg --> svc["Service or<br/>DatabaseService"]
    svc --> rd["Pooled read connection<br/>(query_only)"]
    svc --> wr["Write via sharedWriteLock<br/>(single writer)"]
    reg --> json["JSON response"]
```

## Data model

Captured traffic lives in two linked halves. `proxy_traffic` holds the flattened, deduplicated row plus the raw wire BLOBs that serve as byte-exact evidence. A separate normalized side (`traffic_meta` + `traffic_requests`/`traffic_responses`, indexed by FTS5 virtual tables `request_index`/`response_index`) backs full-text body search and carries tags/comments.

The two halves were historically written under independent auto-increment counters and bridged only by `content_hash`. Schema **v14** added `traffic_meta.proxy_traffic_id`, an explicit link to the public `proxy_traffic.id` space so a body-search hit resolves to the exact captured instance and annotations land on the request the caller is looking at (#21, #28). The diagram is simplified to the core capture tables.

```mermaid
erDiagram
    proxy_traffic ||--o| traffic_meta : "proxy_traffic_id (v14)"
    traffic_meta ||--|| traffic_requests : "normalized request"
    traffic_meta ||--|| traffic_responses : "normalized response"
    traffic_requests ||--|| request_index : "FTS5 trigger"
    traffic_responses ||--|| response_index : "FTS5 trigger"

    proxy_traffic {
        integer id PK
        text method
        text url
        text host
        integer status_code
        text content_hash
        text traffic_source
        blob request_raw
        blob response_raw
    }
    traffic_meta {
        integer id PK
        integer proxy_traffic_id FK
        text tags
        text comment
        integer replayed_from
    }
    traffic_requests {
        integer id PK
        text request_headers
        text request_body
    }
    traffic_responses {
        integer id PK
        text response_headers
        text response_body
    }
    request_index {
        text url
        text method
        text request_body
    }
    response_index {
        text response_body
    }
```

## Active scan backend selection

`POST /scanner/scan-request` first runs a scope preflight, because an out-of-scope Montoya audit is silently accepted but sends zero payloads. It then dispatches to one of two backends. The default (`backend=auto`) prefers Burp's built-in REST API (which can apply a named scan configuration and a resource pool) but falls back to a Montoya single-request audit when fidelity demands it (a request body or a non-GET method, which the REST `/scan` path cannot replay) or when the REST service is unreachable.

```mermaid
flowchart TD
    start["POST /scanner/scan-request"] --> scope{"ScopePreflight.decide()"}
    scope -->|"out of scope &<br/>auto_scope=false"| block["409<br/>scan_would_send_zero_payloads"]
    scope -->|"in scope / added"| backend{"backend?"}

    backend -->|"montoya"| mont["Montoya single-request audit<br/>api.scanner().startAudit()<br/>backend=montoya"]
    backend -->|"rest"| restchk
    backend -->|"auto"| fid{"body present<br/>or method ≠ GET?"}

    fid -->|"yes (needs fidelity)"| mont
    fid -->|"no"| restchk{"REST API<br/>reachable?"}

    restchk -->|"yes"| rest["Burp REST /scan :1337<br/>named config + resource pool<br/>task_id = rest_*"]
    restchk -->|"no / error"| mont

    mont --> tasks["GET /scanner/tasks/{id}<br/>PENDING → RUNNING → DONE"]
    rest --> tasks
    tasks --> issues["GET /scanner/issues"]
```

## Key design decisions

- **One synchronous DB writer.** `AllToolsLogger` owns all capture writes on the Montoya thread; the async queue is for WebSocket fan-out only. This trades a little handler-thread latency for a complete, non-duplicated, byte-exact record (#53).
- **Byte-exact evidence over projections.** Raw request/response bytes are stored in BLOB columns and served by `GET /proxy/history/{id}/raw`. The flattened `headers`/`body` columns are a best-effort search projection, not the citable evidence source.
- **One public id space.** Every read endpoint returns a `proxy_traffic.id`; the `traffic_meta.proxy_traffic_id` link (v14) keeps replay, tagging, and body-search results resolving to the same instance (#21, #28).
- **Pooled reads, serialized writes.** A connection pool leases per-thread read connections (`query_only`) so concurrent searches never share one JDBC `Connection`, while a single write lock respects SQLite's single-writer constraint (#52).
- **Reuse Burp's scan machinery.** Rather than rebuild a task engine, scans run through Burp's authoritative REST API or a Montoya audit, with pure mappers (`ScanStatusMapper`, `RestScanMapper`) normalizing both into one status vocabulary.
- **Safe by default.** The server binds loopback and leaves authentication off for local single-user use; binding to a non-loopback interface without a token logs a warning. Sensitive material (tokens, cookies, Collaborator secrets) is never written to disk or logs.
- **Durable, per-project store.** Each Burp project gets its own SQLite database (co-located beside the `.burp` file when detectable); nothing is pruned automatically, so the store is the durable record Burp's in-memory Logger tab is not.
