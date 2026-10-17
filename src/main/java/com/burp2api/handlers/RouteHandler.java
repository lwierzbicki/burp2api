package com.burp2api.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.burp2api.BurpApiExtension;
import com.burp2api.config.ApiConfig;
import com.burp2api.database.DatabaseService;
import com.burp2api.database.TrafficQueue;
import com.burp2api.database.schema.SchemaManager;
import com.burp2api.services.ScanTaskManager;
import com.burp2api.services.BCheckService;
import com.burp2api.services.ProxyInterceptionService;
import com.burp2api.handlers.SessionRouteRegistrar;
import com.burp2api.handlers.CollaboratorRouteRegistrar;
import com.burp2api.utils.CurlGenerator;
import com.burp2api.utils.BodyCodec;
import com.burp2api.utils.HeaderInput;
import com.burp2api.utils.HeaderList;
import com.burp2api.utils.StoredText;
import com.burp2api.handlers.BCheckRouteRegistrar;
import com.burp2api.websocket.WebSocketManager;
import com.burp2api.websocket.EventBroadcaster;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Handles all HTTP route registrations and request processing for the REST API.
 * This class acts as the main router and controller for all API endpoints.
 * 
 * @version 1.0.0
 */
public class RouteHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(RouteHandler.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final TrafficQueue trafficQueue;
    private final ApiConfig config;
    private final ObjectMapper objectMapper;
    private final JsonMapper jsonMapper;
    private final ScanTaskManager scanTaskManager;
    private com.burp2api.services.ProxyInterceptionService proxyInterceptionService;
    
    // BChecks service
    private final BCheckService bCheckService;
    
    //  WebSocket streaming components
    private final WebSocketManager webSocketManager;
    private final EventBroadcaster eventBroadcaster;
    
    // Curl generator for creating curl commands
    private final Object curlGenerator;

    // Per-session_tag cookie jar for stateful /proxy/send and /proxy/replay flows.
    private final com.burp2api.utils.SessionCookieJar cookieJar = new com.burp2api.utils.SessionCookieJar();
    
    /**
     * Constructor for RouteHandler.
     * 
     * @param api The MontoyaApi instance
     * @param databaseService The database service for data persistence
     * @param trafficQueue The traffic queue for asynchronous processing
     * @param config The API configuration
     */
    public RouteHandler(MontoyaApi api, DatabaseService databaseService, TrafficQueue trafficQueue, ApiConfig config) {
        this.api = api;
        this.databaseService = databaseService;
        this.trafficQueue = trafficQueue;
        this.config = config;
        this.objectMapper = new ObjectMapper();
        
        //  Initialize WebSocket components
        this.webSocketManager = new WebSocketManager();
        this.eventBroadcaster = new EventBroadcaster(this.webSocketManager);
        
        // Initialize ScanTaskManager
        this.scanTaskManager = new ScanTaskManager(databaseService, webSocketManager);
        
        // Initialize BCheck service
        this.bCheckService = new BCheckService(api, config, databaseService);
        
        // Initialize curl generator (placeholder - would need actual implementation)
        this.curlGenerator = null;
        
        // Create JsonMapper for Javalin
        this.jsonMapper = new JsonMapper() {
            @Override
            public String toJsonString(Object obj, Type type) {
                try {
                    return objectMapper.writeValueAsString(obj);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to serialize object to JSON", e);
                }
            }
            
            @Override
            public <T> T fromJsonString(String json, Type targetType) {
                try {
                    return objectMapper.readValue(json, objectMapper.constructType(targetType));
                } catch (Exception e) {
                    throw new RuntimeException("Failed to deserialize JSON to object", e);
                }
            }
        };
    }
    
    /**
     * Checks if database service is available and returns appropriate error response if not.
     * 
     * @param ctx The Javalin context
     * @return true if database is available, false if not (and error response is set)
     */
    /**
     * Constant-time string comparison to avoid leaking token length/content via timing.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] ab = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return java.security.MessageDigest.isEqual(ab, bb);
    }

    private boolean checkDatabaseAvailable(io.javalin.http.Context ctx) {
        if (databaseService == null || !databaseService.isInitialized()) {
            ctx.status(503).json(Map.of(
                "error", "Database not available",
                "message", "Database service is not initialized. Please configure the extension in the 'REST API Config' tab.",
                "status", "service_unavailable"
            ));
            return false;
        }
        
        // REMOVED: Project change checking was causing database instability
        
        return true;
    }
    
    /**
     * Registers all API routes with the Javalin application.
     * 
     * @param app The Javalin application instance
     */
    public void registerRoutes(Javalin app) {
        logger.info("Registering API routes");

        // Optional bearer-token authentication. Enabled only when BURP2API_TOKEN (api.token)
        // is set. /health stays open so liveness probes work without credentials.
        if (config.isAuthEnabled()) {
            final String expected = "Bearer " + config.getAuthToken();
            app.before(ctx -> {
                if ("/health".equals(ctx.path())) {
                    return;
                }
                String provided = ctx.header("Authorization");
                if (provided == null || !constantTimeEquals(provided, expected)) {
                    throw new io.javalin.http.UnauthorizedResponse(
                        "Missing or invalid bearer token. Provide 'Authorization: Bearer <BURP2API_TOKEN>'.");
                }
            });
            // Specific mapper so auth failures render as 401 instead of the generic 500 handler below.
            app.exception(io.javalin.http.HttpResponseException.class, (e, ctx) -> {
                ctx.status(e.getStatus()).json(Map.of(
                    "error", e.getMessage(),
                    "status", e.getStatus()
                ));
            });
            logger.info("Bearer-token authentication ENABLED for all routes except /health");
        }

        // Add request logging middleware
        app.before(ctx -> {
            logger.debug("API Request: {} {} from {}",
                       ctx.method(),
                       ctx.path(),
                       ctx.ip());
            
            // Log request body if present (for POST/PUT requests)
            if (!ctx.body().isEmpty()) {
                logger.debug("Request body: {}", ctx.body());
            }
            
            // Log query parameters if present
            if (!ctx.queryParamMap().isEmpty()) {
                logger.debug("Query parameters: {}", ctx.queryParamMap());
            }
        });
        
        // Add response logging middleware
        app.after(ctx -> {
            Long startTime = ctx.attribute("requestStartTime");
            long duration = startTime != null ? System.currentTimeMillis() - startTime : 0;
            logger.debug("API Response: {} {} -> {} ({}ms)",
                       ctx.method(),
                       ctx.path(),
                       ctx.status(),
                       duration);
        });
        
        // Add request timing
        app.before(ctx -> ctx.attribute("requestStartTime", System.currentTimeMillis()));
        
        // Add exception handling middleware
        app.exception(Exception.class, (exception, ctx) -> {
            logger.error("Unhandled exception in API endpoint {} {}: {}", 
                        ctx.method(), 
                        ctx.path(), 
                        exception.getMessage(), 
                        exception);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Internal server error");
            errorResponse.put("message", exception.getMessage());
            errorResponse.put("timestamp", System.currentTimeMillis());
            errorResponse.put("path", ctx.path());
            
            ctx.status(500).json(errorResponse);
        });
        
        // Add 404 handler
        app.error(404, ctx -> {
            logger.warn("API endpoint not found: {} {}", ctx.method(), ctx.path());
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Not found");
            errorResponse.put("message", "API endpoint not found");
            errorResponse.put("timestamp", System.currentTimeMillis());
            errorResponse.put("path", ctx.path());
            
            ctx.json(errorResponse);
        });
        
        // Root endpoint
        app.get("/", ctx -> {
            Map<String, Object> response = new HashMap<>();
            response.put("name", BurpApiExtension.getName());
            response.put("version", BurpApiExtension.getVersion());
            response.put("status", "running");
            response.put("endpoints", getEndpointList());
            ctx.json(response);
        });
        
        // Version endpoint
        app.get("/version", ctx -> {
            Map<String, Object> response = new HashMap<>();
            response.put("api_version", BurpApiExtension.getVersion());
            // Build's target schema version — a capability signal decoupled from
            // any open database. Byte-exact raw capture (#24) requires >= 12, so
            // an operator can confirm their jar has the lossless-capture fix.
            response.put("schema_version", SchemaManager.currentSchemaVersion());

            // Convert Burp version to serializable format
            var burpVersion = api.burpSuite().version();
            Map<String, Object> burpVersionInfo = new HashMap<>();
            burpVersionInfo.put("name", burpVersion.name());
            burpVersionInfo.put("version_string", burpVersion.toString());
            burpVersionInfo.put("build_number", burpVersion.buildNumber());
            burpVersionInfo.put("edition", burpVersion.edition().toString());
            
            response.put("burp_version", burpVersionInfo);
            ctx.json(response);
        });
        
        // Health check endpoint
        app.get("/health", ctx -> {
            Map<String, Object> response = new HashMap<>();
            response.put("status", "healthy");
            response.put("database", databaseService != null && databaseService.isInitialized() ? "connected" : "disconnected");
            // #25: echo the bound port/host and version so an operator or agent
            // who reaches the service can confirm it and correct a stale, remembered
            // port. /health stays unauthenticated, so this is safe to expose.
            response.put("port", config.getPort());
            response.put("bind", config.getBindHost());
            response.put("version", BurpApiExtension.getVersion());
            response.put("timestamp", System.currentTimeMillis());
            ctx.json(response);
        });
        
        // Debug route to see all registered routes
        app.get("/debug/routes", ctx -> {
            Map<String, Object> routeInfo = new HashMap<>();
            routeInfo.put("message", "Route debugging information");
            routeInfo.put("timestamp", System.currentTimeMillis());
            
            // List some key routes we're looking for
            List<String> expectedRoutes = List.of(
                "POST /proxy/tag",
                "POST /proxy/comment", 
                "POST /proxy/import-history",
                "GET /proxy/stats",
                "GET /health"
            );
            routeInfo.put("expected_routes", expectedRoutes);
            routeInfo.put("note", "These routes should be registered - checking if tag/comment endpoints are accessible");
            
            // Test if we can access our own endpoints internally
            try {
                routeInfo.put("debug_info", "Routes registered in this handler");
            } catch (Exception e) {
                routeInfo.put("error", e.getMessage());
            }
            
            ctx.json(routeInfo);
        });
        
        // Project information endpoint
        app.get("/project", ctx -> {
            Map<String, Object> response = new HashMap<>();
            
            if (databaseService != null && databaseService.isInitialized()) {
                response.put("current_project", databaseService.getCurrentProjectName());
                response.put("database_path", databaseService.getCurrentDatabasePath());
                response.put("database_status", "connected");
            } else {
                response.put("current_project", null);
                response.put("database_path", null);
                response.put("database_status", "disconnected");
            }
            
            response.put("timestamp", System.currentTimeMillis());
            ctx.json(response);
        });
        
        
        // Initialize ScanTaskManager
        try {
            scanTaskManager.initialize();
            logger.info("ScanTaskManager initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize ScanTaskManager", e);
        }
        
        // Register proxy routes
        registerProxyRoutes(app);
        
        // Register scope routes
        registerScopeRoutes(app);
        
        // Register scanner routes
        registerScannerRoutes(app);
        
        // Register BCheck routes 
        registerBCheckRoutes(app);
        
        // Register configuration management routes
        registerConfigurationRoutes(app);
        
        // Register authentication routes
        registerAuthRoutes(app);
        
        // Register documentation routes 
        registerDocumentationRoutes(app);
        
        // Register collaborator routes
        registerCollaboratorRoutes(app);

        // Register session management routes
        registerSessionRoutes(app);

        // Register traffic metadata routes
        registerTrafficMetadataRoutes(app);

        // Register curl generator routes
        registerCurlGeneratorRoutes(app);

        // Register analytics and stats routes
        registerAnalyticsRoutes(app);

        // Register replay functionality - using replay-matched format
        app.post("/proxy/replay", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Extract request IDs. Each entry may be a bare id or an object
                // {id, expect:{method?,url?}} that asserts which request the id
                // must resolve to; a top-level `expect` applies to every bare id
                // (#28 opt-in cross-check against the silent-wrong-replay).
                List<Long> requestIds = new ArrayList<>();
                Map<Long, Map<String, String>> expectById = new HashMap<>();
                Map<String, String> topExpect = parseExpect(requestData.get("expect"));
                if (requestData.containsKey("request_ids")) {
                    List<Object> ids = (List<Object>) requestData.get("request_ids");
                    for (Object entry : ids) {
                        long id;
                        Map<String, String> expect = topExpect;
                        if (entry instanceof Map) {
                            Map<?, ?> obj = (Map<?, ?>) entry;
                            Object idVal = obj.get("id");
                            if (idVal == null) {
                                continue;
                            }
                            id = Long.valueOf(idVal.toString());
                            Map<String, String> perId = parseExpect(obj.get("expect"));
                            if (perId != null) {
                                expect = perId;
                            }
                        } else {
                            id = Long.valueOf(entry.toString());
                        }
                        requestIds.add(id);
                        if (expect != null) {
                            expectById.put(id, expect);
                        }
                    }
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing request_ids",
                        "message", "Must provide 'request_ids' array",
                        "example", Map.of("request_ids", List.of(1, 2, 3))
                    ));
                    return;
                }
                
                String sessionTag = (String) requestData.getOrDefault("session_tag",
                    config.getSessionTag() + "_replay_" + System.currentTimeMillis());

                // Session-scoped cookie jar mode, as on /proxy/send.
                String cookieJarMode = ((String) requestData.getOrDefault("cookie_jar", "off")).toLowerCase();
                boolean useCookieJar = "use".equals(cookieJarMode) || "reset".equals(cookieJarMode);
                if ("reset".equals(cookieJarMode)) {
                    cookieJar.reset(sessionTag);
                }

                List<Map<String, Object>> results = new ArrayList<>();
                List<Map<String, Object>> errors = new ArrayList<>();
                List<Long> notFound = new ArrayList<>();
                List<Map<String, Object>> mismatched = new ArrayList<>();

                // Get records to replay. Unknown ids are reported (not silently
                // dropped), and an id that resolves to a request other than the
                // one the caller asserted via `expect` is refused (#28).
                List<Map<String, Object>> recordsToReplay = new ArrayList<>();
                for (Long id : requestIds) {
                    Map<String, Object> record = databaseService.getTrafficById(id);
                    if (record == null) {
                        notFound.add(id);
                        continue;
                    }
                    Map<String, String> expect = expectById.get(id);
                    if (expect != null) {
                        String actualMethod = (String) record.get("method");
                        String actualUrl = (String) record.get("url");
                        boolean methodOk = expect.get("method") == null
                            || expect.get("method").equalsIgnoreCase(actualMethod);
                        boolean urlOk = expect.get("url") == null
                            || expect.get("url").equals(actualUrl);
                        if (!methodOk || !urlOk) {
                            Map<String, Object> actual = new HashMap<>();
                            actual.put("method", actualMethod);
                            actual.put("url", actualUrl);
                            Map<String, Object> mm = new HashMap<>();
                            mm.put("id", id);
                            mm.put("expected", expect);
                            mm.put("actual", actual);
                            mismatched.add(mm);
                            continue;
                        }
                    }
                    recordsToReplay.add(record);
                }

                if (recordsToReplay.isEmpty()) {
                    // Separate an explicit expectation mismatch (409) from ids
                    // that simply do not resolve (404).
                    if (!mismatched.isEmpty()) {
                        ctx.status(409).json(Map.of(
                            "error", "Replay id did not match the expected request",
                            "message", "No id both resolved and matched its expected "
                                + "method/url; nothing was replayed. See issue #28.",
                            "mismatched", mismatched,
                            "not_found", notFound
                        ));
                        return;
                    }
                    ctx.status(404).json(Map.of(
                        "error", "No records found",
                        "message", "No traffic records found for the specified IDs",
                        "not_found", notFound
                    ));
                    return;
                }
                
                // Replay each record
                for (Map<String, Object> record : recordsToReplay) {
                    try {
                        String method = (String) record.get("method");
                        String url = (String) record.get("url");
                        String headers = (String) record.get("headers");
                        String body = (String) record.get("body");
                        Long originalId = (Long) record.get("id");
                        
                        // Create HTTP request exactly like replay-matched
                        burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
                            burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url)
                                .withMethod(method)
                                .withBody(body != null ? body : "");
                        
                        // Check API availability exactly like replay-matched
                        if (api == null) {
                            logger.error("Burp API is not available for replay. Skipping request.");
                            continue; // Skip this request and continue with next one
                        }
                        
                        var httpService = api.http();
                        if (httpService == null) {
                            logger.error("Burp HTTP service is not available for replay. Skipping request.");
                            continue; // Skip this request and continue with next one
                        }

                        // Apply the session cookie jar to the replayed request.
                        if (useCookieJar) {
                            httpRequest = applyCookieJar(httpRequest, sessionTag, url,
                                (String) record.get("host"));
                        }

                        // Send request exactly like replay-matched
                        burp.api.montoya.http.message.HttpRequestResponse response =
                            httpService.sendRequest(httpRequest);

                        // Ingest Set-Cookie so subsequent replays under this tag
                        // carry the (possibly rotated) cookies.
                        if (useCookieJar && response.response() != null) {
                            cookieJar.update(sessionTag, (String) record.get("host"),
                                response.response().headers().toString());
                        }

                        // Store the replayed request and response exactly like replay-matched
                        long replayId = databaseService.storeRawTraffic(
                            method, url, (String) record.get("host"), headers, body,
                            response.response().headers().toString(), response.response().bodyToString(),
                            (int) response.response().statusCode(), sessionTag
                        );
                        
                        Map<String, Object> result = new HashMap<>();
                        result.put("original_id", originalId);
                        result.put("replay_id", replayId);
                        result.put("method", method);
                        result.put("url", url);
                        result.put("status_code", response.response().statusCode());
                        result.put("response_length", response.response().body().length());
                        
                        results.add(result);
                        
                    } catch (Exception e) {
                        Map<String, Object> error = new HashMap<>();
                        error.put("original_id", record.get("id"));
                        error.put("url", record.get("url"));
                        error.put("error", e.getMessage());
                        errors.add(error);
                    }
                }
                
                // Count actual successes vs failures (like replay-matched does)
                long successCount = results.stream()
                    .mapToLong(r -> {
                        Object replayId = r.get("replay_id");
                        // Positive replay_id = success, -2 or negative = failure
                        return (replayId instanceof Number && ((Number) replayId).longValue() > 0) ? 1 : 0;
                    }).sum();
                
                long failureCount = results.size() - successCount + errors.size();
                
                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("successful_replays", successCount);
                response.put("failed_replays", failureCount);
                response.put("total_requests", requestIds.size());
                response.put("replay_results", results);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }
                if (!notFound.isEmpty()) {
                    response.put("not_found", notFound);
                }
                if (!mismatched.isEmpty()) {
                    response.put("mismatched", mismatched);
                }

                ctx.json(response);

            } catch (Exception e) {
                logger.error("Replay endpoint error: {}", e.getMessage());
                ctx.status(500).json(Map.of(
                    "error", "Failed to process replay request",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Save query preset
        app.post("/proxy/query/save", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                String name = (String) requestData.get("name");
                Map<String, Object> queryParams = (Map<String, Object>) requestData.get("query_params");
                String description = (String) requestData.get("description");
                
                if (name == null || name.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing name parameter",
                        "message", "name parameter is required"
                    ));
                    return;
                }
                
                if (queryParams == null) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing query_params parameter", 
                        "message", "query_params parameter is required"
                    ));
                    return;
                }
                
                // Get current session tag
                String sessionTag = ctx.sessionAttribute("session_tag");
                if (sessionTag == null) {
                    sessionTag = "default";
                }
                
                String queryParamsJson = objectMapper.writeValueAsString(queryParams);
                
                // Note: DatabaseService already handles uniqueness for test queries
                long queryId = databaseService.saveQuery(name, description, queryParamsJson, sessionTag);
                
                if (queryId > 0) {
                    ctx.json(Map.of(
                        "success", true,
                        "query_id", queryId,
                        "name", name,
                        "message", "Query saved successfully"
                    ));
                } else {
                    ctx.status(500).json(Map.of(
                        "error", "Failed to save query",
                        "message", "Query could not be saved (may already exist)"
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to save query", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to save query",
                    "message", e.getMessage()
                ));
            }
        });
        
        // List saved queries
        app.get("/proxy/query/list", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                String sessionTag = ctx.queryParam("session_tag");
                List<Map<String, Object>> queries = databaseService.listSavedQueries(sessionTag);
                
                // Parse query_params JSON for each query
                for (Map<String, Object> query : queries) {
                    String queryParamsJson = (String) query.get("query_params");
                    if (queryParamsJson != null) {
                        try {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> queryParams = objectMapper.readValue(queryParamsJson, Map.class);
                            query.put("query_params", queryParams);
                        } catch (Exception e) {
                            logger.warn("Failed to parse query_params for query {}: {}", query.get("name"), e.getMessage());
                        }
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("queries", queries);
                response.put("count", queries.size());
                response.put("session_tag_filter", sessionTag);
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to list saved queries", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to list queries",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Load saved query - WITH DATABASE
        app.get("/proxy/query/load", ctx -> {
            String name = ctx.queryParam("name");
            if (name == null) {
                ctx.status(400).json(Map.of("error", "Missing name"));
                return;
            }
            
            try {
                Map<String, Object> query = databaseService.loadQuery(name);
                if (query != null) {
                    ctx.json(query);
                } else {
                    ctx.status(404).json(Map.of("error", "Query not found"));
                }
            } catch (Exception e) {
                ctx.status(500).json(Map.of("error", "Database error", "message", e.getMessage()));
            }
        });
        
        // Delete saved query - WITH DATABASE
        app.delete("/proxy/query/{name}", ctx -> {
            String name = ctx.pathParam("name");
            try {
                boolean success = databaseService.deleteSavedQuery(name);
                if (success) {
                    ctx.json(Map.of("success", true, "name", name, "message", "Query deleted successfully"));
                } else {
                    ctx.status(404).json(Map.of("error", "Query not found"));
                }
            } catch (Exception e) {
                ctx.status(500).json(Map.of("error", "Database error", "message", e.getMessage()));
            }
        });
        
        // WebSocket endpoints
        app.get("/ws/stats", ctx -> {
            try {
                logger.info("WebSocket stats endpoint called");
                Map<String, Object> stats = webSocketManager.getConnectionStats();
                logger.info("WebSocket stats retrieved successfully: {}", stats);
                
                // Create a completely safe response using primitive types only
                Map<String, Object> safeResponse = new HashMap<>();
                safeResponse.put("total_connections", 0);
                safeResponse.put("active_connections", 0);
                safeResponse.put("status", "healthy");
                safeResponse.put("timestamp", System.currentTimeMillis());
                
                // Try to get actual values safely
                if (stats != null) {
                    try {
                        Object totalConn = stats.get("total_connections");
                        if (totalConn instanceof Number) {
                            safeResponse.put("total_connections", ((Number) totalConn).intValue());
                        }
                        
                        Object activeConn = stats.get("active_connections");
                        if (activeConn instanceof Number) {
                            safeResponse.put("active_connections", ((Number) activeConn).longValue());
                        }
                        
                        Object lastActivity = stats.get("last_activity");
                        if (lastActivity instanceof Number) {
                            safeResponse.put("last_activity", ((Number) lastActivity).longValue());
                        }
                        
                        Object totalEvents = stats.get("total_events_sent");
                        if (totalEvents instanceof Number) {
                            safeResponse.put("total_events_sent", ((Number) totalEvents).longValue());
                        }
                        
                        Object uptime = stats.get("uptime_ms");
                        if (uptime instanceof Number) {
                            safeResponse.put("uptime_ms", ((Number) uptime).longValue());
                        }
                        
                        // Skip connections_by_session for now to avoid complex object serialization
                        safeResponse.put("connections_by_session", new HashMap<String, Integer>());
                    } catch (Exception statsError) {
                        logger.warn("Error extracting individual stats: {}", statsError.getMessage());
                    }
                }
                
                ctx.json(safeResponse);
                logger.info("WebSocket stats endpoint completed successfully");
            } catch (Exception e) {
                logger.error("Failed to get WebSocket stats", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get WebSocket stats",
                    "message", e.getMessage() != null ? e.getMessage() : "Unknown error"
                ));
            }
        });
        
        app.get("/ws/test", ctx -> {
            try {
                String sessionTag = ctx.queryParam("session_tag");
                if (sessionTag == null) {
                    sessionTag = "test_broadcast";
                }
                
                // Broadcast a test message
                Map<String, Object> testData = Map.of(
                    "message", "WebSocket test broadcast", 
                    "timestamp", System.currentTimeMillis(),
                    "test", true
                );
                
                webSocketManager.broadcastToSession(
                    new com.burp2api.websocket.WebSocketEvent(
                        com.burp2api.websocket.WebSocketEventType.SYSTEM_STATUS, 
                        sessionTag,
                        testData
                    ), 
                    sessionTag
                );
                
                ctx.json(Map.of(
                    "success", true,
                    "message", "Test broadcast sent to WebSocket clients",
                    "session_tag", sessionTag,
                    "timestamp", System.currentTimeMillis()
                ));
                
                logger.info("WebSocket test broadcast sent for session: {}", sessionTag);
                
            } catch (Exception e) {
                logger.error("Failed to send WebSocket test broadcast", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to send test broadcast",
                    "message", e.getMessage()
                ));
            }
        });
        
        // WebSocket streaming endpoint
        app.ws("/ws/stream", ws -> {
            ws.onConnect(ctx -> {
                webSocketManager.handleConnect(ctx);
            });
            
            ws.onMessage(ctx -> {
                webSocketManager.handleMessage(ctx, ctx.message());
            });
            
            ws.onClose(ctx -> {
                webSocketManager.handleDisconnect(ctx);
            });
            
            ws.onError(ctx -> {
                logger.error("WebSocket error for connection {}: {}", 
                    ctx.getSessionId(), ctx.error() != null ? ctx.error().getMessage() : "Unknown error");
            });
        });
        
        logger.info("All API routes registered successfully");
    }
    
    /**
     * Registers proxy-related routes.
     */
    private void registerProxyRoutes(Javalin app) {
        // Enhanced search proxy traffic with features
        app.get("/proxy/search", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;

            Map<String, String> searchParams = extractSearchParams(ctx);

            // Handle session_tag parameter - default to searching all sessions
            String explicitSessionTag = ctx.queryParam("session_tag");
            if (explicitSessionTag != null && !explicitSessionTag.isEmpty()) {
                // Specific session tag provided - use it
                searchParams.put("session_tag", explicitSessionTag);
            }
            // If no session_tag or empty session_tag - search all sessions (don't add filter)

            // Always answer with a JSON body: a search failure must surface as a JSON
            // error, never a bare closed connection the client has to guess at (#52).
            try {
                // Get search results
                List<Map<String, Object>> results = databaseService.searchTraffic(searchParams);
                annotateRecords(results);

                // Get total count for pagination
                long totalCount = databaseService.getSearchCount(searchParams);

                // Build response with pagination metadata
                Map<String, Object> response = new HashMap<>();
                response.put("results", results);
                response.put("count", results.size());
                response.put("total_count", totalCount);
                response.put("filters", searchParams);

                // Add pagination metadata
                if (searchParams.containsKey("limit") || searchParams.containsKey("offset")) {
                    Map<String, Object> pagination = new HashMap<>();
                    int limit = searchParams.containsKey("limit") ? Integer.parseInt(searchParams.get("limit")) : 1000;
                    int offset = searchParams.containsKey("offset") ? Integer.parseInt(searchParams.get("offset")) : 0;

                    pagination.put("limit", limit);
                    pagination.put("offset", offset);
                    pagination.put("total_pages", (totalCount + limit - 1) / limit);
                    pagination.put("current_page", (offset / limit) + 1);
                    pagination.put("has_next", offset + limit < totalCount);
                    pagination.put("has_previous", offset > 0);

                    response.put("pagination", pagination);
                }

                ctx.json(response);
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid pagination parameter",
                    "message", "limit and offset must be integers"
                ));
            } catch (Exception e) {
                logger.error("Failed to search proxy traffic", e);
                ctx.status(500).json(Map.of(
                    "error", "Search failed",
                    "message", String.valueOf(e.getMessage())
                ));
            }
        });
        
        // Download endpoint for exporting search results
        app.get("/proxy/search/download", ctx -> {
            String format = ctx.queryParam("format");
            if (format == null) {
                format = "json";
            }
            format = format.toLowerCase();
            
            if (!format.equals("json") && !format.equals("csv")) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid format",
                    "message", "Format must be 'json' or 'csv'",
                    "supported_formats", List.of("json", "csv")
                ));
                return;
            }
            
            Map<String, String> searchParams = extractSearchParams(ctx);
            
            // Remove pagination for export (export all matching results)
            searchParams.remove("limit");
            searchParams.remove("offset");
            
            List<Map<String, Object>> results = databaseService.searchTraffic(searchParams);
            if (format.equals("json")) {
                annotateRecords(results);
            }

            // Set appropriate headers for file download
            String filename = "proxy_traffic_" + System.currentTimeMillis() + "." + format;
            ctx.header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            
            if (format.equals("json")) {
                ctx.contentType("application/json")
                   .result(objectMapper.writeValueAsString(Map.of(
                       "export_metadata", Map.of(
                           "timestamp", System.currentTimeMillis(),
                           "total_records", results.size(),
                           "filters", searchParams
                       ),
                       "data", results
                   )));
            } else if (format.equals("csv")) {
                ctx.contentType("text/csv")
                   .result(convertToCsv(results));
            }
        });
        
        // Get proxy history (all traffic) - enhanced with pagination and optimized scope filtering
        app.get("/proxy/history", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            Map<String, String> searchParams = new HashMap<>();
            
            // Extract pagination parameters with SAFE DEFAULTS for large databases
            String limitParam = ctx.queryParam("limit");
            String offsetParam = ctx.queryParam("offset");
            
            // Default limit to 100 to prevent loading massive datasets accidentally
            int defaultLimit = 100;
            int maxLimit = 10000; // Maximum allowed limit to prevent memory issues
            
            if (limitParam != null) {
                try {
                    int requestedLimit = Integer.parseInt(limitParam);
                    if (requestedLimit > maxLimit) {
                        ctx.status(400).json(Map.of(
                            "error", "Limit too large",
                            "message", String.format("Maximum allowed limit is %d. Use pagination with offset to get more records.", maxLimit),
                            "max_limit", maxLimit,
                            "suggested_usage", String.format("?limit=%d&offset=0, then ?limit=%d&offset=%d, etc.", maxLimit, maxLimit, maxLimit)
                        ));
                        return;
                    }
                    searchParams.put("limit", String.valueOf(requestedLimit));
                } catch (NumberFormatException e) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid limit parameter",
                        "message", "Limit must be a valid integer"
                    ));
                    return;
                }
            } else {
                // Apply default limit
                searchParams.put("limit", String.valueOf(defaultLimit));
            }
            
            if (offsetParam != null) {
                try {
                    Integer.parseInt(offsetParam); // Validate it's a number
                    searchParams.put("offset", offsetParam);
                } catch (NumberFormatException e) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid offset parameter", 
                        "message", "Offset must be a valid integer"
                    ));
                    return;
                }
            } else {
                searchParams.put("offset", "0");
            }
            
            // Handle session_tag parameter - default to searching all sessions
            String sessionTag = ctx.queryParam("session_tag");
            if (sessionTag != null && !sessionTag.isEmpty()) {
                // Specific session tag provided - use it
                searchParams.put("session_tag", sessionTag);
            }
            // If no session_tag or empty session_tag - search all sessions (don't add filter)
            
            // Extract scope filtering parameters
            boolean isInScope = "true".equalsIgnoreCase(ctx.queryParam("isInScope"));
            boolean notInScope = "true".equalsIgnoreCase(ctx.queryParam("notInScope"));
            
            if (isInScope && notInScope) {
                ctx.status(400).json(Map.of(
                    "error", "Conflicting scope filters",
                    "message", "Cannot use both 'isInScope=true' and 'notInScope=true' at the same time",
                    "examples", List.of(
                        "?isInScope=true - Show only in-scope traffic",
                        "?notInScope=true - Show only out-of-scope traffic", 
                        "?limit=100&isInScope=true - Paginated in-scope traffic"
                    )
                ));
                return;
            }
            
            // Get database results with proper pagination
            List<Map<String, Object>> allResults = databaseService.searchTraffic(searchParams);
            annotateRecords(allResults);

            // Optimized scope filtering using bulk checking
            List<Map<String, Object>> filteredResults = new ArrayList<>();
            int scopeFilteredCount = 0;
            int cacheHits = 0;
            List<String> urlsToCheck = new ArrayList<>();
            
            if (isInScope || notInScope) {
                // Extract all URLs for bulk scope checking
                urlsToCheck = allResults.stream()
                    .map(record -> (String) record.get("url"))
                    .filter(url -> url != null)
                    .distinct()
                    .collect(java.util.stream.Collectors.toList());
                
                // Use bulk scope checking with cache
                Map<String, Boolean> scopeResults = databaseService.bulkScopeCheck(urlsToCheck, api);
                
                // Apply scope filtering
                for (Map<String, Object> record : allResults) {
                    String url = (String) record.get("url");
                    if (url != null) {
                        Boolean urlInScope = scopeResults.get(url);
                        if (urlInScope != null) {
                            if ((isInScope && urlInScope) || (notInScope && !urlInScope)) {
                                filteredResults.add(record);
                            } else {
                                scopeFilteredCount++;
                            }
                        } else {
                            // Include records where scope check failed
                            filteredResults.add(record);
                        }
                    } else {
                        // Include records without URLs
                        filteredResults.add(record);
                    }
                }
                
                // Calculate cache efficiency  
                cacheHits = urlsToCheck.size() - scopeResults.values().size();
            } else {
                // No scope filtering requested
                filteredResults = allResults;
            }
            
            // Get total count (before scope filtering) for pagination metadata
            long totalCount = databaseService.getSearchCount(searchParams);
            
            Map<String, Object> response = new HashMap<>();
            response.put("history", filteredResults);
            response.put("count", filteredResults.size());
            response.put("total_count_before_scope_filter", totalCount);
            
            // Add performance information for large databases
            Map<String, Object> performanceInfo = new HashMap<>();
            performanceInfo.put("default_limit_applied", limitParam == null);
            performanceInfo.put("max_limit", maxLimit);
            performanceInfo.put("current_limit", searchParams.get("limit"));
            performanceInfo.put("current_offset", searchParams.get("offset"));
            if (limitParam == null) {
                performanceInfo.put("note", String.format("Default limit of %d applied. Use ?limit=N&offset=M for custom pagination", defaultLimit));
            }
            response.put("performance", performanceInfo);
            
            // Add enhanced scope filtering information with performance metrics
            if (isInScope || notInScope) {
                Map<String, Object> scopeInfo = new HashMap<>();
                scopeInfo.put("filter_applied", isInScope ? "in_scope_only" : "out_of_scope_only");
                scopeInfo.put("records_after_scope_filter", filteredResults.size());
                scopeInfo.put("records_filtered_by_scope", scopeFilteredCount);
                scopeInfo.put("scope_check_method", "optimized_bulk_with_cache");
                scopeInfo.put("unique_urls_checked", urlsToCheck.size());
                scopeInfo.put("cache_efficiency", String.format("%.1f%%", cacheHits * 100.0 / Math.max(1, urlsToCheck.size())));
                response.put("scope_filtering", scopeInfo);
            }
            
            // Enhanced pagination metadata 
            Map<String, Object> pagination = new HashMap<>();
            int limit = Integer.parseInt(searchParams.get("limit"));
            int offset = Integer.parseInt(searchParams.get("offset"));
            
            // Note: Pagination is applied to database results, then scope filtering is applied
            // This means the final count may be less than the limit due to scope filtering
            pagination.put("limit", limit);
            pagination.put("offset", offset);
            pagination.put("note", "Pagination applied before scope filtering - final count may be less than limit");
            
            // Calculate pagination based on pre-scope-filter totals
            pagination.put("total_pages_before_scope", (totalCount + limit - 1) / limit);
            pagination.put("current_page", (offset / limit) + 1);
            pagination.put("has_next_before_scope", offset + limit < totalCount);
            pagination.put("has_previous", offset > 0);
            
            // Add navigation hints for large databases
            if (totalCount > 1000) {
                List<String> hints = new ArrayList<>();
                hints.add(String.format("Large database detected (%d total records)", totalCount));
                hints.add(String.format("Use limit=%d for faster queries", maxLimit));
                hints.add("Consider using /proxy/search with filters for better performance");
                pagination.put("large_db_hints", hints);
            }
            
            response.put("pagination", pagination);
            
            ctx.json(response);
        });
        
        //  Replay endpoint - Send raw request and capture response
        app.post("/proxy/send", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Validate required fields
                if (!requestData.containsKey("method") || !requestData.containsKey("url")) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Both 'method' and 'url' are required",
                        "required_fields", List.of("method", "url")
                    ));
                    return;
                }
                
                String method = (String) requestData.get("method");
                String url = (String) requestData.get("url");

                // Validate the URL up front. httpRequestFromUrl() throws an
                // opaque IllegalArgumentException ("Invalid data", caused by
                // MalformedURLException) on anything that is not an absolute
                // http(s) URL - e.g. an agent that passes a CLI-style token like
                // "--help" as the url. Without this it surfaces as a 500 with a
                // full stack trace; a bad url is client error, so fail fast 400.
                String urlError = validateHttpUrl(url);
                if (urlError != null) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid url",
                        "message", urlError
                    ));
                    return;
                }
                // Accept headers as a JSON object, an array of [name, value] pairs,
                // or the legacy CRLF string. Normalize to a block for storage.
                List<HeaderInput.Header> headerList = HeaderInput.parse(requestData.get("headers"));
                String headers = HeaderInput.toBlock(headerList);
                String body = (String) requestData.getOrDefault("body", "");
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag());

                // Session-scoped cookie jar mode: "use" applies+updates the jar,
                // "reset" clears it first, "off"/absent keeps stateless behavior.
                String cookieJarMode = ((String) requestData.getOrDefault("cookie_jar", "off")).toLowerCase();
                boolean useCookieJar = "use".equals(cookieJarMode) || "reset".equals(cookieJarMode);
                if ("reset".equals(cookieJarMode)) {
                    cookieJar.reset(sessionTag);
                }

                // Create HTTP request using Burp API
                String host = extractHostFromUrl(url);
                burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url)
                        .withMethod(method)
                        .withBody(body);

                // Apply caller-supplied headers. Without this, agent-provided auth
                // tokens / content-type would be dropped.
                httpRequest = HeaderInput.applyTo(httpRequest, headerList);

                // Check if Burp API and HTTP service are available
                if (api == null) {
                    ctx.status(503).json(Map.of(
                        "error", "Service Unavailable",
                        "message", "Burp API is not available. Please ensure Burp Suite is fully loaded."
                    ));
                    return;
                }
                
                var httpService = api.http();
                if (httpService == null) {
                    ctx.status(503).json(Map.of(
                        "error", "Service Unavailable",
                        "message", "Burp HTTP service is not available. Please ensure Burp Suite is fully loaded."
                    ));
                    return;
                }
                
                // Process basic request options (advanced features require newer API)
                Map<String, Object> options = (Map<String, Object>) requestData.get("options");

                // Apply the session cookie jar to the outgoing Cookie header before
                // intercept rules run, so rules and Burp see the final request.
                if (useCookieJar) {
                    httpRequest = applyCookieJar(httpRequest, sessionTag, url, host);
                }

                // Apply request intercept rules before sending (if service exists)
                if (proxyInterceptionService != null) {
                    httpRequest = applyRequestInterceptRules(httpRequest);
                }
                
                // Track timing for basic performance monitoring
                long requestStart = System.currentTimeMillis();
                
                // Send request through Burp (with basic options support)
                burp.api.montoya.http.message.HttpRequestResponse response = httpService.sendRequest(httpRequest);
                
                long requestDuration = System.currentTimeMillis() - requestStart;
                
                // Apply response intercept rules after receiving (if service exists)
                if (proxyInterceptionService != null && response.response() != null) {
                    HttpResponse modifiedResponse = applyResponseInterceptRules(response.response());
                    // Create new HttpRequestResponse with modified response
                    response = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                        response.request(), modifiedResponse
                    );
                }

                // Ingest Set-Cookie into the jar so the next call under this
                // session_tag carries the (possibly rotated) cookies.
                if (useCookieJar && response.response() != null) {
                    cookieJar.update(sessionTag, host, response.response().headers().toString());
                }

                // Follow redirects when requested, carrying/refreshing the cookie
                // jar each hop so a rotating session token stays fresh through the
                // chain. Each intermediate hop is stored under the session tag.
                boolean followRedirects = Boolean.TRUE.equals(requestData.get("follow_redirects"));
                int maxRedirects = parseMaxRedirects(requestData.get("max_redirects"));
                List<Map<String, Object>> redirectTrail = new ArrayList<>();
                int hops = 0;
                while (followRedirects && hops < maxRedirects && response.response() != null
                        && isRedirectStatus(response.response().statusCode())) {
                    String location = response.response().headerValue("Location");
                    if (location == null || location.isBlank()) {
                        break;
                    }
                    String nextUrl = resolveRedirectUrl(url, location);
                    if (nextUrl == null) {
                        break;
                    }
                    int fromStatus = response.response().statusCode();

                    // Store the hop we are leaving before advancing.
                    databaseService.storeRawTrafficWithSource(
                        method, url, host, headers, body,
                        response.response().headers().toString(), response.response().bodyToString(),
                        fromStatus, sessionTag, com.burp2api.logging.TrafficSource.API,
                        httpRequest.httpVersion(), response.response().httpVersion(),
                        com.burp2api.models.TimingData.createBasicTiming(0));
                    redirectTrail.add(Map.of("status_code", fromStatus, "from", url, "location", location));

                    // 301/302/303 to a safe method drop the body; 307/308 preserve.
                    if (fromStatus == 303
                            || ((fromStatus == 301 || fromStatus == 302)
                                && !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method))) {
                        method = "GET";
                        body = "";
                    }
                    // Redirected requests carry only the cookie jar, not caller
                    // headers (avoids forwarding Authorization across origins).
                    url = nextUrl;
                    host = extractHostFromUrl(url);
                    headers = "";
                    httpRequest = burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url)
                        .withMethod(method)
                        .withBody(body);
                    if (useCookieJar) {
                        httpRequest = applyCookieJar(httpRequest, sessionTag, url, host);
                    }
                    if (proxyInterceptionService != null) {
                        httpRequest = applyRequestInterceptRules(httpRequest);
                    }

                    response = httpService.sendRequest(httpRequest);
                    if (proxyInterceptionService != null && response.response() != null) {
                        response = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                            response.request(), applyResponseInterceptRules(response.response()));
                    }
                    if (useCookieJar && response.response() != null) {
                        cookieJar.update(sessionTag, host, response.response().headers().toString());
                    }
                    hops++;
                }

                // Store the request and response using normalized schema with timing data
                String requestHttpVersion = httpRequest.httpVersion();
                String responseHttpVersion = response.response().httpVersion();
                
                // Create basic timing data with measured duration
                com.burp2api.models.TimingData timingData = com.burp2api.models.TimingData.createBasicTiming(requestDuration);
                
                long recordId = databaseService.storeRawTrafficWithSource(
                    method, url, host, headers, body,
                    response.response().headers().toString(), response.response().bodyToString(),
                    (int) response.response().statusCode(), sessionTag,
                    com.burp2api.logging.TrafficSource.API, requestHttpVersion, responseHttpVersion,
                    timingData
                );

                // #24: byte-exact wire bytes for the stored row (evidence source).
                if (recordId > 0) {
                    databaseService.setRawBytes(recordId,
                        response.request() != null ? response.request().toByteArray().getBytes() : null,
                        response.response() != null ? response.response().toByteArray().getBytes() : null);
                }

                // Return response data with enhanced information. The body is
                // encoded from the raw response bytes so a UTF-8 body (control
                // chars included) stays readable text while a binary/non-UTF-8
                // body is Base64-encoded rather than corrupted; body_encoding
                // discriminates the two.
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("request_id", recordId);
                BodyCodec.EncodedBody sendBody =
                    BodyCodec.encodeBytes(response.response().body().getBytes());
                Map<String, Object> responseBlock = new HashMap<>();
                responseBlock.put("status_code", response.response().statusCode());
                responseBlock.put("headers", response.response().headers().toString());
                // Structured headers so clients read individual fields (and
                // multi-value headers like Set-Cookie) without re-parsing the blob.
                responseBlock.put("headers_list", HeaderList.fromMontoya(response.response().headers()));
                BodyCodec.putEncoded(responseBlock, "body", "body_encoding", sendBody);
                responseBlock.put("length", response.response().body().length());
                responseBlock.put("http_version", responseHttpVersion);
                responseData.put("response", responseBlock);
                
                // Include timing data if available
                if (timingData != null && timingData.hasAnyTiming()) {
                    Map<String, Object> timingInfo = new HashMap<>();
                    if (timingData.getDnsResolutionTime() != null) {
                        timingInfo.put("dns_resolution_time", timingData.getDnsResolutionTime());
                    }
                    if (timingData.getConnectionTime() != null) {
                        timingInfo.put("connection_time", timingData.getConnectionTime());
                    }
                    if (timingData.getTlsNegotiationTime() != null) {
                        timingInfo.put("tls_negotiation_time", timingData.getTlsNegotiationTime());
                    }
                    if (timingData.getRequestTime() != null) {
                        timingInfo.put("request_time", timingData.getRequestTime());
                    }
                    if (timingData.getResponseTime() != null) {
                        timingInfo.put("response_time", timingData.getResponseTime());
                    }
                    if (timingData.getTotalTime() != null) {
                        timingInfo.put("total_time", timingData.getTotalTime());
                    }
                    responseData.put("timing", timingInfo);
                } else {
                    responseData.put("timing", Map.of("timestamp", System.currentTimeMillis()));
                }
                
                // Include request options used
                if (options != null && !options.isEmpty()) {
                    responseData.put("request_options", options);
                }
                
                // Include protocol information
                responseData.put("protocol_info", Map.of(
                    "request_http_version", requestHttpVersion,
                    "response_http_version", responseHttpVersion
                ));

                // Echo the effective cookie jar mode for observability.
                responseData.put("cookie_jar", cookieJarMode);

                // Include the redirect trail when redirects were followed.
                if (followRedirects && !redirectTrail.isEmpty()) {
                    responseData.put("redirects", redirectTrail);
                }

                ctx.json(responseData);
                
            } catch (Exception e) {
                logger.error("Failed to send/replay request", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to send request",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Upload endpoint for HAR files and raw HTTP logs
        app.post("/proxy/upload", ctx -> {
            try {
                String contentType = ctx.contentType();
                String sessionTag = ctx.queryParam("session_tag");
                if (sessionTag == null) {
                    sessionTag = config.getSessionTag() + "_upload_" + System.currentTimeMillis();
                }
                
                String uploadData = ctx.body();
                
                // Handle JSON wrapper format for API compatibility
                if (contentType != null && contentType.contains("application/json") && uploadData.contains("\"data\"")) {
                    try {
                        Map<String, Object> jsonBody = objectMapper.readValue(uploadData, Map.class);
                        if (jsonBody.containsKey("data")) {
                            uploadData = (String) jsonBody.get("data");
                        }
                    } catch (Exception e) {
                        // If JSON parsing fails, use raw data
                    }
                }
                
                // Fix double-escaped line endings from API clients
                if (uploadData.contains("\\\\r\\\\n")) {
                    uploadData = uploadData.replace("\\\\r\\\\n", "\r\n");
                }
                if (uploadData.contains("\\r\\n")) {
                    uploadData = uploadData.replace("\\r\\n", "\n");
                }
                
                if (uploadData.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Empty upload data",
                        "message", "Please provide HAR file content or raw HTTP logs"
                    ));
                    return;
                }
                
                int recordsImported = 0;
                List<String> errors = new ArrayList<>();
                
                // Determine upload type and parse accordingly
                // Check if it's actually HAR content (starts with { and has log property)
                if (uploadData.trim().startsWith("{") && uploadData.contains("\"log\"")) {
                    // Try to parse as HAR file
                    recordsImported = parseAndStoreHarData(uploadData, sessionTag, errors);
                } else {
                    // Parse as raw HTTP logs
                    recordsImported = parseAndStoreRawHttpLogs(uploadData, sessionTag, errors);
                }
                
                Map<String, Object> result = new HashMap<>();
                result.put("records_imported", recordsImported);
                result.put("session_tag", sessionTag);
                result.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                    result.put("partial_success", true);
                }
                
                if (recordsImported > 0) {
                    ctx.json(result);
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "No valid records found",
                        "message", "Could not parse any valid HTTP requests from the uploaded data",
                        "errors", errors
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to process upload", e);
                ctx.status(500).json(Map.of(
                    "error", "Upload processing failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Import existing proxy history from current Burp project
        app.post("/proxy/import-history", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                String sessionTag = ctx.queryParam("session_tag");
                if (sessionTag == null) {
                    sessionTag = config.getSessionTag() + "_imported_" + System.currentTimeMillis();
                }
                
                int importedCount = databaseService.importExistingProxyHistory(api, sessionTag);
                
                Map<String, Object> result = new HashMap<>();
                result.put("operation", "import_proxy_history");
                result.put("records_imported", importedCount);
                result.put("session_tag", sessionTag);
                result.put("timestamp", System.currentTimeMillis());
                
                if (importedCount > 0) {
                    result.put("message", String.format("Successfully imported %d proxy history records", importedCount));
                    ctx.json(result);
                } else {
                    result.put("message", "No proxy history found in current project to import");
                    ctx.json(result);
                }
                
            } catch (Exception e) {
                logger.error("Failed to import proxy history", e);
                ctx.status(500).json(Map.of(
                    "error", "Import failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Tag traffic records (restored functionality)
        app.post("/proxy/tag", ctx -> {
            try {
                // Skip database check for now
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                Object requestIdObj = requestData.get("request_id");
                Object tagsObj = requestData.get("tags");
                
                if (requestIdObj == null) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing request_id",
                        "message", "request_id is required"
                    ));
                    return;
                }
                
                long requestId = requestIdObj instanceof Number 
                    ? ((Number) requestIdObj).longValue() 
                    : Long.parseLong(requestIdObj.toString());
                
                // Handle tags as either string or array
                String tags;
                if (tagsObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> tagsList = (List<String>) tagsObj;
                    tags = String.join(",", tagsList);
                } else {
                    tags = tagsObj != null ? tagsObj.toString() : "";
                }
                
                // The annotation must land on the request the client is looking at.
                // Resolve through traffic_meta.proxy_traffic_id, the exact link to
                // the public id space, not the raw id -- those counters drift (#21).
                if (rejectUnknownTrafficId(ctx, requestId)) {
                    return;
                }
                if (databaseService.ensureTrafficMetaForProxyId(requestId) <= 0) {
                    ctx.status(500).json(Map.of(
                        "success", false,
                        "request_id", requestId,
                        "tags", tags,
                        "message", "Could not create traffic metadata record"
                    ));
                    return;
                }

                // Try to update database
                boolean success = databaseService.updateTrafficTags(requestId, tags);
                
                ctx.json(Map.of(
                    "success", success,
                    "request_id", requestId,
                    "tags", tags,
                    "message", success ? "Tags updated successfully" : "Failed to update tags"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to update traffic tags", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to update tags",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Add comment to traffic record (full functionality restored)
        app.post("/proxy/comment", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                Object requestIdObj = requestData.get("request_id");
                String comment = (String) requestData.get("comment");
                
                if (requestIdObj == null) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing request_id",
                        "message", "request_id is required"
                    ));
                    return;
                }
                
                long requestId = requestIdObj instanceof Number 
                    ? ((Number) requestIdObj).longValue() 
                    : Long.parseLong(requestIdObj.toString());
                
                // Resolve through the public id link, same as /proxy/tag (#21).
                if (rejectUnknownTrafficId(ctx, requestId)) {
                    return;
                }
                if (databaseService.ensureTrafficMetaForProxyId(requestId) <= 0) {
                    ctx.status(500).json(Map.of(
                        "success", false,
                        "request_id", requestId,
                        "comment", comment != null ? comment : "",
                        "message", "Could not create traffic metadata record"
                    ));
                    return;
                }

                boolean success = databaseService.updateTrafficComment(requestId, comment);
                
                ctx.json(Map.of(
                    "success", success,
                    "request_id", requestId,
                    "comment", comment != null ? comment : "",
                    "message", success ? "Comment updated successfully" : "Failed to update comment"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to update traffic comment", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to update comment",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Get all tagged records
        app.get("/proxy/tags", ctx -> {
            try {
                String sessionTag = ctx.queryParam("session_tag");
                String sql = "SELECT tm.id, tm.proxy_traffic_id, tm.url, tm.method, tm.host, tm.tags, tm.timestamp, tm.session_tag " +
                           "FROM traffic_meta tm WHERE tm.tags IS NOT NULL AND tm.tags != '' ";

                if (sessionTag != null) {
                    sql += "AND tm.session_tag = ? ";
                }
                sql += "ORDER BY tm.timestamp DESC";

                List<Map<String, Object>> taggedRecords = new ArrayList<>();
                try (Connection conn = databaseService.getConnection();
                     PreparedStatement stmt = conn.prepareStatement(sql)) {

                    if (sessionTag != null) {
                        stmt.setString(1, sessionTag);
                    }

                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String, Object> record = new HashMap<>();
                            // `id` is the public proxy_traffic.id so it round-trips to
                            // /proxy/tag, /proxy/search and /proxy/replay; traffic_meta_id
                            // stays visible (#21).
                            long resolvedId = rs.getLong("proxy_traffic_id");
                            record.put("id", rs.wasNull() ? null : resolvedId);
                            record.put("traffic_meta_id", rs.getLong("id"));
                            record.put("url", rs.getString("url"));
                            record.put("method", rs.getString("method"));
                            record.put("host", rs.getString("host"));
                            record.put("tags", rs.getString("tags"));
                            record.put("timestamp", rs.getLong("timestamp"));
                            record.put("session_tag", rs.getString("session_tag"));
                            taggedRecords.add(record);
                        }
                    }
                }
                
                ctx.json(Map.of(
                    "tagged_records", taggedRecords,
                    "count", taggedRecords.size(),
                    "session_filter", sessionTag != null ? sessionTag : "all",
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                logger.error("Failed to retrieve tagged records", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve tagged records",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Get all commented records
        app.get("/proxy/comments", ctx -> {
            try {
                String sessionTag = ctx.queryParam("session_tag");
                String sql = "SELECT tm.id, tm.proxy_traffic_id, tm.url, tm.method, tm.host, tm.comment, tm.timestamp, tm.session_tag " +
                           "FROM traffic_meta tm WHERE tm.comment IS NOT NULL AND tm.comment != '' ";

                if (sessionTag != null) {
                    sql += "AND tm.session_tag = ? ";
                }
                sql += "ORDER BY tm.timestamp DESC";

                List<Map<String, Object>> commentedRecords = new ArrayList<>();
                try (Connection conn = databaseService.getConnection();
                     PreparedStatement stmt = conn.prepareStatement(sql)) {

                    if (sessionTag != null) {
                        stmt.setString(1, sessionTag);
                    }

                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String, Object> record = new HashMap<>();
                            // Public proxy_traffic.id, matching /proxy/tags (#21).
                            long resolvedId = rs.getLong("proxy_traffic_id");
                            record.put("id", rs.wasNull() ? null : resolvedId);
                            record.put("traffic_meta_id", rs.getLong("id"));
                            record.put("url", rs.getString("url"));
                            record.put("method", rs.getString("method"));
                            record.put("host", rs.getString("host"));
                            record.put("comment", rs.getString("comment"));
                            record.put("timestamp", rs.getLong("timestamp"));
                            record.put("session_tag", rs.getString("session_tag"));
                            commentedRecords.add(record);
                        }
                    }
                }
                
                ctx.json(Map.of(
                    "commented_records", commentedRecords,
                    "count", commentedRecords.size(),
                    "session_filter", sessionTag != null ? sessionTag : "all",
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                logger.error("Failed to retrieve commented records", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve commented records",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Search tagged/commented records (simpler dedicated endpoint)
        app.get("/proxy/search/metadata", ctx -> {
            try {
                String tags = ctx.queryParam("tags");
                String comment = ctx.queryParam("comment");
                String hasTagsParam = ctx.queryParam("has_tags");
                String hasCommentsParam = ctx.queryParam("has_comments");
                String sessionTag = ctx.queryParam("session_tag");
                String limitParam = ctx.queryParam("limit");
                int limit = Math.min(Integer.parseInt(limitParam != null ? limitParam : "20"), 1000);
                
                StringBuilder sql = new StringBuilder(
                    "SELECT p.id, p.timestamp, p.method, p.url, p.host, p.status_code, " +
                    "p.headers, p.body, p.response_headers, p.response_body, p.session_tag, " +
                    "tm.tags, tm.comment " +
                    "FROM proxy_traffic p " +
                    // Join on the exact link, not the raw id -- the two counters
                    // drift, so p.id = tm.id paired unrelated requests (#21).
                    "INNER JOIN traffic_meta tm ON p.id = tm.proxy_traffic_id " +
                    "WHERE 1=1 "
                );
                
                List<Object> params = new ArrayList<>();
                
                // Add filters
                if (tags != null && !tags.isEmpty()) {
                    if (tags.contains(",")) {
                        String[] tagArray = tags.split(",");
                        sql.append("AND (");
                        for (int i = 0; i < tagArray.length; i++) {
                            if (i > 0) sql.append(" OR ");
                            sql.append("tm.tags LIKE ?");
                            params.add("%" + tagArray[i].trim() + "%");
                        }
                        sql.append(") ");
                    } else {
                        sql.append("AND tm.tags LIKE ? ");
                        params.add("%" + tags + "%");
                    }
                }
                
                if ("true".equalsIgnoreCase(hasTagsParam)) {
                    sql.append("AND tm.tags IS NOT NULL AND tm.tags != '' ");
                }
                
                if ("true".equalsIgnoreCase(hasCommentsParam)) {
                    sql.append("AND tm.comment IS NOT NULL AND tm.comment != '' ");
                }
                
                if (comment != null && !comment.isEmpty()) {
                    sql.append("AND tm.comment LIKE ? ");
                    params.add("%" + comment + "%");
                }
                
                if (sessionTag != null && !sessionTag.isEmpty()) {
                    sql.append("AND p.session_tag = ? ");
                    params.add(sessionTag);
                }
                
                sql.append("ORDER BY p.timestamp DESC LIMIT ?");
                params.add(limit);
                
                List<Map<String, Object>> results = new ArrayList<>();
                try (Connection conn = databaseService.getConnection();
                     PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
                    
                    for (int i = 0; i < params.size(); i++) {
                        stmt.setObject(i + 1, params.get(i));
                    }
                    
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String, Object> record = new HashMap<>();
                            record.put("id", rs.getLong("id"));
                            record.put("timestamp", rs.getLong("timestamp"));
                            record.put("method", rs.getString("method"));
                            record.put("url", rs.getString("url"));
                            record.put("host", rs.getString("host"));
                            record.put("status_code", rs.getInt("status_code"));
                            record.put("headers", rs.getString("headers"));
                            record.put("body", rs.getString("body"));
                            record.put("response_headers", rs.getString("response_headers"));
                            record.put("response_body", rs.getString("response_body"));
                            record.put("session_tag", rs.getString("session_tag"));
                            record.put("tags", rs.getString("tags"));
                            record.put("comment", rs.getString("comment"));
                            results.add(record);
                        }
                    }
                }
                
                ctx.json(Map.of(
                    "results", results,
                    "count", results.size(),
                    "filters", Map.of(
                        "tags", tags != null ? tags : "",
                        "comment", comment != null ? comment : "",
                        "has_tags", hasTagsParam != null ? hasTagsParam : "",
                        "has_comments", hasCommentsParam != null ? hasCommentsParam : "",
                        "session_tag", sessionTag != null ? sessionTag : "",
                        "limit", limit
                    ),
                    "endpoint", "metadata_search",
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                logger.error("Failed to search metadata", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to search tagged/commented records",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Delete/purge endpoint
        app.delete("/proxy/delete", ctx -> {
            try {
                String sessionTag = ctx.queryParam("session_tag");
                String deleteAll = ctx.queryParam("all");
                String startTime = ctx.queryParam("start_time");
                String endTime = ctx.queryParam("end_time");
                
                int deletedCount = 0;
                Map<String, Object> result = new HashMap<>();
                
                if ("true".equalsIgnoreCase(deleteAll)) {
                    // Delete all records
                    deletedCount = databaseService.deleteAllTraffic();
                    result.put("operation", "delete_all");
                } else if (sessionTag != null) {
                    // Delete by session tag
                    deletedCount = databaseService.deleteTrafficBySessionTag(sessionTag);
                    result.put("operation", "delete_by_session_tag");
                    result.put("session_tag", sessionTag);
                } else if (startTime != null || endTime != null) {
                    // Delete by time range
                    deletedCount = databaseService.deleteTrafficByTimeRange(startTime, endTime);
                    result.put("operation", "delete_by_time_range");
                    result.put("start_time", startTime);
                    result.put("end_time", endTime);
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid delete operation",
                        "message", "Must specify either 'all=true', 'session_tag', or time range ('start_time'/'end_time')",
                        "examples", List.of(
                            "?all=true",
                            "?session_tag=my_session",
                            "?start_time=2024-01-01T00:00:00&end_time=2024-01-02T00:00:00"
                        )
                    ));
                    return;
                }
                
                result.put("deleted_count", deletedCount);
                result.put("timestamp", System.currentTimeMillis());
                
                ctx.json(result);
                
            } catch (Exception e) {
                logger.error("Failed to delete traffic records", e);
                ctx.status(500).json(Map.of(
                    "error", "Delete operation failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Replay matched results from a search
        app.post("/proxy/replay-matched", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Extract search parameters or record IDs
                Map<String, String> searchParams = new HashMap<>();
                List<Long> recordIds = new ArrayList<>();
                
                if (requestData.containsKey("search_params")) {
                    Map<String, Object> searchParamsObj = (Map<String, Object>) requestData.get("search_params");
                    for (Map.Entry<String, Object> entry : searchParamsObj.entrySet()) {
                        searchParams.put(entry.getKey(), entry.getValue().toString());
                    }
                } else if (requestData.containsKey("record_ids")) {
                    List<Object> ids = (List<Object>) requestData.get("record_ids");
                    for (Object id : ids) {
                        recordIds.add(Long.valueOf(id.toString()));
                    }
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing replay criteria",
                        "message", "Must provide either 'search_params' or 'record_ids'",
                        "examples", Map.of(
                            "search_params", Map.of("host", "example.com", "method", "GET"),
                            "record_ids", List.of(1, 2, 3)
                        )
                    ));
                    return;
                }
                
                String sessionTag = (String) requestData.getOrDefault("session_tag", 
                    config.getSessionTag() + "_replay_" + System.currentTimeMillis());
                
                List<Map<String, Object>> results = new ArrayList<>();
                List<Map<String, Object>> errors = new ArrayList<>();
                
                // Get records to replay
                List<Map<String, Object>> recordsToReplay;
                if (!searchParams.isEmpty()) {
                    // Remove pagination for replay (get all matches)
                    searchParams.remove("limit");
                    searchParams.remove("offset");
                    recordsToReplay = databaseService.searchTraffic(searchParams);
                } else {
                    // Get specific records by ID
                    recordsToReplay = new ArrayList<>();
                    for (Long id : recordIds) {
                        Map<String, Object> record = databaseService.getTrafficById(id);
                        if (record != null) {
                            recordsToReplay.add(record);
                        }
                    }
                }
                
                // Replay each record
                for (Map<String, Object> record : recordsToReplay) {
                    try {
                        String method = (String) record.get("method");
                        String url = (String) record.get("url");
                        String headers = (String) record.get("headers");
                        String body = (String) record.get("body");
                        
                        // Create HTTP request
                        burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
                            burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url)
                                .withMethod(method)
                                .withBody(body != null ? body : "");
                        
                        // Check if Burp API and HTTP service are available
                        if (api == null) {
                            logger.error("Burp API is not available for replay-matched. Skipping request.");
                            continue; // Skip this request and continue with next one
                        }
                        
                        var httpService = api.http();
                        if (httpService == null) {
                            logger.error("Burp HTTP service is not available for replay-matched. Skipping request.");
                            continue; // Skip this request and continue with next one
                        }
                        
                        // Send request
                        burp.api.montoya.http.message.HttpRequestResponse response = 
                            httpService.sendRequest(httpRequest);
                        
                        // Store the replayed request and response
                        long replayId = databaseService.storeRawTraffic(
                            method, url, (String) record.get("host"), headers, body,
                            response.response().headers().toString(), response.response().bodyToString(),
                            (int) response.response().statusCode(), sessionTag
                        );
                        
                        Map<String, Object> replayResult = new HashMap<>();
                        replayResult.put("original_id", record.get("id"));
                        replayResult.put("replay_id", replayId);
                        replayResult.put("method", method);
                        replayResult.put("url", url);
                        replayResult.put("status_code", response.response().statusCode());
                        replayResult.put("response_length", response.response().body().length());
                        
                        results.add(replayResult);
                        
                    } catch (Exception e) {
                        logger.error("Failed to replay record {}", record.get("id"), e);
                        Map<String, Object> error = new HashMap<>();
                        error.put("record_id", record.get("id"));
                        error.put("error", e.getMessage());
                        errors.add(error);
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("replayed_count", results.size());
                response.put("total_requested", recordsToReplay.size());
                response.put("session_tag", sessionTag);
                response.put("results", results);
                response.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to replay matched records", e);
                ctx.status(500).json(Map.of(
                    "error", "Replay operation failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Dedicated hosts endpoint for complete host list
        app.get("/proxy/hosts", ctx -> {
            try {
                if (!checkDatabaseAvailable(ctx)) return;
                
                Map<String, String> searchParams = extractSearchParams(ctx);
                // Force getting all hosts by setting all_hosts=true
                searchParams.put("all_hosts", "true");
                
                Map<String, Object> stats = databaseService.getTrafficStats(searchParams);
                List<Map<String, Object>> hostsList = (List<Map<String, Object>>) stats.get("by_host");
                
                // Convert list to map format for easier consumption
                Map<String, Object> hosts = new HashMap<>();
                if (hostsList != null) {
                    for (Map<String, Object> hostStat : hostsList) {
                        String host = (String) hostStat.get("host");
                        Object count = hostStat.get("count");
                        if (host != null) {
                            hosts.put(host, count);
                        }
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("hosts", hosts);
                response.put("total_hosts", hosts.size());
                response.put("filters", searchParams);
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
            } catch (Exception e) {
                logger.error("Failed to get hosts list", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve hosts",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Bonus Feature: Traffic statistics endpoint
        app.get("/proxy/stats", ctx -> {
            try {
                Map<String, String> searchParams = extractSearchParams(ctx);
                Map<String, Object> stats = databaseService.getTrafficStats(searchParams);
                
                Map<String, Object> response = new HashMap<>();
                response.put("statistics", stats);
                response.put("filters", searchParams);
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to get traffic statistics", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get statistics",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Bonus Feature: Traffic timeline endpoint
        app.get("/proxy/timeline", ctx -> {
            try {
                Map<String, String> searchParams = extractSearchParams(ctx);
                String interval = ctx.queryParam("interval");
                if (interval == null) {
                    interval = "hour"; // Default to hourly grouping
                }
                
                // Validate interval parameter
                if (!interval.matches("(?i)(minute|hour|day)")) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid interval",
                        "message", "Interval must be 'minute', 'hour', or 'day'",
                        "supported_intervals", List.of("minute", "hour", "day")
                    ));
                    return;
                }
                
                List<Map<String, Object>> timeline = databaseService.getTrafficTimeline(searchParams, interval);
                
                Map<String, Object> response = new HashMap<>();
                response.put("timeline", timeline);
                response.put("interval", interval);
                response.put("filters", searchParams);
                response.put("count", timeline.size());
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to get traffic timeline", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get timeline",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Bonus Feature: HAR export endpoint
        app.get("/proxy/har-export", ctx -> {
            try {
                Map<String, String> searchParams = extractSearchParams(ctx);
                
                // Remove pagination for export - get all matching records
                searchParams.remove("offset");
                
                // Apply reasonable limit for HAR export to prevent memory issues
                if (!searchParams.containsKey("limit")) {
                    searchParams.put("limit", "1000"); // Default limit for HAR export
                }
                
                List<Map<String, Object>> trafficData = databaseService.getTrafficForHarExport(searchParams);
                
                // Generate HAR format
                Map<String, Object> har = generateHarFormat(trafficData);
                
                // Set headers for file download
                String filename = "proxy_traffic_" + System.currentTimeMillis() + ".har";
                ctx.header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
                ctx.contentType("application/json");
                
                ctx.result(objectMapper.writeValueAsString(har));
                
            } catch (Exception e) {
                logger.error("Failed to export HAR file", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to export HAR",
                    "message", e.getMessage()
                ));
            }
        });
    }
    
    /**
     * Registers scope-related routes.
     */
    private void registerScopeRoutes(Javalin app) {
        //  Get current scope - Now enhanced with actual project scope data
        app.get("/scope/current", ctx -> {
            try {
                Map<String, Object> response = new HashMap<>();
                
                // Get the actual project scope configuration from Burp
                try {
                    // Export the full project configuration and extract scope from target.scope
                    String projectConfigJson = api.burpSuite().exportProjectOptionsAsJson();
                    
                    // Parse the JSON to extract scope information
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode projectConfig = mapper.readTree(projectConfigJson);
                    JsonNode scopeConfig = projectConfig.path("target").path("scope");
                    
                    if (!scopeConfig.isMissingNode()) {
                        response.put("scope_configuration", scopeConfig);
                        response.put("source", "current_project_file");
                        
                        // Extract and format scope rules for easier consumption
                        Map<String, Object> scopeSummary = new HashMap<>();
                        JsonNode includeInScope = scopeConfig.path("include");
                        JsonNode excludeFromScope = scopeConfig.path("exclude");
                        
                        if (!includeInScope.isMissingNode() && includeInScope.isArray()) {
                            List<Map<String, Object>> includeRules = new ArrayList<>();
                            for (JsonNode rule : includeInScope) {
                                Map<String, Object> ruleMap = new HashMap<>();
                                ruleMap.put("enabled", rule.path("enabled").asBoolean());
                                ruleMap.put("prefix", rule.path("prefix").asText());
                                ruleMap.put("include_subdomains", rule.path("include_subdomains").asBoolean());
                                // Handle legacy format compatibility
                                if (rule.has("file")) ruleMap.put("file", rule.path("file").asText());
                                if (rule.has("host")) ruleMap.put("host", rule.path("host").asText());
                                if (rule.has("port")) ruleMap.put("port", rule.path("port").asText());
                                if (rule.has("protocol")) ruleMap.put("protocol", rule.path("protocol").asText());
                                includeRules.add(ruleMap);
                            }
                            scopeSummary.put("include_rules", includeRules);
                            scopeSummary.put("include_count", includeRules.size());
                        }
                        
                        if (!excludeFromScope.isMissingNode() && excludeFromScope.isArray()) {
                            List<Map<String, Object>> excludeRules = new ArrayList<>();
                            for (JsonNode rule : excludeFromScope) {
                                Map<String, Object> ruleMap = new HashMap<>();
                                ruleMap.put("enabled", rule.path("enabled").asBoolean());
                                ruleMap.put("prefix", rule.path("prefix").asText());
                                ruleMap.put("include_subdomains", rule.path("include_subdomains").asBoolean());
                                // Handle legacy format compatibility
                                if (rule.has("file")) ruleMap.put("file", rule.path("file").asText());
                                if (rule.has("host")) ruleMap.put("host", rule.path("host").asText());
                                if (rule.has("port")) ruleMap.put("port", rule.path("port").asText());
                                if (rule.has("protocol")) ruleMap.put("protocol", rule.path("protocol").asText());
                                excludeRules.add(ruleMap);
                            }
                            scopeSummary.put("exclude_rules", excludeRules);
                            scopeSummary.put("exclude_count", excludeRules.size());
                        }
                        
                        // Add advanced mode info
                        scopeSummary.put("advanced_mode", scopeConfig.path("advanced_mode").asBoolean());
                        
                        response.put("scope_summary", scopeSummary);
                        
                    } else {
                        response.put("scope_configuration", null);
                        response.put("message", "No scope configuration found in current project");
                    }
                    
                } catch (Exception scopeError) {
                    logger.warn("Failed to read project scope configuration: {}", scopeError.getMessage());
                    response.put("scope_configuration", null);
                    response.put("error", "Failed to read project scope: " + scopeError.getMessage());
                }
                
                // Add API capabilities information
                response.put("api_capabilities", Map.of(
                    "can_read_project_scope", true,
                    "can_check_individual_urls", true,
                    "can_add_to_scope", true,
                    "can_exclude_from_scope", true,
                    "can_enumerate_all_rules", true
                ));
                
                response.put("available_endpoints", List.of(
                    "POST /scope/exclude - Add URLs to exclusion",
                    "POST /scope/import - Add URLs to scope",  
                    "GET /scope/check?url=<url> - Check if URL is in scope",
                    "GET /scope/current - Get current project scope configuration",
                    "GET /scope/project-config - Export full project configuration or specific sections (optional: sections=target.scope,project_options.connections)",
                    "POST /scope/project-config - Import project options (e.g. a resource-pool template to throttle scans on low memory)"
                ));
                response.put("timestamp", System.currentTimeMillis());

                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to get current scope", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve scope",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Check if URL is in scope
        app.get("/scope/check", ctx -> {
            try {
                String url = ctx.queryParam("url");
                if (url == null || url.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing URL parameter",
                        "message", "Please provide a URL to check",
                        "example", "/scope/check?url=https://example.com/test"
                    ));
                    return;
                }
                
                boolean inScope = api.scope().isInScope(url);
                
                Map<String, Object> response = new HashMap<>();
                response.put("url", url);
                response.put("in_scope", inScope);
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to check scope for URL", e);
                ctx.status(500).json(Map.of(
                    "error", "Scope check failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Exclude URLs from scope
        app.post("/scope/exclude", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                List<String> urlsToExclude = new ArrayList<>();
                
                // Handle single URL or list of URLs
                if (requestData.containsKey("url")) {
                    urlsToExclude.add((String) requestData.get("url"));
                } else if (requestData.containsKey("urls")) {
                    List<Object> urls = (List<Object>) requestData.get("urls");
                    for (Object url : urls) {
                        urlsToExclude.add(url.toString());
                    }
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing URL data",
                        "message", "Must provide either 'url' or 'urls' parameter",
                        "examples", Map.of(
                            "single_url", Map.of("url", "https://example.com/admin/*"),
                            "multiple_urls", Map.of("urls", List.of("https://example.com/login", "https://example.com/logout"))
                        )
                    ));
                    return;
                }
                
                List<String> excludedUrls = new ArrayList<>();
                List<String> errors = new ArrayList<>();
                
                // Add each URL to exclusion rules
                for (String url : urlsToExclude) {
                    try {
                        api.scope().excludeFromScope(url);
                        excludedUrls.add(url);
                        logger.info("Added URL to exclusion scope: {}", url);
                    } catch (Exception e) {
                        logger.error("Failed to exclude URL from scope: {}", url, e);
                        errors.add("Failed to exclude '" + url + "': " + e.getMessage());
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("excluded_count", excludedUrls.size());
                response.put("excluded_urls", excludedUrls);
                response.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                    response.put("partial_success", true);
                }
                
                if (excludedUrls.isEmpty()) {
                    ctx.status(400).json(response);
                } else {
                    ctx.json(response);
                }
                
            } catch (Exception e) {
                logger.error("Failed to exclude URLs from scope", e);
                ctx.status(500).json(Map.of(
                    "error", "Scope exclusion failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        
        //  Import URLs to scope
        app.post("/scope/import", ctx -> {
            try {
                String contentType = ctx.contentType();
                String body = ctx.body();
                
                if (body.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Empty request body",
                        "message", "Please provide URLs in JSON format or as plain text list"
                    ));
                    return;
                }
                
                String sessionTag = ctx.queryParam("session_tag");
                String scopeType = ctx.queryParam("type");
                if (scopeType == null) {
                    scopeType = "include"; // Default to include
                }
                
                if (!"include".equals(scopeType) && !"exclude".equals(scopeType)) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid scope type",
                        "message", "Scope type must be 'include' or 'exclude'",
                        "received", scopeType
                    ));
                    return;
                }
                
                List<String> urlsToImport = new ArrayList<>();
                
                // Parse input based on content type
                if (contentType != null && contentType.contains("application/json") || body.trim().startsWith("{") || body.trim().startsWith("[")) {
                    // Parse as JSON
                    try {
                        if (body.trim().startsWith("[")) {
                            // Array of URLs
                            List<Object> urls = objectMapper.readValue(body, List.class);
                            for (Object url : urls) {
                                urlsToImport.add(url.toString());
                            }
                        } else {
                            // Object with URLs array
                            Map<String, Object> data = objectMapper.readValue(body, Map.class);
                            if (data.containsKey("urls")) {
                                List<Object> urls = (List<Object>) data.get("urls");
                                for (Object url : urls) {
                                    urlsToImport.add(url.toString());
                                }
                            } else {
                                ctx.status(400).json(Map.of(
                                    "error", "Invalid JSON format",
                                    "message", "JSON object must contain 'urls' array",
                                    "example", Map.of("urls", List.of("https://example.com/*", "https://test.com/api/*"))
                                ));
                                return;
                            }
                        }
                    } catch (Exception e) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid JSON",
                            "message", "Failed to parse JSON: " + e.getMessage()
                        ));
                        return;
                    }
                } else {
                    // Parse as plain text (one URL per line)
                    String[] lines = body.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) { // Skip empty lines and comments
                            urlsToImport.add(line);
                        }
                    }
                }
                
                if (urlsToImport.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "No URLs found",
                        "message", "No valid URLs found in the input data"
                    ));
                    return;
                }
                
                List<String> addedUrls = new ArrayList<>();
                List<String> errors = new ArrayList<>();
                
                // Add each URL to scope
                for (String url : urlsToImport) {
                    try {
                        if ("include".equals(scopeType)) {
                            api.scope().includeInScope(url);
                        } else if ("exclude".equals(scopeType)) {
                            api.scope().excludeFromScope(url);
                        }
                        
                        addedUrls.add(url);
                        logger.info("Added URL to {} scope: {}", scopeType, url);
                        
                        // Store in database if session tag provided
                        if (sessionTag != null) {
                            databaseService.storeRawTraffic(
                                "SCOPE_IMPORT", url, extractHostFromUrl(url), 
                                "Scope-Type: " + scopeType, "",
                                "", "", null, sessionTag
                            );
                        }
                        
                    } catch (Exception e) {
                        logger.error("Failed to add URL to {} scope: {}", scopeType, url, e);
                        errors.add("Failed to add '" + url + "': " + e.getMessage());
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("imported_count", addedUrls.size());
                response.put("imported_urls", addedUrls);
                response.put("scope_type", scopeType);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                    response.put("partial_success", true);
                }
                
                if (addedUrls.isEmpty()) {
                    ctx.status(400).json(response);
                } else {
                    ctx.json(response);
                }
                
            } catch (Exception e) {
                logger.error("Failed to import URLs to scope", e);
                ctx.status(500).json(Map.of(
                    "error", "Scope import failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Reset scope - Clear all include/exclude rules using proper Montoya API
        app.post("/scope/reset", ctx -> {
            try {
                Map<String, Object> response = new HashMap<>();
                List<String> clearedIncludes = new ArrayList<>();
                List<String> clearedExcludes = new ArrayList<>();
                List<String> errors = new ArrayList<>();
                
                // Get current scope configuration from project
                try {
                    String projectConfigJson = api.burpSuite().exportProjectOptionsAsJson();
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode projectConfig = mapper.readTree(projectConfigJson);
                    JsonNode scopeConfig = projectConfig.path("target").path("scope");
                    
                    if (!scopeConfig.isMissingNode()) {
                        // Process include rules - exclude them to clear
                        JsonNode includeRules = scopeConfig.path("include");
                        if (includeRules.isArray()) {
                            for (JsonNode includeRule : includeRules) {
                                if (includeRule.path("enabled").asBoolean(true)) {
                                    String prefix = includeRule.path("prefix").asText();
                                    if (!prefix.isEmpty()) {
                                        try {
                                            api.scope().excludeFromScope(prefix);
                                            clearedIncludes.add(prefix);
                                            logger.info("Cleared include rule: {}", prefix);
                                        } catch (Exception e) {
                                            errors.add("Failed to clear include rule " + prefix + ": " + e.getMessage());
                                            logger.error("Failed to clear include rule: {}", prefix, e);
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Process exclude rules - include them to remove exclusions
                        JsonNode excludeRules = scopeConfig.path("exclude");
                        if (excludeRules.isArray()) {
                            for (JsonNode excludeRule : excludeRules) {
                                if (excludeRule.path("enabled").asBoolean(true)) {
                                    String prefix = excludeRule.path("prefix").asText();
                                    if (!prefix.isEmpty()) {
                                        try {
                                            api.scope().includeInScope(prefix);
                                            clearedExcludes.add(prefix);
                                            logger.info("Cleared exclude rule: {}", prefix);
                                        } catch (Exception e) {
                                            errors.add("Failed to clear exclude rule " + prefix + ": " + e.getMessage());
                                            logger.error("Failed to clear exclude rule: {}", prefix, e);
                                        }
                                    }
                                }
                            }
                        }
                        
                        response.put("message", "Scope reset completed successfully");
                        response.put("cleared_includes", clearedIncludes);
                        response.put("cleared_excludes", clearedExcludes);
                        response.put("includes_cleared_count", clearedIncludes.size());
                        response.put("excludes_cleared_count", clearedExcludes.size());
                        response.put("total_rules_processed", clearedIncludes.size() + clearedExcludes.size());
                        
                        if (!errors.isEmpty()) {
                            response.put("errors", errors);
                            response.put("partial_success", true);
                        }
                        
                        // Log the reset action
                        logger.info("Scope reset completed: {} includes cleared, {} excludes cleared", 
                                   clearedIncludes.size(), clearedExcludes.size());
                        
                    } else {
                        response.put("message", "No scope configuration found - scope already empty");
                        response.put("cleared_includes", clearedIncludes);
                        response.put("cleared_excludes", clearedExcludes);
                    }
                    
                } catch (Exception configError) {
                    logger.error("Failed to read project scope configuration for reset", configError);
                    response.put("error", "Failed to read scope configuration");
                    response.put("message", "Could not access current scope rules: " + configError.getMessage());
                    ctx.status(500).json(response);
                    return;
                }
                
                response.put("timestamp", System.currentTimeMillis());
                response.put("operation", "scope_reset");
                response.put("api_version", "2025.8+");
                
                if (errors.isEmpty()) {
                    ctx.json(response);
                } else {
                    ctx.status(207).json(response); // 207 Multi-Status for partial success
                }
                
            } catch (Exception e) {
                logger.error("Failed to reset scope", e);
                ctx.status(500).json(Map.of(
                    "error", "Scope reset failed",
                    "message", e.getMessage(),
                    "timestamp", System.currentTimeMillis()
                ));
            }
        });
        
        //  Export full project configuration
        app.get("/scope/project-config", ctx -> {
            try {
                String sections = ctx.queryParam("sections");
                String configJson;
                
                if (sections != null && !sections.isEmpty()) {
                    // Export specific sections (comma-separated)
                    String[] sectionPaths = sections.split(",");
                    for (int i = 0; i < sectionPaths.length; i++) {
                        sectionPaths[i] = sectionPaths[i].trim();
                    }
                    configJson = api.burpSuite().exportProjectOptionsAsJson(sectionPaths);
                } else {
                    // Export full project configuration
                    configJson = api.burpSuite().exportProjectOptionsAsJson();
                }
                
                // Parse and return as structured JSON
                ObjectMapper mapper = new ObjectMapper();
                JsonNode configNode = mapper.readTree(configJson);
                
                Map<String, Object> response = new HashMap<>();
                response.put("project_configuration", configNode);
                response.put("source", "current_project_file");
                response.put("sections_requested", sections != null ? Arrays.asList(sections.split(",")) : "all");
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to export project configuration", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to export project configuration",
                    "message", e.getMessage()
                ));
            }
        });

        // Import project configuration (ticket #13, Phase 3). The Montoya-path
        // throttle lever: apply a resource-pool template (concurrency + request
        // throttle) so audits complete on a memory-constrained JVM, without
        // needing the built-in REST API. Accepts either a raw project-options
        // object or the export-shaped {"project_configuration": {...}} wrapper,
        // so a GET /scope/project-config export round-trips.
        app.post("/scope/project-config", ctx -> {
            try {
                ObjectMapper mapper = new ObjectMapper();
                String rawBody = ctx.body();
                JsonNode body = (rawBody == null || rawBody.isBlank())
                    ? null
                    : mapper.readTree(rawBody);

                String importJson;
                List<String> sections;
                try {
                    importJson = com.burp2api.services.ProjectConfigImportMapper.toImportJson(body);
                    sections = com.burp2api.services.ProjectConfigImportMapper.importedSections(body);
                } catch (IllegalArgumentException e) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid project configuration",
                        "message", e.getMessage(),
                        "hint", "Send a JSON object of project options (e.g. {\"project_options\":"
                            + "{\"connections\":{\"resource_pool\":{...}}}}) or a "
                            + "GET /scope/project-config export."
                    ));
                    return;
                }

                api.burpSuite().importProjectOptionsFromJson(importJson);

                Map<String, Object> response = new HashMap<>();
                response.put("imported", true);
                response.put("sections_imported", sections);
                response.put("message", "Project options imported into the current Burp project.");
                response.put("timestamp", System.currentTimeMillis());
                ctx.json(response);

            } catch (Exception e) {
                logger.error("Failed to import project configuration", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to import project configuration",
                    "message", e.getMessage()
                ));
            }
        });

        // Export user options (ticket #14). User options are where the built-in
        // REST API service settings live (Settings -> Suite -> REST API), which
        // project options do not carry. This is the enabler for capturing the
        // keyless `rest_api` block over the API without the UI, e.g.
        // GET /config/user-config?sections=user_options.rest_api. Never logs the
        // exported body (it can contain an API key if one is configured).
        app.get("/config/user-config", ctx -> {
            try {
                String sections = ctx.queryParam("sections");
                String configJson;

                if (sections != null && !sections.isEmpty()) {
                    // Export specific sections (comma-separated)
                    String[] sectionPaths = sections.split(",");
                    for (int i = 0; i < sectionPaths.length; i++) {
                        sectionPaths[i] = sectionPaths[i].trim();
                    }
                    configJson = api.burpSuite().exportUserOptionsAsJson(sectionPaths);
                } else {
                    // Export full user configuration
                    configJson = api.burpSuite().exportUserOptionsAsJson();
                }

                // Parse and return as structured JSON
                ObjectMapper mapper = new ObjectMapper();
                JsonNode configNode = mapper.readTree(configJson);

                Map<String, Object> response = new HashMap<>();
                response.put("user_configuration", configNode);
                response.put("source", "current_user_options");
                response.put("sections_requested", sections != null ? Arrays.asList(sections.split(",")) : "all");
                response.put("timestamp", System.currentTimeMillis());

                ctx.json(response);

            } catch (Exception e) {
                logger.error("Failed to export user configuration", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to export user configuration",
                    "message", e.getMessage()
                ));
            }
        });

        // Import user options (ticket #14). Symmetric with the export above and
        // with POST /scope/project-config: apply a captured user-options block
        // (e.g. the keyless `rest_api` service settings from
        // user-options.template.json) to the running Burp. Accepts either a raw
        // user-options object or the export-shaped {"user_configuration": {...}}
        // wrapper, so a GET /config/user-config export round-trips.
        app.post("/config/user-config", ctx -> {
            try {
                ObjectMapper mapper = new ObjectMapper();
                String rawBody = ctx.body();
                JsonNode body = (rawBody == null || rawBody.isBlank())
                    ? null
                    : mapper.readTree(rawBody);

                String importJson;
                List<String> sections;
                try {
                    importJson = com.burp2api.services.UserConfigImportMapper.toImportJson(body);
                    sections = com.burp2api.services.UserConfigImportMapper.importedSections(body);
                } catch (IllegalArgumentException e) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid user configuration",
                        "message", e.getMessage(),
                        "hint", "Send a JSON object of user options (e.g. {\"user_options\":"
                            + "{\"rest_api\":{...}}}) or a GET /config/user-config export."
                    ));
                    return;
                }

                api.burpSuite().importUserOptionsFromJson(importJson);

                Map<String, Object> response = new HashMap<>();
                response.put("imported", true);
                response.put("sections_imported", sections);
                response.put("message", "User options imported into the running Burp instance.");
                response.put("timestamp", System.currentTimeMillis());
                ctx.json(response);

            } catch (Exception e) {
                logger.error("Failed to import user configuration", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to import user configuration",
                    "message", e.getMessage()
                ));
            }
        });
    }

    /**
     * Registers scanner-related routes.
     */
    private void registerScannerRoutes(Javalin app) {
        // Delegate to ScannerRouteRegistrar
        ScannerRouteRegistrar scannerRegistrar = new ScannerRouteRegistrar(api, databaseService, config, this, scanTaskManager);
        scannerRegistrar.registerRoutes(app);
    }
    
    /**
     * Registers BCheck-related routes .
     */
    private void registerBCheckRoutes(Javalin app) {
        // Delegate to BCheckRouteRegistrar
        BCheckRouteRegistrar bcheckRegistrar = new BCheckRouteRegistrar(bCheckService);
        bcheckRegistrar.registerRoutes(app);
    }
    
    /**
     * Registers configuration management routes.
     */
    private void registerConfigurationRoutes(Javalin app) {
        // Delegate to ConfigurationRouteRegistrar
        com.burp2api.handlers.ConfigurationRouteRegistrar configRegistrar = new com.burp2api.handlers.ConfigurationRouteRegistrar(databaseService, config);
        configRegistrar.registerRoutes(app);
    }
    
    /**
     * Reconstructs and returns the live session cookies for a host from captured
     * proxy traffic, so an agent can reuse an existing authenticated session
     * without re-running the interactive login flow.
     */
    /** Reconstructed cookies for a host plus how many exchanges were examined. */
    private record ReconstructedCookies(com.burp2api.utils.CookieReconstructor.Result result,
                                        int exchangesExamined) {
    }

    /**
     * Reconstructs the live session cookies for {@code host} from captured proxy
     * traffic. Shared by the {@code /auth/cookies?host=} view and jar seeding.
     */
    private ReconstructedCookies reconstructCookiesForHost(String host) {
        Map<String, String> searchParams = new HashMap<>();
        searchParams.put("host", host);
        searchParams.put("sort", "timestamp");
        searchParams.put("order", "desc");
        searchParams.put("limit", "500");

        List<Map<String, Object>> records = databaseService.searchTraffic(searchParams);

        // searchTraffic matches host as a substring; keep only exact host matches
        // (case-insensitive) so cookies are not leaked across unrelated hosts.
        List<com.burp2api.utils.CookieReconstructor.Exchange> exchanges = new ArrayList<>();
        for (Map<String, Object> record : records) {
            String recordHost = (String) record.get("host");
            if (recordHost == null || !recordHost.equalsIgnoreCase(host)) {
                continue;
            }
            exchanges.add(new com.burp2api.utils.CookieReconstructor.Exchange(
                (String) record.get("headers"),
                (String) record.get("response_headers")
            ));
        }

        com.burp2api.utils.CookieReconstructor.Result result =
            com.burp2api.utils.CookieReconstructor.reconstruct(host, exchanges);
        return new ReconstructedCookies(result, exchanges.size());
    }

    private void handleLiveCookiesForHost(Context ctx, String host) {
        ReconstructedCookies reconstructed = reconstructCookiesForHost(host);
        com.burp2api.utils.CookieReconstructor.Result result = reconstructed.result();

        List<Map<String, Object>> cookiesJson = new ArrayList<>();
        for (com.burp2api.utils.CookieReconstructor.Cookie cookie : result.cookies()) {
            Map<String, Object> cookieData = new HashMap<>();
            cookieData.put("name", cookie.name());
            cookieData.put("value", cookie.value());
            cookieData.put("domain", cookie.domain());
            cookieData.put("path", cookie.path());
            cookieData.put("secure", cookie.secure());
            cookieData.put("http_only", cookie.httpOnly());
            cookieData.put("source", cookie.source());
            cookiesJson.add(cookieData);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("host", host);
        response.put("source", "reconstructed_from_proxy_traffic");
        response.put("cookies", cookiesJson);
        response.put("cookie_header", result.cookieHeader());
        response.put("count", cookiesJson.size());
        response.put("exchanges_examined", reconstructed.exchangesExamined());
        response.put("note", "Live session cookies reconstructed from captured proxy traffic "
            + "(Cookie request headers and Set-Cookie responses). Browse the target through "
            + "the Burp proxy to populate this view.");
        response.put("timestamp", System.currentTimeMillis());

        ctx.json(response);
    }

    /**
     * Registers authentication and session management routes.
     */
    private void registerAuthRoutes(Javalin app) {
        //  Get current cookies from Burp Cookie Jar
        app.get("/auth/cookies", ctx -> {
            try {
                // When a host is supplied, reconstruct the live session cookies for
                // that host from captured proxy traffic. The Montoya CookieJar API
                // cannot enumerate existing cookies, but the browser's authenticated
                // session is visible in the Cookie request header of proxied traffic.
                String host = ctx.queryParam("host");
                if (host != null && !host.isBlank()) {
                    handleLiveCookiesForHost(ctx, host.trim());
                    return;
                }

                // Note: Burp Montoya API doesn't expose individual Cookie objects for retrieval
                // We can only manage cookies through setCookie and track them in our database

                // Get cookie configurations from database (cookies we've added)
                Map<String, String> searchParams = new HashMap<>();
                searchParams.put("method", "COOKIE_INJECTION");
                
                String sessionTag = ctx.queryParam("session_tag");
                if (sessionTag != null) {
                    searchParams.put("session_tag", sessionTag);
                }
                
                List<Map<String, Object>> cookieRecords = databaseService.searchTraffic(searchParams);
                
                // Extract cookie information from database records
                List<Map<String, Object>> cookiesJson = new ArrayList<>();
                for (Map<String, Object> record : cookieRecords) {
                    Map<String, Object> cookieData = new HashMap<>();
                    
                    // Parse headers for cookie details
                    String headers = (String) record.get("headers");
                    if (headers != null) {
                        for (String line : headers.split("\n")) {
                            if (line.startsWith("Cookie-Name: ")) {
                                cookieData.put("name", line.substring(13));
                            } else if (line.startsWith("Cookie-Value: ")) {
                                cookieData.put("value", line.substring(14));
                            } else if (line.startsWith("Cookie-Domain: ")) {
                                cookieData.put("domain", line.substring(15));
                            } else if (line.startsWith("Cookie-Path: ")) {
                                cookieData.put("path", line.substring(13));
                            }
                        }
                    }
                    
                    cookieData.put("injection_id", record.get("id"));
                    cookieData.put("session_tag", record.get("session_tag"));
                    cookieData.put("timestamp", record.get("timestamp"));
                    cookiesJson.add(cookieData);
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("message", "Cookie retrieval limited by Burp API - showing cookies injected via this API");
                response.put("api_limitation", "Burp Montoya API doesn't expose methods to retrieve existing cookies from Cookie Jar");
                response.put("injected_cookies", cookiesJson);
                response.put("count", cookiesJson.size());
                response.put("timestamp", System.currentTimeMillis());
                response.put("note", "Only cookies added through this REST API are tracked and displayed");
                
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to retrieve cookies from cookie jar", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve cookies",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Add/inject cookies into Burp Cookie Jar
        app.post("/auth/cookies", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                // Check if Burp API and HTTP service are available
                if (api == null || api.http() == null) {
                    ctx.status(503).json(Map.of(
                        "error", "Service Unavailable", 
                        "message", "Burp HTTP service is not available for cookie operations."
                    ));
                    return;
                }
                
                burp.api.montoya.http.sessions.CookieJar cookieJar = api.http().cookieJar();
                
                List<String> addedCookies = new ArrayList<>();
                List<String> errors = new ArrayList<>();
                
                // Handle single cookie or array of cookies
                List<Map<String, Object>> cookiesToAdd = new ArrayList<>();
                if (requestData.containsKey("cookie")) {
                    // Single cookie
                    cookiesToAdd.add((Map<String, Object>) requestData.get("cookie"));
                } else if (requestData.containsKey("cookies")) {
                    // Array of cookies
                    List<Object> cookies = (List<Object>) requestData.get("cookies");
                    for (Object cookie : cookies) {
                        cookiesToAdd.add((Map<String, Object>) cookie);
                    }
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing cookie data",
                        "message", "Must provide either 'cookie' or 'cookies' parameter",
                        "examples", Map.of(
                            "single_cookie", Map.of("cookie", Map.of(
                                "name", "session_id",
                                "value", "abc123",
                                "domain", "example.com",
                                "path", "/"
                            )),
                            "multiple_cookies", Map.of("cookies", List.of(
                                Map.of("name", "auth_token", "value", "xyz789", "domain", "example.com"),
                                Map.of("name", "preference", "value", "dark_mode", "domain", "example.com")
                            ))
                        )
                    ));
                    return;
                }
                
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_cookie_injection");
                
                // Add each cookie to the jar
                for (Map<String, Object> cookieData : cookiesToAdd) {
                    try {
                        String name = (String) cookieData.get("name");
                        String value = (String) cookieData.get("value");
                        String domain = (String) cookieData.getOrDefault("domain", "");
                        String path = (String) cookieData.getOrDefault("path", "/");
                        
                        if (name == null || value == null) {
                            errors.add("Cookie missing required 'name' or 'value' field");
                            continue;
                        }
                        
                        // Parse expiration if provided
                        java.time.ZonedDateTime expiration = null;
                        if (cookieData.containsKey("expiration")) {
                            try {
                                String expirationStr = (String) cookieData.get("expiration");
                                if (expirationStr != null && !expirationStr.isEmpty()) {
                                    expiration = java.time.ZonedDateTime.parse(expirationStr);
                                }
                            } catch (Exception e) {
                                errors.add("Failed to parse expiration for cookie '" + name + "': " + e.getMessage());
                            }
                        }
                        
                        // Add cookie to Burp's cookie jar
                        cookieJar.setCookie(name, value, path, domain, expiration);
                        addedCookies.add(name + "=" + value + " (domain: " + domain + ", path: " + path + ")");
                        
                        // Store cookie injection in database for tracking
                        databaseService.storeRawTraffic(
                            "COOKIE_INJECTION", domain + path, domain,
                            "Cookie-Name: " + name + "\nCookie-Value: " + value + "\nCookie-Domain: " + domain + "\nCookie-Path: " + path,
                            "", "", "", null, sessionTag
                        );
                        
                        logger.info("Added cookie to jar: {} for domain: {}", name, domain);
                        
                    } catch (Exception e) {
                        logger.error("Failed to add cookie", e);
                        errors.add("Failed to add cookie: " + e.getMessage());
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("added_count", addedCookies.size());
                response.put("added_cookies", addedCookies);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                    response.put("partial_success", true);
                }
                
                if (addedCookies.isEmpty()) {
                    ctx.status(400).json(response);
                } else {
                    ctx.json(response);
                }
                
            } catch (Exception e) {
                logger.error("Failed to inject cookies", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to inject cookies",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Configure token injection headers
        app.post("/auth/tokens", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Handle both formats: direct fields or headers object
                String headerName = (String) requestData.get("header_name");
                String tokenValue = (String) requestData.get("token_value");
                String tokenFormat = (String) requestData.getOrDefault("format", "bearer");
                
                // Alternative format: headers object 
                if (headerName == null && requestData.containsKey("headers")) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> headers = (Map<String, String>) requestData.get("headers");
                    if (headers != null && !headers.isEmpty()) {
                        Map.Entry<String, String> firstHeader = headers.entrySet().iterator().next();
                        headerName = firstHeader.getKey();
                        tokenValue = firstHeader.getValue();
                    }
                }
                
                if (headerName == null || tokenValue == null) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Both 'header_name' and 'token_value' are required",
                        "required_fields", List.of("header_name", "token_value"),
                        "examples", Map.of(
                            "bearer_token", Map.of(
                                "header_name", "Authorization",
                                "token_value", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                "format", "bearer"
                            ),
                            "custom_token", Map.of(
                                "header_name", "X-API-Key",
                                "token_value", "abc123xyz789",
                                "format", "custom"
                            )
                        )
                    ));
                    return;
                }
                
                // Format the token value based on the specified format
                String formattedTokenValue;
                switch (tokenFormat.toLowerCase()) {
                    case "bearer":
                        formattedTokenValue = tokenValue.startsWith("Bearer ") ? tokenValue : "Bearer " + tokenValue;
                        break;
                    case "jwt":
                        formattedTokenValue = tokenValue.startsWith("Bearer ") ? tokenValue : "Bearer " + tokenValue;
                        break;
                    case "basic":
                        formattedTokenValue = tokenValue.startsWith("Basic ") ? tokenValue : "Basic " + tokenValue;
                        break;
                    case "custom":
                        formattedTokenValue = tokenValue;
                        break;
                    default:
                        formattedTokenValue = tokenValue;
                        break;
                }
                
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_token_config");
                boolean persistent = Boolean.parseBoolean((String) requestData.getOrDefault("persistent", "false"));
                
                // Store token configuration in database for future use
                long tokenConfigId = databaseService.storeRawTraffic(
                    "TOKEN_CONFIG", headerName, "token_configuration",
                    "Token-Header: " + headerName + "\nToken-Format: " + tokenFormat + "\nPersistent: " + persistent,
                    formattedTokenValue, "", "", null, sessionTag
                );
                
                Map<String, Object> response = new HashMap<>();
                response.put("token_configured", true);
                response.put("config_id", tokenConfigId);
                response.put("header_name", headerName);
                response.put("token_format", tokenFormat);
                response.put("formatted_value_preview", formattedTokenValue.length() > 50 ? 
                    formattedTokenValue.substring(0, 50) + "..." : formattedTokenValue);
                response.put("persistent", persistent);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                response.put("message", "Token configuration stored. Use this token data in request replay and scanning operations.");
                response.put("usage_note", "The token configuration is stored in the database and can be referenced by session_tag for programmatic use in future requests.");
                
                ctx.json(response);
                
                logger.info("Token configuration stored: {} format for header: {}", tokenFormat, headerName);
                
            } catch (Exception e) {
                logger.error("Failed to configure token injection", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to configure token injection",
                    "message", e.getMessage()
                ));
            }
        });
        
        //  Get token configurations
        app.get("/auth/tokens", ctx -> {
            try {
                // Search for token configurations in database
                Map<String, String> searchParams = new HashMap<>();
                searchParams.put("method", "TOKEN_CONFIG");
                
                String sessionTag = ctx.queryParam("session_tag");
                if (sessionTag != null) {
                    searchParams.put("session_tag", sessionTag);
                }
                
                List<Map<String, Object>> tokenConfigs = databaseService.searchTraffic(searchParams);
                
                // Extract token configuration details
                List<Map<String, Object>> formattedConfigs = new ArrayList<>();
                for (Map<String, Object> config : tokenConfigs) {
                    Map<String, Object> tokenData = new HashMap<>();
                    tokenData.put("config_id", config.get("id"));
                    tokenData.put("header_name", config.get("url")); // stored in url field
                    tokenData.put("session_tag", config.get("session_tag"));
                    tokenData.put("timestamp", config.get("timestamp"));
                    
                    // Parse headers for token details
                    String headers = (String) config.get("headers");
                    if (headers != null) {
                        for (String line : headers.split("\n")) {
                            if (line.startsWith("Token-Format: ")) {
                                tokenData.put("token_format", line.substring(14));
                            } else if (line.startsWith("Persistent: ")) {
                                tokenData.put("persistent", Boolean.parseBoolean(line.substring(12)));
                            }
                        }
                    }
                    
                    // Add preview of token value (truncated for security)
                    String tokenValue = (String) config.get("body");
                    if (tokenValue != null && tokenValue.length() > 0) {
                        tokenData.put("token_preview", tokenValue.length() > 50 ? 
                            tokenValue.substring(0, 50) + "..." : tokenValue);
                    }
                    
                    formattedConfigs.add(tokenData);
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("token_configurations", formattedConfigs);
                response.put("count", formattedConfigs.size());
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to retrieve token configurations", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve token configurations",
                    "message", e.getMessage()
                ));
            }
        });
    }
    
    /**
     * Gets the list of available endpoints.
     * 
     * @return List of endpoint descriptions
     */
    private List<Map<String, String>> getEndpointList() {
        return List.of(
            // Core endpoints
            Map.of("method", "GET", "path", "/", "description", "API information"),
            Map.of("method", "GET", "path", "/version", "description", "Version information"),
            Map.of("method", "GET", "path", "/health", "description", "Health check"),
            Map.of("method", "GET", "path", "/project", "description", "Current project information and database status"),
            
            // Proxy traffic management
            Map.of("method", "GET", "path", "/proxy/search", "description", "Search captured traffic (this store only; run POST /proxy/import-history first for pre-existing browser history). Filters: url, match, method, host, hosts[], status_code, session_tag, tags, has_tags, has_comments, comment, case_insensitive, start_time, end_time, since, limit, offset. The 'url' filter is a substring match by default; use match=exact to pin one full URL exactly, or wildcards (* and ?) in 'url'. To locate one specific captured request reliably, tag it (POST /proxy/tag or the send/replay session_tag) and filter by session_tag. Returns an object with a 'results' array, count, total_count, filters, and 'pagination' only when limit/offset is set."),
            Map.of("method", "GET", "path", "/proxy/search/download", "description", "Download search results as JSON or CSV (format=json|csv)"),
            Map.of("method", "GET", "path", "/proxy/search/metadata", "description", "Search tagged and commented records with metadata filters (tags, has_tags, has_comments, comment, session_tag, limit)"),
            Map.of("method", "GET", "path", "/proxy/history", "description", "Get proxy history with optimized scope filtering and performance enhancements (limit, offset, isInScope, notInScope)"),
            Map.of("method", "POST", "path", "/proxy/send", "description", "Send HTTP request and capture response (requires: method, url; optional: headers as newline-separated 'Name: Value' lines, body, session_tag, cookie_jar=use|reset|off for a session_tag-scoped cookie jar, follow_redirects, max_redirects)"),
            Map.of("method", "POST", "path", "/proxy/upload", "description", "Upload HAR files or raw HTTP logs for storage (supports JSON HAR format and plain text HTTP logs)"),
            Map.of("method", "POST", "path", "/proxy/import-history", "description", "Import the current Burp project's existing proxy history into this store (optional: session_tag). Prerequisite for searching pre-existing browser traffic via GET /proxy/search."),
            Map.of("method", "DELETE", "path", "/proxy/delete", "description", "Delete traffic records (options: all=true, session_tag=value, start_time/end_time)"),
            Map.of("method", "POST", "path", "/proxy/replay-matched", "description", "Replay traffic from search results or specific record IDs (requires: search_params or record_ids)"),
            Map.of("method", "GET", "path", "/proxy/stats", "description", "Get traffic statistics grouped by host, method, status code, and session tag. Supports host_limit (custom limit), all_hosts=true (remove limit), hosts[] (batch filtering), since (incremental updates)."),
            Map.of("method", "GET", "path", "/proxy/timeline", "description", "Get traffic timeline grouped by time intervals (interval=minute|hour|day; supports all search filters)"),
            Map.of("method", "GET", "path", "/proxy/har-export", "description", "Export proxy history as HAR file (supports all search filters; limit defaults to 1000)"),
            Map.of("method", "GET", "path", "/proxy/hosts", "description", "List every host present in captured traffic with its request count (accepts the /proxy/search filters; the host limit is lifted for this endpoint)"),

            //  Enhanced Proxy Features
            Map.of("method", "POST", "path", "/proxy/tag", "description", "Tag traffic records with analyst labels (requires: request_id, tags)"),
            Map.of("method", "POST", "path", "/proxy/comment", "description", "Add comments to traffic records (requires: request_id, comment)"),
            Map.of("method", "GET", "path", "/proxy/tags", "description", "Get all tagged traffic records (optional: session_tag filter)"),
            Map.of("method", "GET", "path", "/proxy/comments", "description", "Get all commented traffic records (optional: session_tag filter)"),
            Map.of("method", "POST", "path", "/proxy/replay", "description", "Replay requests by ID with header/body overrides and lineage tracking (requires: request_ids)"),
            Map.of("method", "GET", "path", "/proxy/replay/lineage/{id}", "description", "Track replay genealogy for forensic analysis (requires: id path parameter)"),
            Map.of("method", "GET", "path", "/proxy/search/request-body", "description", "FTS5-powered full-text search in request bodies (requires: q query parameter)"),
            Map.of("method", "GET", "path", "/proxy/search/response-body", "description", "FTS5-powered full-text search in response bodies (requires: q query parameter)"),
            Map.of("method", "POST", "path", "/proxy/query/save", "description", "Save query presets with JSON parameters (requires: name, query_params)"),
            Map.of("method", "GET", "path", "/proxy/query/load", "description", "Load saved query by name (requires: name parameter)"),
            Map.of("method", "GET", "path", "/proxy/query/list", "description", "List all saved queries with optional session filtering (optional: session_tag)"),
            Map.of("method", "DELETE", "path", "/proxy/query/{name}", "description", "Delete saved query by name (requires: name path parameter)"),
            
            //  Curl Generator
            Map.of("method", "GET", "path", "/proxy/request/{id}/curl", "description", "Generate a curl command for a captured request (requires: id; optional: redact, pretty, shell, metadata). The id is the public proxy_traffic.id from /proxy/search; an internal traffic_meta id (traffic_meta_id) is also accepted and resolved through its proxy_traffic_id link. Response echoes request_id (public id used), requested_id, and resolved_via ('id' or 'traffic_meta_id'); a miss returns a 404 naming the id space, not a bare Not found."),

            //  Byte-exact raw capture (#24)
            Map.of("method", "GET", "path", "/proxy/history/{id}/raw", "description", "Byte-exact raw request/response bytes for a stored row, base64-encoded (request_raw_b64/response_raw_b64 with present/omitted flags and max_raw_bytes)"),
            
            // Advanced Response Analysis (Montoya API 2025.8+)
            Map.of("method", "POST", "path", "/proxy/analyze/compare", "description", "Advanced response variation analysis using Montoya API ResponseVariationsAnalyzer (requires: request_ids array with 2+ IDs)"),
            Map.of("method", "POST", "path", "/proxy/analyze/keywords", "description", "Keyword-based security analysis using Montoya API ResponseKeywordsAnalyzer (requires: request_ids, keywords; optional: case_sensitive)"),
            
            // Real-time Proxy Interception (Montoya API 2025.8+)
            Map.of("method", "POST", "path", "/proxy/intercept/rules", "description", "Create real-time proxy interception rules for dynamic request/response modification (requires: name, type, condition, action)"),
            Map.of("method", "GET", "path", "/proxy/intercept/rules", "description", "List all active proxy interception rules with hit counts and status"),
            Map.of("method", "POST", "path", "/proxy/intercept/rules/{ruleId}/toggle", "description", "Enable or disable specific proxy interception rule (requires: enabled boolean)"),
            Map.of("method", "POST", "path", "/proxy/intercept/rules/{ruleId}/delete", "description", "Delete specific proxy interception rule by ID"),
            
            //  WebSocket Streaming
            Map.of("method", "WS", "path", "/ws/stream", "description", "Real-time WebSocket traffic streaming (query: session_tag; events: traffic.new, traffic.tagged, stats.updated, etc.)"),
            Map.of("method", "GET", "path", "/ws/stats", "description", "WebSocket connection statistics and performance metrics"),
            Map.of("method", "GET", "path", "/ws/test", "description", "Test WebSocket broadcasting functionality (optional: session_tag parameter)"),
            
            // Scope management (optimized)
            Map.of("method", "GET", "path", "/scope/current", "description", "Get current scope information with enhanced project configuration access"),
            Map.of("method", "GET", "path", "/scope/project-config", "description", "Export full project configuration or specific sections (optional: sections=target.scope,project_options.connections)"),
            Map.of("method", "POST", "path", "/scope/project-config", "description", "Import project options (e.g. a resource-pool template to throttle scans on low memory)"),
            Map.of("method", "GET", "path", "/config/user-config", "description", "Export user options or specific sections (optional: sections=user_options.rest_api) - e.g. capture the keyless REST API block"),
            Map.of("method", "POST", "path", "/config/user-config", "description", "Import user options (e.g. the keyless rest_api service block) into the running Burp instance"),
            Map.of("method", "GET", "path", "/scope/check", "description", "Check if URL is in scope (optimized with caching) (requires: url parameter)"),
            Map.of("method", "POST", "path", "/scope/exclude", "description", "Exclude URLs from scope (requires: url or urls; supports single URL or array)"),
            Map.of("method", "POST", "path", "/scope/import", "description", "Import URLs to scope (supports JSON array or plain text; options: type=include|exclude, session_tag)"),
            Map.of("method", "POST", "path", "/scope/reset", "description", "Reset scope by clearing all include/exclude rules (reads current rules from project config and uses Montoya API to clear them)"),
            
            // Scanner integration
            Map.of("method", "GET", "path", "/scanner/issues", "description", "Get scanner issues with filtering (severity, confidence, name, host, url, case_insensitive, limit, offset)"),
            Map.of("method", "GET", "path", "/scanner/queue", "description", "Get scanner queue status (limited by Burp API - shows available operations)"),
            Map.of("method", "POST", "path", "/scanner/scan-request", "description", "Scan raw HTTP request (requires: method, url; optional: headers, body, audit_config, session_tag)"),
            Map.of("method", "POST", "path", "/scanner/scan-url-list", "description", "Scan multiple URLs (requires: urls or url; optional: method, audit_config, session_tag)"),
            Map.of("method", "POST", "path", "/scanner/crawl", "description", "Start a crawl from seed URLs (requires: urls array or single url; optional: session_tag and crawl configuration fields)"),

            // Scan task tracking
            Map.of("method", "GET", "path", "/scanner/tasks", "description", "List scan tasks (optional: status, task_type, session_tag, limit defaults to 50, offset)"),
            Map.of("method", "GET", "path", "/scanner/tasks/{id}", "description", "Get one scan task's status and progress (requires: id path parameter; 'rest_'-prefixed ids are proxied to Burp's own scan_status/scan_metrics)"),
            Map.of("method", "DELETE", "path", "/scanner/tasks/{id}", "description", "Cancel a running scan task (requires: id path parameter)"),

            // Enhanced scanner (structured ScanRequest model)
            Map.of("method", "POST", "path", "/scanner/enhanced-scan", "description", "Start a scan from a structured ScanRequest body (url or urls, scan_type, audit_config, scan_optimization, crawl_configuration, authentication, scope_restrictions, custom_headers, session_tag)"),
            Map.of("method", "POST", "path", "/scanner/enhanced-scan/validate", "description", "Validate a ScanRequest body without starting it; returns valid, estimated_targets, and estimated_duration_minutes"),
            Map.of("method", "GET", "path", "/scanner/enhanced-scan/configurations", "description", "List the audit configurations, scan types, optimization strategies, insertion point types, and authentication types accepted by /scanner/enhanced-scan"),
            Map.of("method", "GET", "path", "/scanner/enhanced-scan/presets", "description", "List ready-made enhanced-scan presets (quick, thorough, discovery)"),

            // BCheck management
            Map.of("method", "GET", "path", "/bchecks", "description", "List imported BChecks"),
            Map.of("method", "POST", "path", "/bchecks", "description", "Import a BCheck from an inline script (requires: script; optional: name, description, enabled)"),
            Map.of("method", "POST", "path", "/bchecks/import-file", "description", "Import a BCheck from a file on the Burp host (requires: file_path; optional: name, description, enabled)"),
            Map.of("method", "GET", "path", "/bchecks/{bcheckId}", "description", "Get one BCheck's details (requires: bcheckId path parameter)"),
            Map.of("method", "DELETE", "path", "/bchecks/{bcheckId}", "description", "Delete a BCheck (requires: bcheckId path parameter)"),
            Map.of("method", "POST", "path", "/bchecks/validate", "description", "Security-validate a BCheck script without importing it (requires: script)"),
            Map.of("method", "GET", "path", "/bchecks/stats", "description", "BCheck counts and status summary"),
            Map.of("method", "GET", "path", "/bchecks/templates", "description", "Starter BCheck script templates"),
            Map.of("method", "GET", "path", "/bchecks/security-rules", "description", "The rules POST /bchecks/validate enforces against a script"),

            // Authentication utilities
            Map.of("method", "GET", "path", "/auth/cookies", "description", "Get current cookies from Burp Cookie Jar"),
            Map.of("method", "POST", "path", "/auth/cookies", "description", "Add/inject cookies into Burp Cookie Jar"),
            Map.of("method", "POST", "path", "/auth/tokens", "description", "Configure token injection headers"),
            Map.of("method", "GET", "path", "/auth/tokens", "description", "Get token configurations"),
            
            
            // Session management (new)
            Map.of("method", "GET", "path", "/session/current", "description", "Get current session tag with statistics and usage information"),
            Map.of("method", "POST", "path", "/session/tag", "description", "Update session tag with auto-generation support (auto-generates if empty)"),
            Map.of("method", "POST", "path", "/session/new", "description", "Generate a new session tag and apply it (optional: prefix parameter)"),
            Map.of("method", "GET", "path", "/session/history", "description", "Get complete session history and statistics"),
            Map.of("method", "GET", "path", "/session/help", "description", "Complete documentation for session management API"),
            Map.of("method", "GET", "path", "/session/cookies", "description", "Inspect the session-scoped cookie jar for a session_tag (optional: session_tag)"),
            Map.of("method", "DELETE", "path", "/session/cookies", "description", "Reset (clear) the session-scoped cookie jar for a session_tag (optional: session_tag)"),
            Map.of("method", "POST", "path", "/session/cookies", "description", "Seed the session cookie jar from captured proxy traffic (requires: seed_host; optional: session_tag)"),
            
            // Collaborator integration (consolidated)
            Map.of("method", "GET", "path", "/collaborator/status", "description", "Check Collaborator connectivity and server status"),
            Map.of("method", "GET", "path", "/collaborator/interactions", "description", "Retrieve Collaborator interactions for a specific client (requires: client_secret; optional: payload, interaction_id, session_tag filters)"),
            Map.of("method", "POST", "path", "/collaborator/payloads", "description", "Generate payloads using default generator (shows in Collaborator tab; optional: count, options, custom_data, session_tag)"),
            Map.of("method", "POST", "path", "/collaborator/payloads/url", "description", "Generate single URL as plain text (like 'copy to clipboard' functionality)"),
            Map.of("method", "POST", "path", "/collaborator/payloads/client", "description", "Create pollable client with payloads (returns client_secret for API polling; optional: count, options, custom_data, session_tag)"),
            Map.of("method", "GET", "path", "/collaborator/discover-secrets", "description", "Create multiple collaborator clients and extract their secret keys for global access (optional: count parameter, max 20)"),
            Map.of("method", "GET", "path", "/collaborator/global-interactions", "description", "Query interactions across multiple secret keys without needing individual client access (requires: secret_keys parameter as comma-separated list)"),

            // Extension configuration (burp2api's own settings, not Burp's)
            Map.of("method", "GET", "path", "/config", "description", "Get burp2api's current runtime configuration"),
            Map.of("method", "PUT", "path", "/config", "description", "Update burp2api's runtime configuration (requires: configuration object)"),
            Map.of("method", "POST", "path", "/config/validate", "description", "Validate a configuration object without applying it"),
            Map.of("method", "POST", "path", "/config/reload", "description", "Reload configuration from disk"),
            Map.of("method", "GET", "path", "/config/environment", "description", "Show the BURP2API_* environment variables in effect"),
            Map.of("method", "GET", "path", "/config/profiles", "description", "List configuration profiles (held in memory only; not persisted across extension reloads)"),
            Map.of("method", "GET", "path", "/config/profiles/{profile}", "description", "Get one configuration profile (requires: profile path parameter)"),
            Map.of("method", "PUT", "path", "/config/profiles/{profile}", "description", "Create or overwrite a configuration profile (requires: profile path parameter and a configuration body)"),
            Map.of("method", "DELETE", "path", "/config/profiles/{profile}", "description", "Delete a configuration profile (requires: profile path parameter)"),
            Map.of("method", "GET", "path", "/config/databases", "description", "List the per-project SQLite databases in the active database directory (beside the .burp file, or ~/.burp2api/ for temporary projects) with size and last-modified time, and flag which one is active"),
            Map.of("method", "DELETE", "path", "/config/databases/{name}", "description", "Delete a project's SQLite database file by filename (must end in .db; deleting the active database is refused)"),

            // Documentation
            Map.of("method", "GET", "path", "/openapi", "description", "OpenAPI 3.0 specification"),
            Map.of("method", "GET", "path", "/docs", "description", "Swagger UI documentation interface"),
            Map.of("method", "GET", "path", "/postman", "description", "Download Postman collection"),
            Map.of("method", "GET", "path", "/examples", "description", "Interactive request examples for the documented endpoints"),
            Map.of("method", "GET", "path", "/examples/{method}/{path}", "description", "Request examples for one endpoint (requires: method and path path parameters, e.g. /examples/POST/proxy/send)")
        );
    }
    
    /**
     * Gets the configured JSON mapper.
     * 
     * @return The JSON mapper instance
     */
    public JsonMapper getJsonMapper() {
        return jsonMapper;
    }
    

    
    /**
     * Parses HAR file data and stores it in the database.
     * 
     * @param harData The HAR file content
     * @param sessionTag Session tag for the imported data
     * @param errors List to collect error messages
     * @return Number of records imported
     */
    private int parseAndStoreHarData(String harData, String sessionTag, List<String> errors) {
        int recordsImported = 0;
        
        try {
            Map<String, Object> harRoot = objectMapper.readValue(harData, Map.class);
            Map<String, Object> log = (Map<String, Object>) harRoot.get("log");
            
            if (log == null) {
                errors.add("Invalid HAR format: missing 'log' element");
                return 0;
            }
            
            List<Map<String, Object>> entries = (List<Map<String, Object>>) log.get("entries");
            if (entries == null) {
                errors.add("Invalid HAR format: missing 'entries' array");
                return 0;
            }
            
            for (Map<String, Object> entry : entries) {
                try {
                    Map<String, Object> request = (Map<String, Object>) entry.get("request");
                    Map<String, Object> response = (Map<String, Object>) entry.get("response");
                    
                    if (request == null) {
                        errors.add("Skipping entry: missing request data");
                        continue;
                    }
                    
                    String method = (String) request.get("method");
                    String url = (String) request.get("url");
                    String host = extractHostFromUrl(url);
                    
                    // Extract headers
                    StringBuilder requestHeaders = new StringBuilder();
                    List<Map<String, Object>> headers = (List<Map<String, Object>>) request.get("headers");
                    if (headers != null) {
                        for (Map<String, Object> header : headers) {
                            requestHeaders.append(header.get("name")).append(": ").append(header.get("value")).append("\n");
                        }
                    }
                    
                    // Extract request body
                    String requestBody = "";
                    Map<String, Object> postData = (Map<String, Object>) request.get("postData");
                    if (postData != null) {
                        requestBody = (String) postData.getOrDefault("text", "");
                    }
                    
                    // Extract response data
                    String responseHeaders = "";
                    String responseBody = "";
                    Integer statusCode = null;
                    
                    if (response != null) {
                        statusCode = (Integer) response.get("status");
                        
                        List<Map<String, Object>> respHeaders = (List<Map<String, Object>>) response.get("headers");
                        if (respHeaders != null) {
                            StringBuilder respHeadersBuilder = new StringBuilder();
                            for (Map<String, Object> header : respHeaders) {
                                respHeadersBuilder.append(header.get("name")).append(": ").append(header.get("value")).append("\n");
                            }
                            responseHeaders = respHeadersBuilder.toString();
                        }
                        
                        Map<String, Object> content = (Map<String, Object>) response.get("content");
                        if (content != null) {
                            responseBody = (String) content.getOrDefault("text", "");
                        }
                    }
                    
                    // Store in database
                    long recordId = databaseService.storeRawTraffic(
                        method, url, host, requestHeaders.toString(), requestBody,
                        responseHeaders, responseBody, statusCode, sessionTag
                    );
                    
                    if (recordId > 0) {
                        recordsImported++;
                    }
                    
                } catch (Exception e) {
                    errors.add("Failed to process HAR entry: " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            errors.add("Failed to parse HAR data: " + e.getMessage());
        }
        
        return recordsImported;
    }
    
    /**
     * Parses raw HTTP logs and stores them in the database.
     * 
     * @param logData The raw HTTP log content
     * @param sessionTag Session tag for the imported data
     * @param errors List to collect error messages
     * @return Number of records imported
     */
    private int parseAndStoreRawHttpLogs(String logData, String sessionTag, List<String> errors) {
        int recordsImported = 0;
        
        try {
            String[] lines = logData.split("\n");
            StringBuilder currentRequest = new StringBuilder();
            boolean inRequest = false;
            
            for (String line : lines) {
                line = line.trim();
                
                // Check for start of HTTP request
                if (line.matches("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+.+\\s+HTTP/\\d\\.\\d$")) {
                    // Process previous request if exists
                    if (inRequest && currentRequest.length() > 0) {
                        try {
                            parseAndStoreHttpRequest(currentRequest.toString(), sessionTag);
                            recordsImported++;
                        } catch (Exception e) {
                            errors.add("Failed to parse HTTP request: " + e.getMessage());
                        }
                    }
                    
                    // Start new request
                    currentRequest.setLength(0);
                    currentRequest.append(line).append("\n");
                    inRequest = true;
                } else if (inRequest) {
                    currentRequest.append(line).append("\n");
                    
                    // Check for end of request (empty line after headers)
                    if (line.isEmpty()) {
                        // Continue to collect body if present
                    }
                }
            }
            
            // Process final request
            if (inRequest && currentRequest.length() > 0) {
                try {
                    parseAndStoreHttpRequest(currentRequest.toString(), sessionTag);
                    recordsImported++;
                } catch (Exception e) {
                    errors.add("Failed to parse final HTTP request: " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            errors.add("Failed to parse raw HTTP logs: " + e.getMessage());
        }
        
        return recordsImported;
    }
    
    /**
     * Parses a single HTTP request string and stores it in the database.
     * 
     * @param requestString The raw HTTP request string
     * @param sessionTag Session tag for the imported data
     */
    private void parseAndStoreHttpRequest(String requestString, String sessionTag) {
        String[] lines = requestString.split("\n");
        if (lines.length == 0) {
            return;
        }
        
        // Parse request line
        String[] requestLine = lines[0].split("\\s+");
        if (requestLine.length < 3) {
            throw new IllegalArgumentException("Invalid HTTP request line: " + lines[0]);
        }
        
        String method = requestLine[0];
        String path = requestLine[1];
        String url = path; // Default to path if no host header found
        String host = "unknown";
        
        // Parse headers and build URL
        StringBuilder headers = new StringBuilder();
        StringBuilder body = new StringBuilder();
        boolean inBody = false;
        
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            
            if (line.isEmpty()) {
                inBody = true;
                continue;
            }
            
            if (inBody) {
                body.append(line).append("\n");
            } else {
                headers.append(line).append("\n");
                
                // Extract host header
                if (line.toLowerCase().startsWith("host:")) {
                    host = line.substring(5).trim();
                    url = "http://" + host + path; // Assume HTTP for simplicity
                }
            }
        }
        
        // Store in database
        databaseService.storeRawTraffic(
            method, url, host, headers.toString(), body.toString(),
            "", "", null, sessionTag
        );
    }
    
    /**
     * Extracts search parameters from the request context.
     * 
     * @param ctx The Javalin context
     * @return Map of search parameters
     */
    private Map<String, String> extractSearchParams(io.javalin.http.Context ctx) {
        Map<String, String> searchParams = new HashMap<>();
        
        // Basic filters
        if (ctx.queryParam("url") != null) searchParams.put("url", ctx.queryParam("url"));
        if (ctx.queryParam("url_pattern") != null) searchParams.put("url_pattern", ctx.queryParam("url_pattern"));
        // url matching mode: "contains" (default, substring) or "exact" (anchored equality)
        if (ctx.queryParam("match") != null) searchParams.put("match", ctx.queryParam("match"));
        if (ctx.queryParam("method") != null) searchParams.put("method", ctx.queryParam("method"));
        if (ctx.queryParam("host") != null) searchParams.put("host", ctx.queryParam("host"));
        
        // Support bulk hosts filter (comma-separated)
        if (ctx.queryParam("hosts") != null) searchParams.put("hosts", ctx.queryParam("hosts"));
        
        // Handle multiple hosts parameter (hosts[]=host1&hosts[]=host2)
        List<String> hosts = ctx.queryParams("hosts[]");
        if (hosts != null && !hosts.isEmpty()) {
            searchParams.put("hosts", String.join(",", hosts));
        }
        if (ctx.queryParam("status_code") != null) searchParams.put("status_code", ctx.queryParam("status_code"));
        // Only add session_tag if it's not null and not empty (empty means search all sessions)
        if (ctx.queryParam("session_tag") != null && !ctx.queryParam("session_tag").isEmpty()) {
            searchParams.put("session_tag", ctx.queryParam("session_tag"));
        }
        
        // advanced filters
        if (ctx.queryParam("case_insensitive") != null) searchParams.put("case_insensitive", ctx.queryParam("case_insensitive"));
        if (ctx.queryParam("start_time") != null) searchParams.put("start_time", ctx.queryParam("start_time"));
        if (ctx.queryParam("end_time") != null) searchParams.put("end_time", ctx.queryParam("end_time"));
        
        // Pagination
        if (ctx.queryParam("limit") != null) searchParams.put("limit", ctx.queryParam("limit"));
        if (ctx.queryParam("offset") != null) searchParams.put("offset", ctx.queryParam("offset"));

        // Result ordering. sort is a column (id, timestamp, method, host, status_code, url);
        // order is asc|desc, or the friendly aliases newest|oldest (timestamp desc|asc). The
        // default is newest-first (timestamp desc), so offset 0 holds the newest rows (#52).
        if (ctx.queryParam("sort") != null) searchParams.put("sort", ctx.queryParam("sort"));
        if (ctx.queryParam("order") != null) searchParams.put("order", ctx.queryParam("order"));
        
        // Stats-specific parameters
        if (ctx.queryParam("host_limit") != null) searchParams.put("host_limit", ctx.queryParam("host_limit"));
        if (ctx.queryParam("all_hosts") != null) searchParams.put("all_hosts", ctx.queryParam("all_hosts"));
        // Time-window bounds (epoch-ms or ISO 8601): since is exclusive, until inclusive (#54)
        if (ctx.queryParam("since") != null) searchParams.put("since", ctx.queryParam("since"));
        if (ctx.queryParam("until") != null) searchParams.put("until", ctx.queryParam("until"));
        
        // Tag and comment filtering
        if (ctx.queryParam("tags") != null) searchParams.put("tags", ctx.queryParam("tags"));
        if (ctx.queryParam("has_tags") != null) searchParams.put("has_tags", ctx.queryParam("has_tags"));
        if (ctx.queryParam("has_comments") != null) searchParams.put("has_comments", ctx.queryParam("has_comments"));
        if (ctx.queryParam("comment") != null) searchParams.put("comment", ctx.queryParam("comment"));
        
        return searchParams;
    }
    
    /**
     * Converts a list of traffic records to CSV format.
     * 
     * @param results List of traffic records
     * @return CSV string
     */
    private String convertToCsv(List<Map<String, Object>> results) {
        StringBuilder csv = new StringBuilder();
        
        // CSV headers
        csv.append("id,timestamp,method,url,host,status_code,session_tag\n");
        
        // CSV data rows
        for (Map<String, Object> record : results) {
            csv.append(escapeCsvValue(record.get("id")))
               .append(",")
               .append(escapeCsvValue(record.get("timestamp")))
               .append(",")
               .append(escapeCsvValue(record.get("method")))
               .append(",")
               .append(escapeCsvValue(record.get("url")))
               .append(",")
               .append(escapeCsvValue(record.get("host")))
               .append(",")
               .append(escapeCsvValue(record.get("status_code")))
               .append(",")
               .append(escapeCsvValue(record.get("session_tag")))
               .append("\n");
        }
        
        return csv.toString();
    }
    
    /**
     * Escapes a value for CSV format.
     * 
     * @param value The value to escape
     * @return Escaped CSV value
     */
    private String escapeCsvValue(Object value) {
        if (value == null) {
            return "";
        }
        
        String str = value.toString();
        
        // If the value contains comma, quotes, or newlines, wrap in quotes and escape internal quotes
        if (str.contains(",") || str.contains("\"") || str.contains("\n") || str.contains("\r")) {
            str = "\"" + str.replace("\"", "\"\"") + "\"";
        }
        
        return str;
    }
    
    /**
     * Registers documentation routes for Phase 8.
     */
    private void registerDocumentationRoutes(Javalin app) {
        //  OpenAPI 3.0 specification endpoint
        app.get("/openapi", ctx -> {
            Map<String, Object> openApiSpec = generateOpenApiSpec();
            ctx.json(openApiSpec);
        });
        
        //  Swagger UI endpoint
        app.get("/docs", ctx -> {
            String swaggerHtml = generateSwaggerUI();
            ctx.contentType("text/html").result(swaggerHtml);
        });
        
        //  Static assets for Swagger UI (if needed)
        app.get("/docs/swagger-ui.css", ctx -> {
            ctx.contentType("text/css")
               .result("/* Basic Swagger UI styling */\\nbody { font-family: sans-serif; margin: 20px; }\\n.swagger-ui { max-width: 1200px; margin: 0 auto; }");
        });
        
        //  Postman collection export
        app.get("/postman", ctx -> {
            Map<String, Object> postmanCollection = generatePostmanCollection();
            ctx.contentType("application/json")
               .header("Content-Disposition", "attachment; filename=\"burp-rest-api.postman_collection.json\"")
               .json(postmanCollection);
        });
        
        // Advanced Response Analysis Endpoints
        app.post("/proxy/analyze/compare", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                if (!requestData.containsKey("request_ids")) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field 'request_ids'",
                        "message", "Array of request IDs is required for comparison"
                    ));
                    return;
                }
                
                List<Number> requestIdNumbers = (List<Number>) requestData.get("request_ids");
                List<Long> requestIds = requestIdNumbers.stream()
                    .map(Number::longValue)
                    .collect(java.util.stream.Collectors.toList());
                
                if (requestIds.size() < 2) {
                    ctx.status(400).json(Map.of(
                        "error", "At least 2 request IDs required for comparison"
                    ));
                    return;
                }
                
                // Create response analysis service
                com.burp2api.services.ResponseAnalysisService analysisService = 
                    new com.burp2api.services.ResponseAnalysisService(api, databaseService);
                
                Map<String, Object> result = analysisService.analyzeResponseVariations(requestIds);
                ctx.json(result);
                
            } catch (Exception e) {
                logger.error("Response comparison analysis failed", e);
                ctx.status(500).json(Map.of(
                    "error", "Analysis failed",
                    "message", e.getMessage()
                ));
            }
        });
        
        app.post("/proxy/analyze/keywords", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                if (!requestData.containsKey("request_ids") || !requestData.containsKey("keywords")) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Both 'request_ids' and 'keywords' are required",
                        "required_fields", List.of("request_ids", "keywords")
                    ));
                    return;
                }
                
                List<Number> requestIdNumbers = (List<Number>) requestData.get("request_ids");
                List<Long> requestIds = requestIdNumbers.stream()
                    .map(Number::longValue)
                    .collect(java.util.stream.Collectors.toList());
                    
                List<String> keywords = (List<String>) requestData.get("keywords");
                boolean caseSensitive = (Boolean) requestData.getOrDefault("case_sensitive", false);
                
                // Create response analysis service
                com.burp2api.services.ResponseAnalysisService analysisService = 
                    new com.burp2api.services.ResponseAnalysisService(api, databaseService);
                
                Map<String, Object> result = analysisService.analyzeResponseKeywords(requestIds, keywords, caseSensitive);
                ctx.json(result);
                
            } catch (Exception e) {
                logger.error("Keyword analysis failed", e);
                ctx.status(500).json(Map.of(
                    "error", "Analysis failed", 
                    "message", e.getMessage()
                ));
            }
        });
        
        // Real-time Proxy Interception Endpoints (2025.8+)
        app.post("/proxy/intercept/rules", ctx -> {
            try {
                Map<String, Object> ruleData = ctx.bodyAsClass(Map.class);
                
                if (!ruleData.containsKey("name") || !ruleData.containsKey("type") || 
                    !ruleData.containsKey("condition") || !ruleData.containsKey("action")) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Fields 'name', 'type', 'condition', and 'action' are required",
                        "required_fields", List.of("name", "type", "condition", "action")
                    ));
                    return;
                }
                
                String name = (String) ruleData.get("name");
                String typeStr = (String) ruleData.get("type");
                
                // Handle condition - can be string or object
                Map<String, Object> conditions = new HashMap<>();
                Object conditionData = ruleData.get("condition");
                if (conditionData instanceof String) {
                    conditions.put("type", conditionData);
                } else if (conditionData instanceof Map) {
                    conditions = (Map<String, Object>) conditionData;
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid condition format",
                        "message", "Condition must be a string or object"
                    ));
                    return;
                }
                
                // Handle action - can be string or object  
                Map<String, Object> actions = new HashMap<>();
                Object actionData = ruleData.get("action");
                if (actionData instanceof String) {
                    actions.put("type", actionData);
                } else if (actionData instanceof Map) {
                    actions = (Map<String, Object>) actionData;
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid action format",
                        "message", "Action must be a string or object"
                    ));
                    return;
                }
                
                // Create interception service if not exists
                if (proxyInterceptionService == null) {
                    proxyInterceptionService = new com.burp2api.services.ProxyInterceptionService(api);
                }
                
                com.burp2api.services.ProxyInterceptionService.RuleType ruleType;
                try {
                    ruleType = com.burp2api.services.ProxyInterceptionService.RuleType.valueOf(typeStr.toUpperCase());
                } catch (IllegalArgumentException e) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid rule type",
                        "message", "Type must be 'request' or 'response'",
                        "valid_types", List.of("request", "response")
                    ));
                    return;
                }
                
                String ruleId = proxyInterceptionService.addRule(name, ruleType, conditions, actions);
                
                ctx.json(Map.of(
                    "rule_id", ruleId,
                    "name", name,
                    "type", typeStr,
                    "status", "created",
                    "message", "Real-time interception rule created successfully (2025.8+)"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to create interception rule", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to create rule",
                    "message", e.getMessage()
                ));
            }
        });
        
        app.get("/proxy/intercept/rules", ctx -> {
            try {
                if (proxyInterceptionService == null) {
                    ctx.json(Map.of("rules", Map.of(), "total_rules", 0));
                    return;
                }
                
                Map<String, Map<String, Object>> rules = proxyInterceptionService.getAllRules();
                ctx.json(Map.of(
                    "rules", rules,
                    "total_rules", rules.size(),
                    "api_version", "2025.8+"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to get interception rules", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get rules",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Toggle intercept rule (POST method due to Javalin PUT issues)
        app.post("/proxy/intercept/rules/{ruleId}/toggle", ctx -> {
            try {
                String ruleId = ctx.pathParam("ruleId");
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                if (!requestData.containsKey("enabled")) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "Field 'enabled' is required",
                        "required_fields", List.of("enabled")
                    ));
                    return;
                }
                
                boolean enabled = Boolean.TRUE.equals(requestData.get("enabled"));
                
                if (proxyInterceptionService == null) {
                    ctx.status(503).json(Map.of(
                        "error", "Service unavailable",
                        "message", "Proxy interception service is not initialized"
                    ));
                    return;
                }
                
                boolean success = proxyInterceptionService.toggleRule(ruleId, enabled);
                
                if (success) {
                    ctx.json(Map.of(
                        "rule_id", ruleId,
                        "enabled", enabled,
                        "message", "Rule " + (enabled ? "enabled" : "disabled") + " successfully",
                        "api_version", "2025.8+"
                    ));
                } else {
                    ctx.status(404).json(Map.of(
                        "error", "Rule not found",
                        "message", "No interception rule found with ID: " + ruleId,
                        "rule_id", ruleId
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to toggle interception rule", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to toggle rule",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Delete intercept rule (POST method due to Javalin DELETE issues)
        app.post("/proxy/intercept/rules/{ruleId}/delete", ctx -> {
            try {
                String ruleId = ctx.pathParam("ruleId");
                
                if (proxyInterceptionService == null) {
                    ctx.status(503).json(Map.of(
                        "error", "Service unavailable", 
                        "message", "Proxy interception service is not initialized"
                    ));
                    return;
                }
                
                boolean success = proxyInterceptionService.removeRule(ruleId);
                
                if (success) {
                    ctx.json(Map.of(
                        "rule_id", ruleId,
                        "message", "Interception rule deleted successfully",
                        "status", "deleted",
                        "api_version", "2025.8+"
                    ));
                } else {
                    ctx.status(404).json(Map.of(
                        "error", "Rule not found",
                        "message", "No interception rule found with ID: " + ruleId,
                        "rule_id", ruleId
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to delete interception rule", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to delete rule",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Interactive Examples API
        app.get("/examples", ctx -> {
            Map<String, Object> examples = generateInteractiveExamples();
            ctx.json(examples);
        });
        
        app.get("/examples/{method}/{path}", ctx -> {
            String method = ctx.pathParam("method").toUpperCase();
            String path = "/" + ctx.pathParam("path");
            Map<String, Object> example = generateEndpointExamples(method, path);
            ctx.json(example);
        });
    }
    
    /**
     * Generates OpenAPI 3.0 specification for the REST API.
     * 
     * @return OpenAPI specification as a Map
     */
    private Map<String, Object> generateOpenApiSpec() {
        Map<String, Object> spec = new HashMap<>();
        
        // OpenAPI version and info
        spec.put("openapi", "3.0.3");
        
        Map<String, Object> info = new HashMap<>();
        info.put("title", "burp2api - Burp Suite REST API Extension");
        info.put("version", BurpApiExtension.getVersion());
        info.put("description", "REST API extension for Burp Suite Professional that enables programmatic access to proxy traffic, scanner functionality, scope management, and collaborative testing workflows. Features advanced response analysis, real-time proxy interception, and enhanced security testing capabilities using Montoya API 2025.8+.");
        spec.put("info", info);
        
        // Servers
        spec.put("servers", List.of(
            Map.of("url", "http://localhost:" + config.getPort(), "description", "Local Burp API Server")
        ));
        
        // Paths - dynamically generate from endpoint list
        Map<String, Object> paths = new HashMap<>();
        List<Map<String, String>> endpoints = getEndpointList();
        
        for (Map<String, String> endpoint : endpoints) {
            String path = endpoint.get("path");
            String method = endpoint.get("method").toLowerCase();
            String description = endpoint.get("description");
            
            // Create path object if it doesn't exist
            paths.computeIfAbsent(path, k -> new HashMap<String, Object>());
            Map<String, Object> pathObject = (Map<String, Object>) paths.get(path);
            
            // Create operation object
            Map<String, Object> operation = new HashMap<>();
            operation.put("summary", description);
            operation.put("description", description);
            operation.put("tags", List.of(getTagForPath(path)));
            
            // Add responses
            Map<String, Object> responses = new HashMap<>();
            responses.put("200", Map.of(
                "description", "Successful response",
                "content", Map.of(
                    "application/json", Map.of(
                        "schema", Map.of("type", "object")
                    )
                )
            ));
            responses.put("400", Map.of("description", "Bad request"));
            responses.put("500", Map.of("description", "Internal server error"));
            operation.put("responses", responses);
            
            pathObject.put(method, operation);
        }
        
        spec.put("paths", paths);
        
        // Tags
        spec.put("tags", List.of(
            Map.of("name", "General", "description", "General API information"),
            Map.of("name", "Proxy", "description", "Proxy traffic management with advanced analytics, response analysis, and real-time interception (Montoya API 2025.8+)"),
            Map.of("name", "Scope", "description", "Scope management with intelligent caching"),
            Map.of("name", "Scanner", "description", "Scanner and vulnerability management"),
            Map.of("name", "Auth", "description", "Authentication and session management"),
            Map.of("name", "Session", "description", "Session tag management and auto-generation"),
            Map.of("name", "Collaborator", "description", "Collaborator integration for out-of-band testing"),
            Map.of("name", "BChecks", "description", "BCheck import, validation, and management"),
            Map.of("name", "Configuration", "description", "burp2api extension configuration, profiles, and per-project databases"),
            Map.of("name", "Documentation", "description", "API documentation and collections")
        ));
        
        return spec;
    }
    
    /**
     * Determines the appropriate tag for an API path.
     */
    private String getTagForPath(String path) {
        if (path.startsWith("/proxy")) return "Proxy";
        if (path.startsWith("/scope")) return "Scope";
        if (path.startsWith("/scanner")) return "Scanner";
        if (path.startsWith("/auth")) return "Auth";
        if (path.startsWith("/session")) return "Session";
        if (path.startsWith("/collaborator")) return "Collaborator";
        if (path.startsWith("/bchecks")) return "BChecks";
        if (path.startsWith("/config")) return "Configuration";
        if (path.startsWith("/docs") || path.startsWith("/openapi") || path.startsWith("/postman")
                || path.startsWith("/examples")) return "Documentation";
        return "General";
    }
    
    /**
     * Generates Swagger UI HTML page.
     * 
     * @return HTML content for Swagger UI
     */
    private String generateSwaggerUI() {
        return "<!DOCTYPE html>\n" +
               "<html lang=\"en\">\n" +
               "<head>\n" +
               "    <meta charset=\"UTF-8\">\n" +
               "    <title>burp2api v" + BurpApiExtension.getVersion() + " Documentation</title>\n" +
               "    <link rel=\"stylesheet\" type=\"text/css\" href=\"https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css\" />\n" +
               "    <style>\n" +
               "        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }\n" +
               "        *, *:before, *:after { box-sizing: inherit; }\n" +
               "        body { margin:0; background: #fafafa; }\n" +
               "        .swagger-ui .topbar { display: none; }\n" +
               "        .custom-header { background: #1f2937; color: white; padding: 20px; text-align: center; }\n" +
               "        .custom-header h1 { margin: 0; font-size: 2rem; }\n" +
               "        .custom-header p { margin: 10px 0 0 0; opacity: 0.8; }\n" +
               "        .custom-header .features { margin: 15px 0 0 0; font-size: 0.9rem; }\n" +
               "        .custom-header .features span { margin: 0 10px; padding: 3px 8px; background: rgba(255,255,255,0.1); border-radius: 3px; }\n" +
               "    </style>\n" +
               "</head>\n" +
               "<body>\n" +
               "    <div class=\"custom-header\">\n" +
               "        <h1>🚀 burp2api v" + BurpApiExtension.getVersion() + "</h1>\n" +
               "        <p>Comprehensive REST API for traffic management and scripting</p>\n" +
               "        <div class=\"features\">\n" +
               "            <span>🚀 Performance Optimized</span>\n" +
               "            <span>🏷️ Auto Session Tags</span>\n" +
               "            <span>📊 Real-time Monitoring</span>\n" +
               "            <span>🎯 Intelligent Caching</span>\n" +
               "        </div>\n" +
               "    </div>\n" +
               "    <div id=\"swagger-ui\"></div>\n" +
               "    <script src=\"https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js\"></script>\n" +
               "    <script src=\"https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js\"></script>\n" +
               "    <script>\n" +
               "    window.onload = function() {\n" +
               "        const ui = SwaggerUIBundle({\n" +
               "            url: 'http://localhost:" + config.getPort() + "/openapi',\n" +
               "            dom_id: '#swagger-ui',\n" +
               "            deepLinking: true,\n" +
               "            presets: [\n" +
               "                SwaggerUIBundle.presets.apis,\n" +
               "                SwaggerUIStandalonePreset\n" +
               "            ],\n" +
               "            plugins: [\n" +
               "                SwaggerUIBundle.plugins.DownloadUrl\n" +
               "            ],\n" +
               "            layout: 'StandaloneLayout'\n" +
               "        });\n" +
               "    };\n" +
               "    </script>\n" +
               "</body>\n" +
               "</html>";
    }
    
    /**
     * Generates a Postman collection for the REST API.
     * 
     * @return Postman collection as a Map
     */
    private Map<String, Object> generatePostmanCollection() {
        Map<String, Object> collection = new HashMap<>();
        
        // Collection info
        Map<String, Object> info = new HashMap<>();
        info.put("name", "burp2api v" + BurpApiExtension.getVersion());
        info.put("description", "Comprehensive REST API for Burp Suite traffic management and scripting with performance optimizations, auto session tag generation, and enhanced monitoring capabilities");
        info.put("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json");
        collection.put("info", info);
        
        // Variables
        List<Map<String, Object>> variables = new ArrayList<>();
        variables.add(Map.of(
            "key", "baseUrl",
            "value", "http://localhost:" + config.getPort(),
            "type", "string"
        ));
        collection.put("variable", variables);
        
        // Items (endpoints)
        List<Map<String, Object>> items = new ArrayList<>();
        List<Map<String, String>> endpoints = getEndpointList();
        
        // Group endpoints by category
        Map<String, List<Map<String, String>>> groupedEndpoints = new HashMap<>();
        for (Map<String, String> endpoint : endpoints) {
            String tag = getTagForPath(endpoint.get("path"));
            groupedEndpoints.computeIfAbsent(tag, k -> new ArrayList<>()).add(endpoint);
        }
        
        // Create folders for each category
        for (Map.Entry<String, List<Map<String, String>>> entry : groupedEndpoints.entrySet()) {
            String category = entry.getKey();
            List<Map<String, String>> categoryEndpoints = entry.getValue();
            
            Map<String, Object> folder = new HashMap<>();
            folder.put("name", category);
            folder.put("description", "Endpoints for " + category.toLowerCase() + " operations");
            
            List<Map<String, Object>> folderItems = new ArrayList<>();
            for (Map<String, String> endpoint : categoryEndpoints) {
                Map<String, Object> item = new HashMap<>();
                item.put("name", endpoint.get("description"));
                
                Map<String, Object> request = new HashMap<>();
                request.put("method", endpoint.get("method"));
                request.put("url", Map.of(
                    "raw", "{{baseUrl}}" + endpoint.get("path"),
                    "host", List.of("{{baseUrl}}"),
                    "path", List.of(endpoint.get("path").substring(1).split("/"))
                ));
                
                // Add headers for POST/PUT requests
                if ("POST".equals(endpoint.get("method")) || "PUT".equals(endpoint.get("method"))) {
                    request.put("header", List.of(
                        Map.of("key", "Content-Type", "value", "application/json")
                    ));
                    
                    // Add example body for common endpoints
                    if (endpoint.get("path").contains("/proxy/send")) {
                        request.put("body", Map.of(
                            "mode", "raw",
                            "raw", "{\n  \"method\": \"GET\",\n  \"url\": \"https://example.com\",\n  \"session_tag\": \"test\"\n}"
                        ));
                    } else if (endpoint.get("path").contains("/auth/cookies")) {
                        request.put("body", Map.of(
                            "mode", "raw",
                            "raw", "{\n  \"cookie\": {\n    \"name\": \"session_id\",\n    \"value\": \"abc123\",\n    \"domain\": \"example.com\"\n  }\n}"
                        ));
                    } else if (endpoint.get("path").contains("/session/tag")) {
                        request.put("body", Map.of(
                            "mode", "raw",
                            "raw", "{\n  \"session_tag\": \"my_custom_session\"\n}"
                        ));
                    } else if (endpoint.get("path").contains("/collaborator/generate")) {
                        request.put("body", Map.of(
                            "mode", "raw",
                            "raw", "{\n  \"custom_data\": \"test\",\n  \"count\": 3,\n  \"session_tag\": \"collaborator_test\"\n}"
                        ));
                    }
                }
                
                item.put("request", request);
                folderItems.add(item);
            }
            
            folder.put("item", folderItems);
            items.add(folder);
        }
        
        collection.put("item", items);
        
        return collection;
    }
    
    /**
     * Re-encodes the captured body fields of each traffic record so the response
     * is valid JSON regardless of the captured content. A UTF-8 body stays a
     * readable string (control characters are escaped by the JSON serializer); a
     * binary/non-UTF-8 body is Base64-encoded. A {@code *_encoding} discriminator
     * field is added alongside each body field.
     */
    private void annotateRecords(List<Map<String, Object>> records) {
        if (records == null) {
            return;
        }
        for (Map<String, Object> record : records) {
            annotateRecordBody(record, "body", "body_encoding", "body_truncated");
            annotateRecordBody(record, "response_body", "response_body_encoding", "response_body_truncated");
            annotateRecordHeaders(record, "headers", "headers_list");
            annotateRecordHeaders(record, "response_headers", "response_headers_list");
            record.put("max_stored_content_chars", config.getMaxStoredContentChars());
        }
    }

    /**
     * Encodes a stored body and reports whether it hit the storage ceiling. A
     * capped body is flagged rather than marked inline: the store never writes
     * a marker into captured content, so a client cannot tell a complete body
     * from a trimmed one by inspecting it (#20).
     */
    private void annotateRecordBody(Map<String, Object> record, String bodyKey, String encodingKey,
            String truncatedKey) {
        Object value = record.get(bodyKey);
        if (value instanceof String s) {
            record.put(truncatedKey, StoredText.isCapped(s, config.getMaxStoredContentChars()));
            BodyCodec.putEncoded(record, bodyKey, encodingKey, BodyCodec.encodeStoredString(s));
        }
    }

    /**
     * Adds a structured {@code *_list} array of {@code {name, value}} alongside a
     * stored header string, so clients read individual headers without
     * re-parsing the blob. The original string field is left unchanged.
     */
    private void annotateRecordHeaders(Map<String, Object> record, String headerKey, String listKey) {
        Object value = record.get(headerKey);
        if (value instanceof String s) {
            record.put(listKey, HeaderList.fromStoredString(s));
        }
    }

    /**
     * A HAR {@code comment} marking that a stored body reached the storage cap
     * and is a prefix, not the whole captured content. HAR is a citable
     * evidence artifact, so a capped body must say so rather than read as
     * complete (#23). The cap is reported so the reader knows how to recover the
     * full body ({@code BURP2API_MAX_STORED_CONTENT_CHARS}).
     */
    private String harTruncationNotice(String kind) {
        return "[TRUNCATED: " + kind + " body capped at " + config.getMaxStoredContentChars()
            + " characters - full body not captured; raise BURP2API_MAX_STORED_CONTENT_CHARS]";
    }

    /**
     * Generates HAR (HTTP Archive) format from traffic data.
     *
     * @param trafficData List of traffic records
     * @return HAR format map
     */
    private Map<String, Object> generateHarFormat(List<Map<String, Object>> trafficData) {
        Map<String, Object> har = new HashMap<>();
        
        // HAR version
        har.put("version", "1.2");
        
        // Creator info
        Map<String, Object> creator = new HashMap<>();
        creator.put("name", "burp2api");
        creator.put("version", "1.0.0");
        creator.put("comment", "Generated by burp2api - Burp Suite REST API Extension");
        
        // Browser info (optional)
        Map<String, Object> browser = new HashMap<>();
        browser.put("name", "Burp Suite Professional");
        browser.put("version", "2024.x");
        
        // Pages array (we'll use a single page)
        List<Map<String, Object>> pages = new ArrayList<>();
        Map<String, Object> page = new HashMap<>();
        page.put("startedDateTime", new java.util.Date().toInstant().toString());
        page.put("id", "page_1");
        page.put("title", "Burp Proxy Traffic");
        page.put("pageTimings", Map.of("onContentLoad", -1, "onLoad", -1));
        pages.add(page);
        
        // Entries array
        List<Map<String, Object>> entries = new ArrayList<>();
        
        for (Map<String, Object> record : trafficData) {
            try {
                Map<String, Object> entry = new HashMap<>();
                
                // Basic timing info
                String startedDateTime = record.get("timestamp") != null ? 
                    record.get("timestamp").toString() : new java.util.Date().toInstant().toString();
                entry.put("startedDateTime", startedDateTime);
                entry.put("time", 0); // Unknown timing
                
                // Request object
                Map<String, Object> request = new HashMap<>();
                request.put("method", record.getOrDefault("method", "GET"));
                request.put("url", record.getOrDefault("url", ""));
                request.put("httpVersion", "HTTP/1.1");
                
                // Parse headers
                List<Map<String, Object>> requestHeaders = parseHeadersForHar(
                    (String) record.getOrDefault("headers", "")
                );
                request.put("headers", requestHeaders);
                
                // Query string parameters (empty for now)
                request.put("queryString", new ArrayList<>());
                
                // Post data
                String body = (String) record.getOrDefault("body", "");
                if (!body.isEmpty()) {
                    Map<String, Object> postData = new HashMap<>();
                    postData.put("mimeType", "application/x-www-form-urlencoded");
                    postData.put("text", body);
                    if (StoredText.isCapped(body, config.getMaxStoredContentChars())) {
                        postData.put("comment", harTruncationNotice("request"));
                    }
                    request.put("postData", postData);
                }
                
                request.put("headersSize", -1);
                request.put("bodySize", body.length());
                
                entry.put("request", request);
                
                // Response object
                Map<String, Object> response = new HashMap<>();
                response.put("status", record.getOrDefault("status_code", 0));
                response.put("statusText", getStatusText((Integer) record.getOrDefault("status_code", 0)));
                response.put("httpVersion", "HTTP/1.1");
                
                // Parse response headers
                List<Map<String, Object>> responseHeaders = parseHeadersForHar(
                    (String) record.getOrDefault("response_headers", "")
                );
                response.put("headers", responseHeaders);
                
                // Response content. A binary/non-UTF-8 body is emitted Base64 with
                // the HAR-standard content.encoding marker so the archive stays
                // valid JSON and byte-accurate; UTF-8 text passes through verbatim.
                String responseBody = (String) record.getOrDefault("response_body", "");
                Map<String, Object> content = new HashMap<>();
                content.put("size", responseBody.length());
                content.put("mimeType", extractMimeType(responseHeaders));
                BodyCodec.EncodedBody encodedContent = BodyCodec.encodeStoredString(responseBody);
                content.put("text", encodedContent.body());
                if (encodedContent.isBase64()) {
                    content.put("encoding", "base64");
                }
                if (StoredText.isCapped(responseBody, config.getMaxStoredContentChars())) {
                    content.put("comment", harTruncationNotice("response"));
                }
                response.put("content", content);
                
                response.put("redirectURL", "");
                response.put("headersSize", -1);
                response.put("bodySize", responseBody.length());
                
                entry.put("response", response);
                
                // Cache and timings (minimal)
                entry.put("cache", Map.of());
                entry.put("timings", Map.of(
                    "blocked", -1,
                    "dns", -1,
                    "connect", -1,
                    "send", -1,
                    "wait", -1,
                    "receive", -1,
                    "ssl", -1
                ));
                
                // Page reference
                entry.put("pageref", "page_1");
                
                entries.add(entry);
                
            } catch (Exception e) {
                logger.warn("Failed to convert record to HAR entry: {}", e.getMessage());
            }
        }
        
        // Build final HAR structure
        Map<String, Object> log = new HashMap<>();
        log.put("version", "1.2");
        log.put("creator", creator);
        log.put("browser", browser);
        log.put("pages", pages);
        log.put("entries", entries);
        log.put("comment", "Exported from burp2api - Burp Suite REST API Extension");
        
        Map<String, Object> harRoot = new HashMap<>();
        harRoot.put("log", log);
        
        return harRoot;
    }
    
    /**
     * Adapts a stored header blob to the HAR header array shape. Parsing is
     * delegated to {@link HeaderList} — the single parser for stored headers —
     * so HAR export sees the same headers as {@code /proxy/search}. Splitting
     * the blob here on line breaks used to collapse a legacy
     * {@code List.toString()} blob into one bogus header (#20).
     */
    private List<Map<String, Object>> parseHeadersForHar(String headersString) {
        List<Map<String, Object>> headers = new ArrayList<>();
        for (Map<String, String> header : HeaderList.fromStoredString(headersString)) {
            headers.add(new HashMap<>(header));
        }
        return headers;
    }
    
    /**
     * Extracts MIME type from response headers.
     */
    private String extractMimeType(List<Map<String, Object>> headers) {
        for (Map<String, Object> header : headers) {
            String name = (String) header.get("name");
            if ("Content-Type".equalsIgnoreCase(name)) {
                String value = (String) header.get("value");
                if (value != null) {
                    // Extract just the MIME type part before any semicolon
                    int semicolon = value.indexOf(";");
                    return semicolon > 0 ? value.substring(0, semicolon).trim() : value.trim();
                }
            }
        }
        return "text/plain"; // Default MIME type
    }
    
    /**
     * Gets HTTP status text for a given status code.
     */
    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Unknown";
        }
    }
    
    /**
     * Registers collaborator-related routes.
     */
    private void registerCollaboratorRoutes(Javalin app) {
        // Delegate to CollaboratorRouteRegistrar with a shared, API-pollable client
        com.burp2api.services.CollaboratorService collaboratorService =
            new com.burp2api.services.CollaboratorService(api);
        CollaboratorRouteRegistrar collaboratorRegistrar =
            new CollaboratorRouteRegistrar(api, databaseService, config, collaboratorService);
        collaboratorRegistrar.registerRoutes(app);
    }
    
    /**
     * Registers session management routes for handling session tags.
     */
    private void registerSessionRoutes(Javalin app) {
        // Delegate to SessionRouteRegistrar
        SessionRouteRegistrar sessionRegistrar = new SessionRouteRegistrar(databaseService, config);
        sessionRegistrar.registerRoutes(app);

        // Inspect the per-session_tag cookie jar used by /proxy/send.
        app.get("/session/cookies", ctx -> {
            String sessionTag = sessionTagOrCurrent(ctx.queryParam("session_tag"));
            List<Map<String, Object>> cookies = new ArrayList<>();
            for (com.burp2api.utils.SessionCookieJar.StoredCookie c : cookieJar.snapshot(sessionTag)) {
                Map<String, Object> data = new HashMap<>();
                data.put("name", c.name());
                data.put("value", c.value());
                data.put("domain", c.domain());
                data.put("path", c.path());
                data.put("secure", c.secure());
                data.put("http_only", c.httpOnly());
                data.put("host_only", c.hostOnly());
                cookies.add(data);
            }
            ctx.json(Map.of(
                "session_tag", sessionTag,
                "cookies", cookies,
                "count", cookies.size(),
                "timestamp", System.currentTimeMillis()
            ));
        });

        // Reset (clear) the jar for a session tag.
        app.delete("/session/cookies", ctx -> {
            String sessionTag = sessionTagOrCurrent(ctx.queryParam("session_tag"));
            int cleared = cookieJar.snapshot(sessionTag).size();
            cookieJar.reset(sessionTag);
            ctx.json(Map.of(
                "session_tag", sessionTag,
                "cleared", cleared,
                "message", "Session cookie jar cleared",
                "timestamp", System.currentTimeMillis()
            ));
        });

        // Seed the jar for a session tag from cookies reconstructed from
        // captured proxy traffic for seed_host.
        app.post("/session/cookies", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                String seedHost = (String) requestData.get("seed_host");
                if (seedHost == null || seedHost.isBlank()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing seed_host",
                        "message", "Provide 'seed_host' to seed the jar from captured traffic",
                        "example", Map.of("session_tag", "my_session", "seed_host", "app.example.com")
                    ));
                    return;
                }
                String sessionTag = sessionTagOrCurrent((String) requestData.get("session_tag"));
                ReconstructedCookies reconstructed = reconstructCookiesForHost(seedHost.trim());
                int seeded = cookieJar.seed(sessionTag, reconstructed.result().cookies());
                ctx.json(Map.of(
                    "session_tag", sessionTag,
                    "seed_host", seedHost.trim(),
                    "seeded", seeded,
                    "exchanges_examined", reconstructed.exchangesExamined(),
                    "timestamp", System.currentTimeMillis()
                ));
            } catch (Exception e) {
                logger.error("Failed to seed session cookie jar", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to seed session cookie jar",
                    "message", e.getMessage()
                ));
            }
        });
    }

    /** Returns the supplied session tag, or the configured current tag when blank. */
    private String sessionTagOrCurrent(String sessionTag) {
        return (sessionTag == null || sessionTag.isBlank()) ? config.getSessionTag() : sessionTag;
    }
    
    /**
     * Registers traffic metadata routes for tagging, commenting, and replay functionality.
     */
    private void registerTrafficMetadataRoutes(Javalin app) {
        //=================================================================================
        // TRAFFIC METADATA ROUTES - Tagging, Comments, Replay
        //=================================================================================
        
        // OLD ENDPOINTS REMOVED - Now defined earlier to fix routing issue
        
        
        //=================================================================================
        // REQUEST BODY SEARCH
        //=================================================================================
        
        // Search request bodies using FTS5
        app.get("/proxy/search/request-body", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                String query = ctx.queryParam("q");
                if (query == null) {
                    query = ctx.queryParam("query"); // Fallback for backward compatibility
                }
                if (query == null || query.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing query parameter",
                        "message", "q parameter is required for request body search"
                    ));
                    return;
                }
                
                int limit = Integer.parseInt(ctx.queryParam("limit") != null ? ctx.queryParam("limit") : "100");
                int offset = Integer.parseInt(ctx.queryParam("offset") != null ? ctx.queryParam("offset") : "0");
                
                List<Map<String, Object>> results = databaseService.searchRequestBodies(query, limit, offset);
                
                Map<String, Object> response = new HashMap<>();
                response.put("results", results);
                response.put("count", results.size());
                response.put("query", query);
                response.put("limit", limit);
                response.put("offset", offset);
                response.put("fts5_available", databaseService.getConnection() != null && 
                    databaseService.getDatabasePerformanceMetrics().containsKey("request_fts5_available"));
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to search request bodies", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to search request bodies",
                    "message", e.getMessage()
                ));
            }
        });

        // #12: response-body full-text search. The response_index FTS5 table was
        // trigger-maintained for every normalized capture but had no consumer, so
        // this endpoint did not exist and "search response bodies" returned nothing
        // (a 404). Mirrors /proxy/search/request-body; matches by value (e.g. a
        // resource id echoed in an HTTP/2 response) and resolves hits to the public
        // proxy_traffic.id space for replay.
        app.get("/proxy/search/response-body", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;

            try {
                String query = ctx.queryParam("q");
                if (query == null) {
                    query = ctx.queryParam("query"); // Fallback for backward compatibility
                }
                if (query == null || query.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing query parameter",
                        "message", "q parameter is required for response body search"
                    ));
                    return;
                }

                int limit = Integer.parseInt(ctx.queryParam("limit") != null ? ctx.queryParam("limit") : "100");
                int offset = Integer.parseInt(ctx.queryParam("offset") != null ? ctx.queryParam("offset") : "0");

                List<Map<String, Object>> results = databaseService.searchResponseBodies(query, limit, offset);

                Map<String, Object> response = new HashMap<>();
                response.put("results", results);
                response.put("count", results.size());
                response.put("query", query);
                response.put("limit", limit);
                response.put("offset", offset);
                response.put("fts5_available",
                    Boolean.TRUE.equals(databaseService.getDatabasePerformanceMetrics().get("fts5_available")));

                ctx.json(response);

            } catch (Exception e) {
                logger.error("Failed to search response bodies", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to search response bodies",
                    "message", e.getMessage()
                ));
            }
        });

        //=================================================================================
        // SAVED QUERIES MANAGEMENT
        //=================================================================================
        
        //=================================================================================
        // REPLAY LINEAGE TRACKING
        //=================================================================================
        
        // Get replay lineage - find all requests replayed from an original
        app.get("/proxy/replay/lineage/{id}", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                long originalRequestId = Long.parseLong(ctx.pathParam("id"));
                
                List<Map<String, Object>> replayedRequests = databaseService.getReplayedFrom(originalRequestId);
                
                Map<String, Object> response = new HashMap<>();
                response.put("original_request_id", originalRequestId);
                response.put("replayed_requests", replayedRequests);
                response.put("replay_count", replayedRequests.size());
                
                ctx.json(response);
                
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid request ID",
                    "message", "Request ID must be a valid number"
                ));
            } catch (Exception e) {
                logger.error("Failed to get replay lineage", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get replay lineage",
                    "message", e.getMessage()
                ));
            }
        });
    }
    
    /**
     * Registers curl generation routes for converting requests to curl commands.
     */
    private void registerCurlGeneratorRoutes(Javalin app) {
        //=================================================================================
        // CURL GENERATOR ROUTES - Convert requests to curl commands
        //=================================================================================
        
        // Generate curl command for a specific request
        app.get("/proxy/request/{id}/curl", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                long requestId = Long.parseLong(ctx.pathParam("id"));
                
                // Get optional formatting parameters
                boolean redact = "true".equals(ctx.queryParam("redact"));
                boolean pretty = "true".equals(ctx.queryParam("pretty")); 
                String shell = ctx.queryParam("shell"); // bash, powershell, etc.
                boolean includeMetadata = "true".equals(ctx.queryParam("metadata"));
                
                // Generate curl command using proper utility
                Map<String, Object> curl = generateBasicCurl(requestId);

                if (curl != null) {
                    Object resolvedId = curl.get("resolved_id");
                    String resolvedVia = (String) curl.get("resolved_via");
                    Map<String, Object> response = new HashMap<>();
                    response.put("curl_command", curl.get("curl"));
                    // request_id echoes the public proxy_traffic.id the curl was
                    // built from; when the caller passed an internal traffic_meta
                    // id, resolved_via flags that and request_id names the id to
                    // reuse for /proxy/replay and friends (#22).
                    response.put("request_id", resolvedId != null ? resolvedId : requestId);
                    response.put("requested_id", requestId);
                    response.put("resolved_via", resolvedVia != null ? resolvedVia : "id");
                    response.put("options", Map.of(
                        "redacted", redact,
                        "pretty_printed", pretty,
                        "shell", shell != null ? shell : "bash",
                        "include_metadata", includeMetadata
                    ));

                    ctx.json(response);
                } else {
                    ctx.status(404).json(Map.of(
                        "error", "Request not found",
                        "message", "No captured request resolves to ID " + requestId
                            + " in the proxy_traffic id space that GET /proxy/search returns, "
                            + "and it is not an internal traffic_meta id with a linked capture. "
                            + "Confirm the id via GET /proxy/search, or reconstruct the request "
                            + "from that row's headers_list."
                    ));
                }
                
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid request ID", 
                    "message", "Request ID must be a valid number"
                ));
            } catch (Exception e) {
                logger.error("Failed to generate curl command", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to generate curl command",
                    "message", e.getMessage()
                ));
            }
        });

        // #24: byte-exact raw request/response for a stored row. The flattened
        // headers/body columns are a lossy projection (comma-valued headers can
        // shred, bodies round-trip through an ISO-8859-1 char cap); this serves
        // the exact wire bytes, base64-encoded, so a client decode reproduces
        // what Burp sent/received. A pre-v12 or over-cap row reports present:false.
        app.get("/proxy/history/{id}/raw", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;

            try {
                long id = Long.parseLong(ctx.pathParam("id"));
                DatabaseService.RawCaptureRow raw = databaseService.getRawCapture(id);

                if (raw == null) {
                    ctx.status(404).json(Map.of(
                        "error", "Request not found",
                        "message", "No traffic record found with ID: " + id
                    ));
                    return;
                }

                boolean requestPresent = raw.requestRaw != null;
                boolean responsePresent = raw.responseRaw != null;

                Map<String, Object> response = new HashMap<>();
                response.put("id", id);
                response.put("request_raw_present", requestPresent);
                response.put("response_raw_present", responsePresent);
                response.put("request_raw_omitted", raw.requestRawOmitted);
                response.put("response_raw_omitted", raw.responseRawOmitted);
                response.put("request_raw_b64",
                    requestPresent ? java.util.Base64.getEncoder().encodeToString(raw.requestRaw) : null);
                response.put("response_raw_b64",
                    responsePresent ? java.util.Base64.getEncoder().encodeToString(raw.responseRaw) : null);
                response.put("max_raw_bytes", config.getMaxRawBytes());

                if (!requestPresent && !responsePresent) {
                    response.put("note", (raw.requestRawOmitted || raw.responseRawOmitted)
                        ? "Raw capture omitted: message exceeded max_raw_bytes."
                        : "No raw capture for this row (captured before raw storage was added, "
                          + "or through a path that only had a reconstructed string).");
                }

                ctx.json(response);

            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid request ID",
                    "message", "Request ID must be a valid number"
                ));
            } catch (Exception e) {
                logger.error("Failed to read raw capture", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to read raw capture",
                    "message", e.getMessage()
                ));
            }
        });
    }

    /**
     * Helper method to safely format objects for logging
     */
    private String formatForLogging(Object obj) {
        if (obj == null) return "null";
        
        if (obj instanceof String) {
            return "\"" + obj + "\"";
        } else if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            if (map.isEmpty()) return "{}";
            
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(entry.getKey()).append("=");
                if (entry.getValue() instanceof String) {
                    sb.append("\"").append(entry.getValue()).append("\"");
                } else if (entry.getValue() instanceof List) {
                    sb.append(entry.getValue().toString());
                } else {
                    sb.append(entry.getValue());
                }
            }
            sb.append("}");
            return sb.toString();
        } else if (obj instanceof List) {
            return obj.toString();
        }
        
        return obj.toString();
    }
    
    /**
     * Extract host from URL string
     */
    /**
     * Validates that {@code url} is an absolute http(s) URL suitable for
     * {@link burp.api.montoya.http.message.requests.HttpRequest#httpRequestFromUrl}.
     * Returns {@code null} when valid, otherwise a human-readable reason.
     *
     * <p>The Montoya API rejects a non-URL token (e.g. {@code "--help"}) with an
     * opaque {@code IllegalArgumentException}; validating here lets callers
     * answer with a clean 400 instead of a 500 + stack trace. Static and
     * dependency-free so it is unit-testable without a live Burp.
     */
    static String validateHttpUrl(String url) {
        if (url == null || url.isBlank()) {
            return "url is required and must be a non-empty string";
        }
        final java.net.URI uri;
        try {
            uri = java.net.URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            return "url is not a valid URL: " + url;
        }
        String scheme = uri.getScheme();
        if (scheme == null
                || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            return "url must be an absolute http:// or https:// URL: " + url;
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            return "url must include a host: " + url;
        }
        return null;
    }

    public String extractHostFromUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return "";
        }
        
        try {
            // Remove protocol if present
            if (url.startsWith("http://")) {
                url = url.substring(7);
            } else if (url.startsWith("https://")) {
                url = url.substring(8);
            }
            
            // Extract host (before first slash or colon for port)
            int slashIndex = url.indexOf('/');
            int colonIndex = url.indexOf(':');
            
            int endIndex = url.length();
            if (slashIndex != -1) {
                endIndex = Math.min(endIndex, slashIndex);
            }
            if (colonIndex != -1) {
                endIndex = Math.min(endIndex, colonIndex);
            }
            
            return url.substring(0, endIndex);
        } catch (Exception e) {
            logger.warn("Failed to extract host from URL: {}", url, e);
            return "";
        }
    }

    /**
     * Extracts the request path (defaulting to "/") from a URL string.
     */
    private String extractPathFromUrl(String url) {
        if (url == null) {
            return "/";
        }
        try {
            String path = java.net.URI.create(url).getRawPath();
            return (path == null || path.isEmpty()) ? "/" : path;
        } catch (Exception e) {
            return "/";
        }
    }

    /**
     * Merges the session cookie jar's cookies for {@code sessionTag} into the
     * request's Cookie header (caller-supplied cookies win) for a request to
     * {@code url} / {@code host}. Returns the request unchanged when the jar
     * contributes nothing.
     */
    private burp.api.montoya.http.message.requests.HttpRequest applyCookieJar(
            burp.api.montoya.http.message.requests.HttpRequest httpRequest,
            String sessionTag, String url, String host) {
        String callerCookie = httpRequest.hasHeader("Cookie") ? httpRequest.headerValue("Cookie") : null;
        boolean https = url != null && url.toLowerCase().startsWith("https");
        String path = extractPathFromUrl(url);
        String merged = cookieJar.buildCookieHeader(sessionTag, host, path, https, callerCookie);
        if (merged == null || merged.isEmpty()) {
            return httpRequest;
        }
        return applyHeader(httpRequest, "Cookie", merged);
    }

    /**
     * Adds or updates a request header. Montoya's {@code withUpdatedHeader} only
     * updates a header that already exists; it does not add an absent one, so a
     * header the base request lacks (notably {@code Cookie}, which
     * {@code httpRequestFromUrl} never includes) would otherwise be silently
     * dropped before send. Use this wherever caller- or jar-supplied headers are
     * applied so novel headers actually reach the wire.
     */
    private static burp.api.montoya.http.message.requests.HttpRequest applyHeader(
            burp.api.montoya.http.message.requests.HttpRequest request, String name, String value) {
        return request.hasHeader(name)
            ? request.withUpdatedHeader(name, value)
            : request.withAddedHeader(name, value);
    }

    /** True for HTTP status codes that carry a Location redirect. */
    private static boolean isRedirectStatus(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /**
     * Resolves a redirect {@code Location} (absolute or relative) against the
     * current request URL. Returns null when it cannot be resolved.
     */
    private String resolveRedirectUrl(String baseUrl, String location) {
        try {
            return java.net.URI.create(baseUrl).resolve(location).toString();
        } catch (Exception e) {
            logger.warn("Failed to resolve redirect '{}' against '{}'", location, baseUrl);
            return null;
        }
    }

    /**
     * Parses the {@code max_redirects} option: default 5, clamped to 0..10.
     */
    private int parseMaxRedirects(Object raw) {
        int value = 5;
        if (raw instanceof Number n) {
            value = n.intValue();
        } else if (raw instanceof String s && !s.isBlank()) {
            try {
                value = Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        return Math.max(0, Math.min(value, 10));
    }

    /**
     * Generate interactive examples for documentation
     */
    private Map<String, Object> generateInteractiveExamples() {
        Map<String, Object> examples = new HashMap<>();
        examples.put("html", "<div class='interactive-examples'><h3>Try these examples:</h3>" +
                            "<p>Click any endpoint above to test it interactively</p></div>");
        examples.put("examples", List.of("GET /", "GET /health", "GET /version"));
        return examples;
    }
    
    /**
     * Generate endpoint examples
     */
    private Map<String, Object> generateEndpointExamples(String method, String path) {
        Map<String, Object> example = new HashMap<>();
        example.put("method", method);
        example.put("path", path);
        example.put("html", String.format("<div class='endpoint-example'>" +
                                         "<h4>%s %s</h4>" +
                                         "<p>Example usage and parameters</p>" +
                                         "</div>", method, path));
        return example;
    }
    
    /**
     * Register analytics routes
     */
    private void registerAnalyticsRoutes(Javalin app) {
        // Analytics routes would go here
        logger.debug("Analytics routes registration - placeholder");
    }
    
    /**
     * Get event broadcaster
     */
    public EventBroadcaster getEventBroadcaster() {
        return eventBroadcaster;
    }
    
    /**
     * Shutdown method
     */
    public void shutdown() {
        logger.info("RouteHandler shutting down");
        // Cleanup logic would go here
    }
    
    /**
     * Generate basic curl command for a request ID
     */
    private Map<String, Object> generateBasicCurl(long requestId) {
        try {
            // Get full request data from database. The lookup resolves the public
            // proxy_traffic.id /proxy/search returns and, on a miss, an internal
            // traffic_meta.id via its proxy_traffic_id link (#22).
            Map<String, Object> requestData = databaseService.getFullRequestDataForCurl(requestId);
            if (requestData == null) {
                logger.warn("No request found for ID: {}", requestId);
                return null;
            }

            // Convert database record to CurlGenerator.RequestData. getFullRequestDataForCurl
            // returns the request columns as request_headers/request_body; reading headers/body
            // here silently produced a curl command with no -H and no -d.
            CurlGenerator.RequestData curRequest = new CurlGenerator.RequestData(
                (String) requestData.get("method"),
                (String) requestData.get("url"),
                (String) requestData.get("request_headers"),
                (String) requestData.get("request_body"),
                (String) requestData.get("content_type")
            );

            // Generate curl command using the proper utility
            String curl = CurlGenerator.buildCurlCommand(curRequest);
            if (curl == null) {
                return null;
            }
            Map<String, Object> result = new HashMap<>();
            result.put("curl", curl);
            result.put("resolved_id", requestData.get("resolved_id"));
            result.put("resolved_via", requestData.get("resolved_via"));
            return result;
        } catch (Exception e) {
            logger.error("Failed to generate curl command for request {}: {}", requestId, e.getMessage());
            return null;
        }
    }
    
    /**
     * Refuses an annotation whose id cannot be trusted to mean one request.
     *
     * <p>Clients address traffic by the {@code proxy_traffic.id} the read
     * endpoints return, but tags and comments are stored on {@code traffic_meta},
     * which numbers its rows independently. Where the two disagree, writing the
     * annotation would label a different captured request and still report
     * success, so the request is rejected instead (#21).
     *
     * @return true when the caller must stop; a response has already been sent
     */
    /**
     * Parses an optional replay expectation (<code>{method?, url?}</code>) that a
     * caller uses to assert which request an id must resolve to, so a stray id
     * (e.g. an old <code>traffic_meta.id</code>) is refused rather than silently
     * replaying a different request (#28).
     *
     * @return the expected method/url (either key may be absent), or null if none
     */
    @SuppressWarnings("unchecked")
    private Map<String, String> parseExpect(Object raw) {
        if (!(raw instanceof Map)) {
            return null;
        }
        Map<?, ?> obj = (Map<?, ?>) raw;
        Map<String, String> expect = new HashMap<>();
        Object method = obj.get("method");
        Object url = obj.get("url");
        if (method != null) {
            expect.put("method", method.toString());
        }
        if (url != null) {
            expect.put("url", url.toString());
        }
        return expect.isEmpty() ? null : expect;
    }

    /**
     * Reject an annotation whose {@code proxy_traffic.id} names no captured
     * request (404). The misaligned-id case the stopgap once refused with 409 no
     * longer arises: annotations resolve through {@code proxy_traffic_id} and land
     * on the correct request instead (#21).
     */
    private boolean rejectUnknownTrafficId(Context ctx, long requestId) {
        if (databaseService.proxyTrafficExists(requestId)) {
            return false;
        }
        ctx.status(404).json(Map.of(
            "success", false,
            "error", "Unknown request_id",
            "request_id", requestId,
            "message", "No proxy traffic record has this id"
        ));
        return true;
    }

    /**
     * Apply request intercept rules manually for /proxy/send requests
     */
    private burp.api.montoya.http.message.requests.HttpRequest applyRequestInterceptRules(
            burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            Map<String, Map<String, Object>> rules = proxyInterceptionService.getAllRules();
            
            burp.api.montoya.http.message.requests.HttpRequest modifiedRequest = request;
            
            for (Map.Entry<String, Map<String, Object>> entry : rules.entrySet()) {
                Map<String, Object> rule = entry.getValue();
                
                // Only process REQUEST type rules that are enabled
                if (!"REQUEST".equals(rule.get("type")) || !Boolean.TRUE.equals(rule.get("enabled"))) {
                    continue;
                }
                
                // Check if condition matches
                if (matchesRequestCondition(rule, request)) {
                    // Apply the action
                    modifiedRequest = applyRequestAction(rule, modifiedRequest);
                    logger.debug("Applied API request rule '{}' to {}", rule.get("name"), request.url());
                }
            }
            
            return modifiedRequest;
            
        } catch (Exception e) {
            logger.error("Error applying request intercept rules to /proxy/send request", e);
            return request;
        }
    }
    
    /**
     * Apply response intercept rules manually for /proxy/send responses
     */
    private HttpResponse applyResponseInterceptRules(HttpResponse response) {
        try {
            Map<String, Map<String, Object>> rules = proxyInterceptionService.getAllRules();
            
            HttpResponse modifiedResponse = response;
            
            for (Map.Entry<String, Map<String, Object>> entry : rules.entrySet()) {
                Map<String, Object> rule = entry.getValue();
                
                // Only process RESPONSE type rules that are enabled
                if (!"RESPONSE".equals(rule.get("type")) || !Boolean.TRUE.equals(rule.get("enabled"))) {
                    continue;
                }
                
                // Check if condition matches
                if (matchesResponseCondition(rule, response)) {
                    // Apply the action
                    modifiedResponse = applyResponseAction(rule, modifiedResponse);
                    logger.debug("Applied API response rule '{}' to status {}", rule.get("name"), response.statusCode());
                }
            }
            
            return modifiedResponse;
            
        } catch (Exception e) {
            logger.error("Error applying response intercept rules to /proxy/send response", e);
            return response;
        }
    }
    
    /**
     * Check if request matches rule conditions (simplified version of ProxyInterceptionService logic)
     */
    private boolean matchesRequestCondition(Map<String, Object> rule, burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            Map<String, Object> conditions = (Map<String, Object>) rule.get("conditions");
            String conditionType = (String) conditions.get("type");
            
            if (conditionType == null) return false;
            
            switch (conditionType.toLowerCase()) {
                case "url_contains":
                    String urlPattern = (String) conditions.get("value");
                    return urlPattern != null && request.url().toLowerCase().contains(urlPattern.toLowerCase());
                    
                case "method_equals":
                    String methodPattern = (String) conditions.get("value");
                    return methodPattern != null && methodPattern.equalsIgnoreCase(request.method());
                    
                case "all":
                    return true;
                    
                case "none":
                    return false;
                    
                default:
                    return false;
            }
        } catch (Exception e) {
            logger.error("Error matching request condition", e);
            return false;
        }
    }
    
    /**
     * Check if response matches rule conditions (simplified version of ProxyInterceptionService logic)
     */
    private boolean matchesResponseCondition(Map<String, Object> rule, HttpResponse response) {
        try {
            Map<String, Object> conditions = (Map<String, Object>) rule.get("conditions");
            String conditionType = (String) conditions.get("type");
            
            if (conditionType == null) return false;
            
            switch (conditionType.toLowerCase()) {
                case "status_equals":
                    Integer statusCode = (Integer) conditions.get("value");
                    return statusCode != null && statusCode == response.statusCode();
                    
                case "all":
                    return true;
                    
                case "none":
                    return false;
                    
                default:
                    return false;
            }
        } catch (Exception e) {
            logger.error("Error matching response condition", e);
            return false;
        }
    }
    
    /**
     * Apply action to request (simplified version of ProxyInterceptionService logic)
     */
    private burp.api.montoya.http.message.requests.HttpRequest applyRequestAction(Map<String, Object> rule, burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            Map<String, Object> actions = (Map<String, Object>) rule.get("actions");
            String actionType = (String) actions.get("type");
            
            if (actionType == null) return request;
            
            switch (actionType.toLowerCase()) {
                case "add_header":
                    String headerName = (String) actions.get("header_name");
                    String headerValue = (String) actions.get("value");
                    if (headerName != null && headerValue != null) {
                        return request.withAddedHeader(headerName, headerValue);
                    }
                    break;
                    
                case "replace_header":
                    String replaceHeaderName = (String) actions.get("header_name");
                    String replaceHeaderValue = (String) actions.get("value");
                    if (replaceHeaderName != null && replaceHeaderValue != null) {
                        return request.withUpdatedHeader(replaceHeaderName, replaceHeaderValue);
                    }
                    break;
            }
        } catch (Exception e) {
            logger.error("Error applying request action", e);
        }
        return request;
    }
    
    /**
     * Apply action to response (simplified version of ProxyInterceptionService logic) 
     */
    private HttpResponse applyResponseAction(Map<String, Object> rule, HttpResponse response) {
        try {
            Map<String, Object> actions = (Map<String, Object>) rule.get("actions");
            String actionType = (String) actions.get("type");
            
            if (actionType == null) return response;
            
            switch (actionType.toLowerCase()) {
                case "add_header":
                    String headerName = (String) actions.get("header_name");
                    String headerValue = (String) actions.get("value");
                    if (headerName != null && headerValue != null) {
                        return response.withAddedHeader(headerName, headerValue);
                    }
                    break;
                    
                case "replace_header":
                    String replaceHeaderName = (String) actions.get("header_name");
                    String replaceHeaderValue = (String) actions.get("value");
                    if (replaceHeaderName != null && replaceHeaderValue != null) {
                        return response.withUpdatedHeader(replaceHeaderName, replaceHeaderValue);
                    }
                    break;
            }
        } catch (Exception e) {
            logger.error("Error applying response action", e);
        }
        return response;
    }
}
