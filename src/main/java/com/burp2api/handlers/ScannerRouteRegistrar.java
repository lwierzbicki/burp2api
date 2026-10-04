package com.burp2api.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.burp2api.config.ApiConfig;
import com.burp2api.database.DatabaseService;
import com.burp2api.services.ScanTaskManager;
import com.burp2api.utils.HeaderInput;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.Map;

/**
 * Responsible for registering scanner-related API routes.
 * Extracted from RouteHandler for modularity and maintainability.
 */
public class ScannerRouteRegistrar {
    private static final Logger logger = LoggerFactory.getLogger(ScannerRouteRegistrar.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final RouteHandler routeHandler; // For access to utility methods
    private final CollaboratorRouteRegistrar collaboratorRegistrar; // For interaction formatting
    private final ScanTaskManager scanTaskManager; // For task management
    private final com.burp2api.services.BurpRestScannerClient restScannerClient; // Burp built-in REST API backend
    
    /**
     * Constructor for ScannerRouteRegistrar
     * @param api The MontoyaApi instance
     * @param databaseService The database service for data persistence
     * @param config The API configuration
     * @param routeHandler The main RouteHandler for utility methods
     * @param scanTaskManager The scan task manager for task tracking
     */
    public ScannerRouteRegistrar(MontoyaApi api, DatabaseService databaseService, ApiConfig config, RouteHandler routeHandler, ScanTaskManager scanTaskManager) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
        this.routeHandler = routeHandler;
        this.collaboratorRegistrar = new CollaboratorRouteRegistrar(api, databaseService, config,
            new com.burp2api.services.CollaboratorService(api));
        this.scanTaskManager = scanTaskManager;
        this.restScannerClient = new com.burp2api.services.BurpRestScannerClient(
            config.getRestUrl(), config.getRestKey());
    }
    
    /**
     * Register all scanner-related routes.
     * @param app The Javalin app instance
     */
    public void registerRoutes(Javalin app) {
        // Get scanner issues with filtering
        app.get("/scanner/issues", ctx -> {
            try {
                // Get all issues from site map
                List<burp.api.montoya.scanner.audit.issues.AuditIssue> allIssues = api.siteMap().issues();
                
                // Extract filter parameters
                String severityFilter = ctx.queryParam("severity");
                String confidenceFilter = ctx.queryParam("confidence");
                String nameFilter = ctx.queryParam("name");
                String hostFilter = ctx.queryParam("host");
                String urlFilter = ctx.queryParam("url");
                boolean caseInsensitive = "true".equalsIgnoreCase(ctx.queryParam("case_insensitive"));
                
                // Extract pagination parameters
                int limit = ctx.queryParam("limit") != null ? Integer.parseInt(ctx.queryParam("limit")) : 1000;
                int offset = ctx.queryParam("offset") != null ? Integer.parseInt(ctx.queryParam("offset")) : 0;
                
                // Filter issues
                List<Map<String, Object>> filteredIssues = new ArrayList<>();
                for (burp.api.montoya.scanner.audit.issues.AuditIssue issue : allIssues) {
                    boolean matches = true;
                    
                    // Apply severity filter (case-insensitive partial match)
                    if (severityFilter != null && !severityFilter.isEmpty()) {
                        String issueSeverity = issue.severity().toString();
                        if (caseInsensitive) {
                            matches &= issueSeverity.toLowerCase().contains(severityFilter.toLowerCase());
                        } else {
                            matches &= issueSeverity.contains(severityFilter);
                        }
                    }
                    
                    // Apply confidence filter (case-insensitive partial match)
                    if (confidenceFilter != null && !confidenceFilter.isEmpty()) {
                        String issueConfidence = issue.confidence().toString();
                        if (caseInsensitive) {
                            matches &= issueConfidence.toLowerCase().contains(confidenceFilter.toLowerCase());
                        } else {
                            matches &= issueConfidence.contains(confidenceFilter);
                        }
                    }
                    
                    // Apply name filter (case-insensitive partial match)
                    if (nameFilter != null && !nameFilter.isEmpty()) {
                        String issueName = issue.name();
                        if (caseInsensitive) {
                            matches &= issueName.toLowerCase().contains(nameFilter.toLowerCase());
                        } else {
                            matches &= issueName.contains(nameFilter);
                        }
                    }
                    
                    // Apply host filter (case-insensitive partial match)
                    if (hostFilter != null && !hostFilter.isEmpty()) {
                        String issueHost = routeHandler.extractHostFromUrl(issue.baseUrl());
                        if (caseInsensitive) {
                            matches &= issueHost.toLowerCase().contains(hostFilter.toLowerCase());
                        } else {
                            matches &= issueHost.contains(hostFilter);
                        }
                    }
                    
                    // Apply URL filter (case-insensitive partial match)
                    if (urlFilter != null && !urlFilter.isEmpty()) {
                        String issueUrl = issue.baseUrl();
                        if (caseInsensitive) {
                            matches &= issueUrl.toLowerCase().contains(urlFilter.toLowerCase());
                        } else {
                            matches &= issueUrl.contains(urlFilter);
                        }
                    }
                    
                    if (matches) {
                        Map<String, Object> issueData = new HashMap<>();
                        issueData.put("name", issue.name());
                        issueData.put("detail", issue.detail());
                        issueData.put("severity", issue.severity().toString());
                        issueData.put("confidence", issue.confidence().toString());
                        issueData.put("base_url", issue.baseUrl());
                        issueData.put("host", routeHandler.extractHostFromUrl(issue.baseUrl()));
                        
                        // Add request/response information if available
                        if (!issue.requestResponses().isEmpty()) {
                            List<Map<String, Object>> requestResponses = new ArrayList<>();
                            for (burp.api.montoya.http.message.HttpRequestResponse reqResp : issue.requestResponses()) {
                                Map<String, Object> reqRespData = new HashMap<>();
                                reqRespData.put("request_length", reqResp.request().toByteArray().length());
                                reqRespData.put("response_length", reqResp.response() != null ? reqResp.response().toByteArray().length() : 0);
                                reqRespData.put("status_code", reqResp.response() != null ? reqResp.response().statusCode() : null);
                                requestResponses.add(reqRespData);
                            }
                            issueData.put("request_responses", requestResponses);
                        }
                        
                        // Add Collaborator interactions if available
                        if (!issue.collaboratorInteractions().isEmpty()) {
                            List<Map<String, Object>> collaboratorInteractions = new ArrayList<>();
                            for (Interaction interaction : issue.collaboratorInteractions()) {
                                collaboratorInteractions.add(collaboratorRegistrar.formatCollaboratorInteraction(interaction));
                            }
                            issueData.put("collaborator_interactions", collaboratorInteractions);
                            issueData.put("collaborator_interaction_count", collaboratorInteractions.size());
                        }
                        
                        filteredIssues.add(issueData);
                    }
                }
                
                // Apply pagination
                int totalCount = filteredIssues.size();
                int endIndex = Math.min(offset + limit, totalCount);
                List<Map<String, Object>> paginatedIssues = offset < totalCount ? 
                    filteredIssues.subList(offset, endIndex) : new ArrayList<>();
                
                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("issues", paginatedIssues);
                response.put("count", paginatedIssues.size());
                response.put("total_count", totalCount);
                
                // Add pagination metadata
                Map<String, Object> pagination = new HashMap<>();
                pagination.put("limit", limit);
                pagination.put("offset", offset);
                pagination.put("total_pages", (totalCount + limit - 1) / limit);
                pagination.put("current_page", (offset / limit) + 1);
                pagination.put("has_next", offset + limit < totalCount);
                pagination.put("has_previous", offset > 0);
                response.put("pagination", pagination);
                
                // Add applied filters
                Map<String, Object> filters = new HashMap<>();
                if (severityFilter != null) filters.put("severity", severityFilter);
                if (confidenceFilter != null) filters.put("confidence", confidenceFilter);
                if (nameFilter != null) filters.put("name", nameFilter);
                if (hostFilter != null) filters.put("host", hostFilter);
                if (urlFilter != null) filters.put("url", urlFilter);
                filters.put("case_insensitive", caseInsensitive);
                response.put("filters", filters);
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to retrieve scanner issues", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve scanner issues",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Get scanner queue status
        app.get("/scanner/queue", ctx -> {
            try {
                burp.api.montoya.scanner.Scanner scanner = api.scanner();
                
                // Note: The Montoya API doesn't provide direct queue enumeration
                // We can only provide limited information about scanning capabilities
                Map<String, Object> queueInfo = new HashMap<>();
                queueInfo.put("message", "Burp Montoya API provides limited queue visibility");
                queueInfo.put("api_limitation", "Direct queue enumeration not supported by Montoya API");
                queueInfo.put("available_operations", List.of(
                    "POST /scanner/scan-request - Scan individual requests",
                    "POST /scanner/scan-url-list - Scan multiple URLs",
                    "GET /scanner/issues - Retrieve scan results"
                ));
                queueInfo.put("timestamp", System.currentTimeMillis());
                
                // We could potentially track our own submitted scans in the database
                // but the API doesn't expose the internal Burp queue state
                queueInfo.put("note", "Use scan endpoints to submit new scans and check /scanner/issues for results");
                
                ctx.json(queueInfo);
                
            } catch (Exception e) {
                logger.error("Failed to get scanner queue status", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get scanner queue status",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Scan raw request
        app.post("/scanner/scan-request", ctx -> {
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
                // Accept headers as a JSON object, an array of [name, value] pairs,
                // or the legacy CRLF string. Normalize to a block for storage.
                List<HeaderInput.Header> headerList = HeaderInput.parse(requestData.get("headers"));
                String headers = HeaderInput.toBlock(headerList);
                String body = (String) requestData.getOrDefault("body", "");
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_scan");
                
                // Parse audit configuration if provided
                String auditConfig = (String) requestData.getOrDefault("audit_config", "LEGACY_ACTIVE_AUDIT_CHECKS");
                BuiltInAuditConfiguration builtInConfig;
                try {
                    builtInConfig = BuiltInAuditConfiguration.valueOf(auditConfig);
                } catch (IllegalArgumentException e) {
                    builtInConfig = BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
                }
                
                // Ticket #13: scope preflight. An audit against an out-of-scope
                // target is silently accepted but sends zero payload variations,
                // so confirm/add scope (auto_scope, default on) or block the scan.
                boolean autoScope = !"false".equalsIgnoreCase(
                    String.valueOf(requestData.getOrDefault("auto_scope", "true")));
                com.burp2api.services.ScopePreflight.Decision scopeDecision =
                    com.burp2api.services.ScopePreflight.decide(api.scope(), url, autoScope);
                if (scopeDecision == com.burp2api.services.ScopePreflight.Decision.BLOCKED) {
                    ctx.status(409).json(Map.of(
                        "error", "scan_would_send_zero_payloads",
                        "message", "Target is out of Burp's scope; an active scan would be "
                            + "silently accepted but send zero payload variations. Add the target "
                            + "to scope (e.g. POST /scope/import?type=include) or set auto_scope=true.",
                        "url", url,
                        "auto_scope", false
                    ));
                    return;
                }

                // Ticket #14: REST-first, throttled, param-fuzzer-preserving scanning.
                // backend=auto (default) and backend=rest prefer Burp's built-in REST
                // API with a named audit config + resource pool; backend=montoya forces
                // a Montoya audit. Extension-registered checks (param-fuzzer) run on
                // EITHER backend as long as the audit config includes them — verified
                // live: the default b2a-light-fuzz and Burp's default config do; the
                // built-in "Audit checks - light/medium active" presets do NOT.
                String backend = String.valueOf(requestData.getOrDefault("backend", "auto")).toLowerCase();

                // scan_configurations: absent -> default (b2a-light-fuzz); present
                // (including an explicit empty list -> Burp's default config) -> honored.
                boolean scanConfigsProvided = requestData.get("scan_configurations") instanceof List;
                List<?> scanConfigurations;
                if (scanConfigsProvided) {
                    scanConfigurations = (List<?>) requestData.get("scan_configurations");
                } else {
                    // #15: the default scan config may be a library NAME or a PATH to a
                    // config JSON exported from the Burp UI. A path is shipped inline as
                    // a CustomConfiguration so backend=auto works with an empty library.
                    Object defaultEntry;
                    try {
                        defaultEntry = com.burp2api.services.ScanConfigResolver
                            .resolveDefault(config.getScanConfig());
                    } catch (Exception e) {
                        logger.warn("Failed to read scan config file '{}', treating it as a "
                            + "config name: {}", config.getScanConfig(), e.getMessage());
                        defaultEntry = config.getScanConfig();
                    }
                    scanConfigurations = defaultEntry == null ? List.of() : List.of(defaultEntry);
                }

                // resource_pool: absent -> the throttle default; present (incl. "") honored.
                String requestedPool = requestData.get("resource_pool") != null
                    ? String.valueOf(requestData.get("resource_pool")) : null;
                String resourcePool = requestedPool != null ? requestedPool : config.getResourcePool();

                // The REST /scan path scans by URL and cannot replay a custom body, so
                // auto falls back to Montoya for non-GET / bodied requests to preserve
                // request fidelity. Explicit backend=rest still forces REST.
                boolean fidelityNeedsMontoya = (body != null && !body.isEmpty())
                    || !"GET".equalsIgnoreCase(method);
                boolean useRest = "rest".equals(backend)
                    || (!"montoya".equals(backend) && !fidelityNeedsMontoya);
                boolean restFellBack = false;

                if (useRest) {
                    if (restScannerClient.isAvailable()) {
                        try {
                            List<String> scopeInclude = autoScope ? List.of(url) : List.of();
                            Map<String, Object> scanBody = com.burp2api.services.RestScanMapper.buildScanBody(
                                List.of(url), scanConfigurations, resourcePool, scopeInclude);
                            String restTaskId = restScannerClient.startScan(scanBody);

                            long scanRecordId = databaseService.storeRawTraffic(
                                "SCAN_REQUEST_REST", url, routeHandler.extractHostFromUrl(url),
                                "Scan-Type: rest_scan\nResource-Pool: "
                                    + (resourcePool == null ? "default" : resourcePool) + "\n" + headers,
                                body, "", "", null, sessionTag);

                            Map<String, Object> response = new HashMap<>();
                            response.put("scan_initiated", true);
                            response.put("backend", "rest");
                            response.put("task_id", "rest_" + restTaskId);
                            response.put("task_status_url", "/scanner/tasks/rest_" + restTaskId);
                            response.put("target_url", url);
                            response.put("scoped", true);
                            response.put("scope_action", scopeDecision.name().toLowerCase());
                            response.put("scan_record_id", scanRecordId);
                            response.put("resource_pool", resourcePool);
                            response.put("scan_configurations", scanConfigurations);
                            response.put("session_tag", sessionTag);
                            // Extension checks (param-fuzzer) run only if the selected
                            // audit config includes them. Warn when a built-in
                            // "Audit checks - ..." preset is used, since those exclude them.
                            boolean usesBuiltinPreset = scanConfigurations.stream()
                                .map(String::valueOf)
                                .anyMatch(n -> n.toLowerCase().startsWith("audit checks - "));
                            response.put("extension_checks_note", usesBuiltinPreset
                                ? "A built-in 'Audit checks - ...' preset is selected; Burp's built-in "
                                    + "presets EXCLUDE extension-registered checks (e.g. param-fuzzer). "
                                    + "Use b2a-light-fuzz or Burp's default config to keep them."
                                : "Extension checks (e.g. param-fuzzer) run when the selected audit "
                                    + "config includes them (the default b2a-light-fuzz and Burp's "
                                    + "default config do).");
                            response.put("message", "Scan submitted to Burp built-in REST API. "
                                + "Poll task_status_url for scan_status.");
                            response.put("timestamp", System.currentTimeMillis());
                            ctx.json(response);
                            return;
                        } catch (Exception e) {
                            // e.g. the b2a-light-fuzz config is not in the library yet;
                            // fall back to a Montoya audit (LEGACY_ACTIVE runs param-fuzzer
                            // and honors the project resource pool for throttling).
                            logger.warn("Burp REST API scan start failed, falling back to Montoya: {}", e.getMessage());
                            restFellBack = true;
                        }
                    } else {
                        // REST-first default but the service is unreachable; fall back to
                        // a Montoya audit (also runs param-fuzzer, throttled by the
                        // project resource pool).
                        logger.info("Burp REST API backend unavailable; falling back to Montoya audit");
                        restFellBack = true;
                    }
                }

                // Create HTTP request
                HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url)
                    .withMethod(method)
                    .withBody(body);
                httpRequest = HeaderInput.applyTo(httpRequest, headerList);

                // Start audit scan
                Audit audit = api.scanner().startAudit(
                    burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(builtInConfig));
                audit.addRequest(httpRequest);
                
                // Store scan initiation in database for tracking
                long scanRecordId = databaseService.storeRawTraffic(
                    "SCAN_REQUEST", url, routeHandler.extractHostFromUrl(url), 
                    "Scan-Type: single_request\nAudit-Config: " + auditConfig + "\n" + headers, 
                    body, "", "", null, sessionTag
                );
                
                // Register with task manager if available
                String taskId = null;
                if (scanTaskManager != null && scanTaskManager.isReady()) {
                    Map<String, Object> taskConfig = new HashMap<>();
                    taskConfig.put("scan_type", "single_request");
                    taskConfig.put("target_url", url);
                    taskConfig.put("method", method);
                    taskConfig.put("audit_config", auditConfig);
                    taskConfig.put("scan_record_id", scanRecordId);
                    
                    try {
                        taskId = scanTaskManager.registerAudit(audit, taskConfig, sessionTag);
                    } catch (Exception e) {
                        logger.warn("Failed to register scan task with task manager", e);
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("scan_initiated", true);
                response.put("scan_record_id", scanRecordId);
                response.put("target_url", url);
                response.put("method", method);
                response.put("audit_config", auditConfig);
                response.put("session_tag", sessionTag);
                response.put("scoped", true);
                response.put("scope_action", scopeDecision.name().toLowerCase());
                response.put("backend", "montoya");
                if (restFellBack) {
                    response.put("rest_backend", "unavailable");
                }
                response.put("message", "Scan submitted to Burp Scanner. Check /scanner/issues for results.");
                response.put("timestamp", System.currentTimeMillis());
                
                if (taskId != null) {
                    response.put("task_id", taskId);
                    response.put("task_tracking", "enabled");
                    response.put("task_status_url", "/scanner/tasks/" + taskId);
                } else {
                    response.put("task_tracking", "disabled");
                    response.put("note", "Task tracking unavailable - check ScanTaskManager service");
                }
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to initiate scan", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to initiate scan",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Scan multiple URLs
        app.post("/scanner/scan-url-list", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Extract URLs - support both 'urls' array and single 'url'
                List<String> urls = new ArrayList<>();
                if (requestData.containsKey("urls")) {
                    Object urlsObj = requestData.get("urls");
                    if (urlsObj instanceof List) {
                        @SuppressWarnings("unchecked")
                        List<String> urlList = (List<String>) urlsObj;
                        urls.addAll(urlList);
                    } else {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid 'urls' format",
                            "message", "'urls' must be an array of strings"
                        ));
                        return;
                    }
                } else if (requestData.containsKey("url")) {
                    urls.add((String) requestData.get("url"));
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Either 'urls' (array) or 'url' (string) is required",
                        "required_fields", List.of("urls", "url")
                    ));
                    return;
                }
                
                if (urls.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "No URLs provided",
                        "message", "At least one URL must be provided"
                    ));
                    return;
                }
                
                // Extract optional parameters
                String method = (String) requestData.getOrDefault("method", "GET");
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_bulk_scan");
                // Ticket #13: scope preflight per URL (see /scanner/scan-request).
                boolean autoScope = !"false".equalsIgnoreCase(
                    String.valueOf(requestData.getOrDefault("auto_scope", "true")));
                
                // Parse audit configuration if provided
                String auditConfig = (String) requestData.getOrDefault("audit_config", "LEGACY_ACTIVE_AUDIT_CHECKS");
                BuiltInAuditConfiguration builtInConfig;
                try {
                    builtInConfig = BuiltInAuditConfiguration.valueOf(auditConfig);
                } catch (IllegalArgumentException e) {
                    builtInConfig = BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
                }
                
                // Start audit scan
                Audit audit = api.scanner().startAudit(
                    burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(builtInConfig));
                
                // Track scan results
                List<Map<String, Object>> scanResults = new ArrayList<>();
                List<Long> scanRecordIds = new ArrayList<>();
                
                // Process each URL
                for (String url : urls) {
                    try {
                        // Scope preflight: skip out-of-scope URLs that would scan
                        // as no-ops rather than silently sending zero payloads.
                        com.burp2api.services.ScopePreflight.Decision scopeDecision =
                            com.burp2api.services.ScopePreflight.decide(api.scope(), url, autoScope);
                        if (scopeDecision == com.burp2api.services.ScopePreflight.Decision.BLOCKED) {
                            Map<String, Object> skipped = new HashMap<>();
                            skipped.put("url", url);
                            skipped.put("method", method);
                            skipped.put("status", "skipped_out_of_scope");
                            scanResults.add(skipped);
                            continue;
                        }

                        // Create HTTP request for this URL
                        HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url)
                            .withMethod(method);

                        // Add request to audit
                        audit.addRequest(httpRequest);
                        
                        // Store scan initiation in database for tracking
                        long scanRecordId = databaseService.storeRawTraffic(
                            "SCAN_URL_LIST", url, routeHandler.extractHostFromUrl(url), 
                            "Scan-Type: bulk_scan\nAudit-Config: " + auditConfig + "\nMethod: " + method, 
                            "", "", "", null, sessionTag
                        );
                        scanRecordIds.add(scanRecordId);
                        
                        // Track individual scan result
                        Map<String, Object> scanResult = new HashMap<>();
                        scanResult.put("url", url);
                        scanResult.put("method", method);
                        scanResult.put("scan_record_id", scanRecordId);
                        scanResult.put("status", "submitted");
                        scanResults.add(scanResult);
                        
                    } catch (Exception e) {
                        logger.warn("Failed to process URL for scanning: {}", url, e);
                        
                        // Track failed scan result
                        Map<String, Object> scanResult = new HashMap<>();
                        scanResult.put("url", url);
                        scanResult.put("method", method);
                        scanResult.put("status", "failed");
                        scanResult.put("error", e.getMessage());
                        scanResults.add(scanResult);
                    }
                }
                
                // Register with task manager if available
                String taskId = null;
                if (scanTaskManager != null && scanTaskManager.isReady()) {
                    Map<String, Object> taskConfig = new HashMap<>();
                    taskConfig.put("scan_type", "bulk_scan");
                    taskConfig.put("urls", urls);
                    taskConfig.put("method", method);
                    taskConfig.put("audit_config", auditConfig);
                    taskConfig.put("scan_record_ids", scanRecordIds);
                    taskConfig.put("total_urls", urls.size());
                    
                    try {
                        taskId = scanTaskManager.registerAudit(audit, taskConfig, sessionTag);
                    } catch (Exception e) {
                        logger.warn("Failed to register bulk scan task with task manager", e);
                    }
                }
                
                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("bulk_scan_initiated", true);
                response.put("total_urls", urls.size());
                response.put("submitted_count", scanResults.stream().mapToInt(r -> "submitted".equals(r.get("status")) ? 1 : 0).sum());
                response.put("failed_count", scanResults.stream().mapToInt(r -> "failed".equals(r.get("status")) ? 1 : 0).sum());
                response.put("scan_record_ids", scanRecordIds);
                response.put("scan_results", scanResults);
                response.put("method", method);
                response.put("audit_config", auditConfig);
                response.put("session_tag", sessionTag);
                response.put("message", "Bulk scan submitted to Burp Scanner. Check /scanner/issues for results.");
                response.put("timestamp", System.currentTimeMillis());
                
                if (taskId != null) {
                    response.put("task_id", taskId);
                    response.put("task_tracking", "enabled");
                    response.put("task_status_url", "/scanner/tasks/" + taskId);
                } else {
                    response.put("task_tracking", "disabled");
                    response.put("note", "Task tracking unavailable - check ScanTaskManager service");
                }
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to initiate bulk scan", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to initiate bulk scan",
                    "message", e.getMessage()
                ));
            }
        });
        
        // POST /scanner/crawl - Start crawl with seed URLs
        app.post("/scanner/crawl", ctx -> {
            try {
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                
                // Extract seed URLs - support both 'urls' array and single 'url'
                List<String> seedUrls = new ArrayList<>();
                if (requestData.containsKey("urls")) {
                    Object urlsObj = requestData.get("urls");
                    if (urlsObj instanceof List) {
                        @SuppressWarnings("unchecked")
                        List<String> urlList = (List<String>) urlsObj;
                        seedUrls.addAll(urlList);
                    } else {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid 'urls' format",
                            "message", "'urls' must be an array of strings"
                        ));
                        return;
                    }
                } else if (requestData.containsKey("url")) {
                    seedUrls.add((String) requestData.get("url"));
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required fields",
                        "message", "Either 'urls' (array) or 'url' (string) is required",
                        "required_fields", List.of("urls", "url")
                    ));
                    return;
                }
                
                if (seedUrls.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "No URLs provided",
                        "message", "At least one seed URL must be provided"
                    ));
                    return;
                }
                
                // Validate URLs
                for (String url : seedUrls) {
                    if (url == null || url.trim().isEmpty()) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid URL",
                            "message", "All URLs must be non-empty strings"
                        ));
                        return;
                    }
                    // Basic URL validation
                    if (!url.startsWith("http://") && !url.startsWith("https://")) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid URL protocol",
                            "message", "URLs must start with http:// or https://",
                            "invalid_url", url
                        ));
                        return;
                    }
                }
                
                // Extract optional crawl configuration parameters
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_crawl");
                Integer maxDepth = requestData.containsKey("max_depth") ? 
                    Integer.parseInt(requestData.get("max_depth").toString()) : null;
                Integer maxDuration = requestData.containsKey("max_duration_minutes") ? 
                    Integer.parseInt(requestData.get("max_duration_minutes").toString()) : null;
                
                // Extract crawl optimization if provided
                String crawlOptimization = (String) requestData.getOrDefault("crawl_optimization", "NORMAL");
                
                // Validate limits
                if (maxDepth != null && (maxDepth < 1 || maxDepth > 20)) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid max_depth",
                        "message", "max_depth must be between 1 and 20",
                        "received", maxDepth
                    ));
                    return;
                }
                
                if (maxDuration != null && (maxDuration < 1 || maxDuration > 1440)) { // Max 24 hours
                    ctx.status(400).json(Map.of(
                        "error", "Invalid max_duration_minutes",
                        "message", "max_duration_minutes must be between 1 and 1440 (24 hours)",
                        "received", maxDuration
                    ));
                    return;
                }
                
                // Create crawl configuration with seed URLs using the correct static factory method
                CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(
                    seedUrls.toArray(new String[0])
                );
                
                // Start crawl
                Crawl crawl = api.scanner().startCrawl(crawlConfig);
                
                // Store crawl initiation in database for tracking
                String configSummary = String.format(
                    "Crawl-Type: standalone\nSeed-URLs: %s\nMax-Depth: %s\nMax-Duration: %s\nOptimization: %s",
                    String.join(", ", seedUrls),
                    maxDepth != null ? maxDepth.toString() : "default",
                    maxDuration != null ? maxDuration + "min" : "unlimited",
                    crawlOptimization
                );
                
                long crawlRecordId = databaseService.storeRawTraffic(
                    "CRAWLER_INITIATION", seedUrls.get(0), routeHandler.extractHostFromUrl(seedUrls.get(0)),
                    configSummary, "", "", "", null, sessionTag
                );
                
                // Register with task manager if available
                String taskId = null;
                if (scanTaskManager != null && scanTaskManager.isReady()) {
                    Map<String, Object> taskConfig = new HashMap<>();
                    taskConfig.put("scan_type", "crawl");
                    taskConfig.put("seed_urls", seedUrls);
                    taskConfig.put("max_depth", maxDepth);
                    taskConfig.put("max_duration_minutes", maxDuration);
                    taskConfig.put("crawl_optimization", crawlOptimization);
                    taskConfig.put("crawl_record_id", crawlRecordId);
                    
                    try {
                        taskId = scanTaskManager.registerCrawl(crawl, taskConfig, sessionTag);
                    } catch (Exception e) {
                        logger.warn("Failed to register crawl task with task manager", e);
                    }
                }
                
                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("crawl_initiated", true);
                response.put("crawl_record_id", crawlRecordId);
                response.put("seed_urls", seedUrls);
                response.put("seed_count", seedUrls.size());
                response.put("max_depth", maxDepth);
                response.put("max_duration_minutes", maxDuration);
                response.put("crawl_optimization", crawlOptimization);
                response.put("session_tag", sessionTag);
                response.put("message", "Crawl initiated successfully. Monitor progress via task tracking or WebSocket events.");
                response.put("timestamp", System.currentTimeMillis());
                
                if (taskId != null) {
                    response.put("task_id", taskId);
                    response.put("task_tracking", "enabled");
                    response.put("task_status_url", "/scanner/tasks/" + taskId);
                    response.put("progress_monitoring", "available via WebSocket and task status endpoint");
                } else {
                    response.put("task_tracking", "disabled");
                    response.put("note", "Task tracking unavailable - check ScanTaskManager service");
                }
                
                ctx.json(response);
                
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid numeric parameter",
                    "message", "max_depth and max_duration_minutes must be valid integers",
                    "details", e.getMessage()
                ));
            } catch (Exception e) {
                logger.error("Failed to initiate crawl", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to initiate crawl",
                    "message", e.getMessage()
                ));
            }
        });
        
        // New Task Management Endpoints
        
        // GET /scanner/tasks - List all scan tasks with filtering
        app.get("/scanner/tasks", ctx -> {
            try {
                // Extract query parameters
                String status = ctx.queryParam("status");
                String taskTypeStr = ctx.queryParam("task_type");
                String sessionTag = ctx.queryParam("session_tag");
                int limit = ctx.queryParam("limit") != null ? Integer.parseInt(ctx.queryParam("limit")) : 50;
                int offset = ctx.queryParam("offset") != null ? Integer.parseInt(ctx.queryParam("offset")) : 0;
                
                // Validate limit
                if (limit <= 0 || limit > 500) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid limit",
                        "message", "Limit must be between 1 and 500",
                        "received", limit
                    ));
                    return;
                }
                
                // Parse task type
                ScanTaskManager.TaskType taskType = null;
                if (taskTypeStr != null) {
                    try {
                        taskType = ScanTaskManager.TaskType.valueOf(taskTypeStr.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid task_type",
                            "message", "Valid task types: AUDIT, CRAWL, CRAWL_AND_AUDIT",
                            "received", taskTypeStr
                        ));
                        return;
                    }
                }
                
                if (scanTaskManager == null || !scanTaskManager.isReady()) {
                    ctx.status(503).json(Map.of(
                        "error", "ScanTaskManager not available",
                        "message", "Task management service is not initialized"
                    ));
                    return;
                }
                
                // Get tasks from task manager
                List<Map<String, Object>> tasks = scanTaskManager.listTasks(status, taskType, sessionTag, limit, offset);
                
                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("tasks", tasks);
                response.put("count", tasks.size());
                response.put("limit", limit);
                response.put("offset", offset);
                response.put("active_tasks", scanTaskManager.getActiveTaskCount());
                
                // Add applied filters
                Map<String, Object> filters = new HashMap<>();
                if (status != null) filters.put("status", status);
                if (taskType != null) filters.put("task_type", taskType.toString());
                if (sessionTag != null) filters.put("session_tag", sessionTag);
                response.put("filters", filters);
                
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid numeric parameter",
                    "message", "Limit and offset must be valid integers"
                ));
            } catch (Exception e) {
                logger.error("Failed to list scan tasks", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to list scan tasks",
                    "message", e.getMessage()
                ));
            }
        });
        
        // GET /scanner/tasks/{id} - Get specific scan task details
        app.get("/scanner/tasks/{id}", ctx -> {
            try {
                String taskId = ctx.pathParam("id");

                // Ticket #13 Phase 2: REST-backed tasks carry a "rest_" prefix and
                // are answered by proxying Burp's own scan_status/scan_metrics.
                if (taskId.startsWith("rest_")) {
                    Map<String, Object> restStatus = restScannerClient.getScanStatus(taskId.substring(5));
                    if (restStatus == null) {
                        ctx.status(404).json(Map.of(
                            "error", "Task not found",
                            "message", "No REST scan found with ID: " + taskId,
                            "task_id", taskId
                        ));
                        return;
                    }
                    restStatus.put("task_id", taskId);
                    restStatus.put("endpoint", "/scanner/tasks/" + taskId);
                    restStatus.put("timestamp", System.currentTimeMillis());
                    ctx.json(restStatus);
                    return;
                }

                if (scanTaskManager == null || !scanTaskManager.isReady()) {
                    ctx.status(503).json(Map.of(
                        "error", "ScanTaskManager not available",
                        "message", "Task management service is not initialized"
                    ));
                    return;
                }
                
                // Get task status from task manager
                Map<String, Object> taskStatus = scanTaskManager.getTaskStatus(taskId);
                
                if (taskStatus == null) {
                    ctx.status(404).json(Map.of(
                        "error", "Task not found",
                        "message", "No scan task found with ID: " + taskId,
                        "task_id", taskId
                    ));
                    return;
                }
                
                // Add metadata
                taskStatus.put("endpoint", "/scanner/tasks/" + taskId);
                taskStatus.put("timestamp", System.currentTimeMillis());
                
                ctx.json(taskStatus);
                
            } catch (Exception e) {
                logger.error("Failed to get scan task details", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get scan task details",
                    "message", e.getMessage()
                ));
            }
        });
        
        // DELETE /scanner/tasks/{id} - Cancel/delete a scan task
        app.delete("/scanner/tasks/{id}", ctx -> {
            try {
                String taskId = ctx.pathParam("id");
                
                if (scanTaskManager == null || !scanTaskManager.isReady()) {
                    ctx.status(503).json(Map.of(
                        "error", "ScanTaskManager not available",
                        "message", "Task management service is not initialized"
                    ));
                    return;
                }
                
                // Get task details before cancellation
                Map<String, Object> taskStatus = scanTaskManager.getTaskStatus(taskId);
                if (taskStatus == null) {
                    ctx.status(404).json(Map.of(
                        "error", "Task not found",
                        "message", "No scan task found with ID: " + taskId,
                        "task_id", taskId
                    ));
                    return;
                }
                
                // Attempt to cancel the task
                boolean cancelled = scanTaskManager.cancelTask(taskId);
                
                if (cancelled) {
                    Map<String, Object> response = new HashMap<>();
                    response.put("cancelled", true);
                    response.put("task_id", taskId);
                    response.put("previous_status", taskStatus.get("status"));
                    response.put("message", "Scan task cancelled successfully");
                    response.put("timestamp", System.currentTimeMillis());
                    response.put("note", "Task has been marked as CANCELLED in the database");
                    
                    ctx.json(response);
                    
                } else {
                    ctx.status(400).json(Map.of(
                        "error", "Failed to cancel task",
                        "message", "Task could not be cancelled - it may already be completed or failed",
                        "task_id", taskId,
                        "current_status", taskStatus.get("status")
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to cancel scan task", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to cancel scan task",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Enhanced scan endpoints
        registerEnhancedScanRoutes(app);
        
        // Report generation endpoints
        registerReportRoutes(app);
    }
    
    /**
     * Register enhanced scan routes with advanced configuration options
     */
    private void registerEnhancedScanRoutes(Javalin app) {
        
        // POST /scanner/enhanced-scan - Enhanced scan with advanced options
        app.post("/scanner/enhanced-scan", ctx -> {
            try {
                com.burp2api.models.ScanRequest scanRequest = ctx.bodyAsClass(com.burp2api.models.ScanRequest.class);
                
                // Validate scan request
                List<String> validationErrors = scanRequest.validate();
                if (!validationErrors.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Scan validation failed",
                        "validation_errors", validationErrors
                    ));
                    return;
                }
                
                // Initialize enhanced scanner if not already done
                com.burp2api.services.EnhancedScannerService enhancedScanner = 
                    new com.burp2api.services.EnhancedScannerService(api, databaseService, config, scanTaskManager);
                
                // Execute enhanced scan
                enhancedScanner.executeEnhancedScan(scanRequest)
                    .thenAccept(result -> {
                        logger.info("Enhanced scan started: {}", result.getScanId());
                    })
                    .exceptionally(throwable -> {
                        logger.error("Enhanced scan failed", throwable);
                        return null;
                    });
                
                Map<String, Object> response = new HashMap<>();
                response.put("scan_submitted", true);
                response.put("scan_type", scanRequest.getScanType().toString());
                response.put("audit_config", scanRequest.getAuditConfig());
                response.put("session_tag", scanRequest.getSessionTag());
                response.put("target_count", getTargetCount(scanRequest));
                response.put("optimization_strategy", 
                    scanRequest.getScanOptimization() != null ? 
                        scanRequest.getScanOptimization().getStrategy().toString() : "BALANCED");
                response.put("message", "Enhanced scan submitted. Use /scanner/enhanced-scan/status to monitor progress.");
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to start enhanced scan", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to start enhanced scan",
                    "message", e.getMessage()
                ));
            }
        });
        
        // GET /scanner/enhanced-scan/configurations - Get available scan configurations
        app.get("/scanner/enhanced-scan/configurations", ctx -> {
            try {
                Map<String, Object> configurations = new HashMap<>();
                
                // Audit configurations
                configurations.put("audit_configurations", List.of(
                    "LEGACY_PASSIVE_AUDIT_CHECKS",
                    "LEGACY_ACTIVE_AUDIT_CHECKS"
                ));
                
                // Scan types
                configurations.put("scan_types", List.of(
                    "AUDIT", "CRAWL", "PASSIVE", "COMBINED"
                ));
                
                // Optimization strategies
                configurations.put("optimization_strategies", List.of(
                    "FAST", "BALANCED", "THOROUGH", "CUSTOM"
                ));
                
                // Insertion point types
                configurations.put("insertion_point_types", List.of(
                    "PARAM_URL", "PARAM_BODY", "PARAM_COOKIE", "PARAM_XML",
                    "PARAM_XML_ATTR", "PARAM_MULTIPART_ATTR", "PARAM_JSON",
                    "PARAM_AMF", "HEADER", "PARAM_NAME_URL", "PARAM_NAME_BODY",
                    "ENTIRE_BODY", "URL_PATH_FILENAME", "URL_PATH_FOLDER",
                    "USER_PROVIDED", "EXTENSION_PROVIDED"
                ));
                
                // Authentication types
                configurations.put("authentication_types", List.of(
                    "NONE", "BASIC", "BEARER_TOKEN", "SESSION_COOKIES", "CUSTOM_HEADERS"
                ));
                
                // Crawl strategies
                configurations.put("crawl_strategies", List.of(
                    "FASTEST", "MOST_COMPLETE", "CUSTOM"
                ));
                
                // Forms handling options
                configurations.put("forms_handling", List.of(
                    "IGNORE_FORMS", "SUBMIT_FORMS", "PROMPT_FOR_FORMS"
                ));
                
                ctx.json(Map.of(
                    "status", "success",
                    "configurations", configurations,
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                logger.error("Failed to get scan configurations", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get scan configurations",
                    "message", e.getMessage()
                ));
            }
        });
        
        // GET /scanner/enhanced-scan/presets - Get predefined scan presets
        app.get("/scanner/enhanced-scan/presets", ctx -> {
            try {
                Map<String, Object> presets = new HashMap<>();
                
                // Quick scan preset
                Map<String, Object> quickScan = new HashMap<>();
                quickScan.put("name", "Quick Scan");
                quickScan.put("description", "Fast scanning with minimal checks");
                quickScan.put("scan_type", "AUDIT");
                quickScan.put("audit_config", "LEGACY_ACTIVE_AUDIT_CHECKS");
                quickScan.put("optimization_strategy", "FAST");
                quickScan.put("timeout_seconds", 300);
                quickScan.put("insertion_points", List.of("PARAM_URL", "PARAM_BODY", "HEADER"));
                
                // Thorough scan preset
                Map<String, Object> thoroughScan = new HashMap<>();
                thoroughScan.put("name", "Thorough Scan");
                thoroughScan.put("description", "Comprehensive scanning with all checks");
                thoroughScan.put("scan_type", "COMBINED");
                thoroughScan.put("audit_config", "LEGACY_ACTIVE_AUDIT_CHECKS");
                thoroughScan.put("optimization_strategy", "THOROUGH");
                thoroughScan.put("timeout_seconds", 3600);
                
                // Discovery scan preset
                Map<String, Object> discoveryScan = new HashMap<>();
                discoveryScan.put("name", "Discovery Scan");
                discoveryScan.put("description", "Content discovery and passive analysis");
                discoveryScan.put("scan_type", "CRAWL");
                discoveryScan.put("crawl_strategy", "MOST_COMPLETE");
                discoveryScan.put("max_link_depth", 5);
                discoveryScan.put("javascript_analysis", true);
                
                presets.put("quick_scan", quickScan);
                presets.put("thorough_scan", thoroughScan);
                presets.put("discovery_scan", discoveryScan);
                
                ctx.json(Map.of(
                    "status", "success",
                    "presets", presets,
                    "total_presets", presets.size(),
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                logger.error("Failed to get scan presets", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get scan presets",
                    "message", e.getMessage()
                ));
            }
        });
        
        // POST /scanner/enhanced-scan/validate - Validate scan configuration
        app.post("/scanner/enhanced-scan/validate", ctx -> {
            try {
                com.burp2api.models.ScanRequest scanRequest = ctx.bodyAsClass(com.burp2api.models.ScanRequest.class);
                
                List<String> validationErrors = scanRequest.validate();
                
                if (validationErrors.isEmpty()) {
                    Map<String, Object> response = new HashMap<>();
                    response.put("valid", true);
                    response.put("message", "Scan configuration is valid");
                    response.put("estimated_targets", getTargetCount(scanRequest));
                    response.put("estimated_duration_minutes", estimateScanDuration(scanRequest));
                    response.put("timestamp", System.currentTimeMillis());
                    
                    ctx.json(response);
                } else {
                    ctx.status(400).json(Map.of(
                        "valid", false,
                        "validation_errors", validationErrors,
                        "message", "Scan configuration validation failed"
                    ));
                }
                
            } catch (Exception e) {
                logger.error("Failed to validate scan configuration", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to validate scan configuration",
                    "message", e.getMessage()
                ));
            }
        });
        
        logger.info("Enhanced scanner routes registered");
    }
    
    /**
     * Get target count from scan request
     */
    private int getTargetCount(com.burp2api.models.ScanRequest scanRequest) {
        int count = 0;
        if (scanRequest.getUrl() != null) count++;
        if (scanRequest.getUrls() != null) count += scanRequest.getUrls().size();
        return count;
    }
    
    /**
     * Estimate scan duration based on configuration
     */
    private int estimateScanDuration(com.burp2api.models.ScanRequest scanRequest) {
        int baseMinutes = 10; // Base estimation
        int targetCount = getTargetCount(scanRequest);
        
        // Adjust based on scan type
        switch (scanRequest.getScanType()) {
            case CRAWL:
                baseMinutes = targetCount * 5;
                break;
            case AUDIT:
                baseMinutes = targetCount * 15;
                break;
            case COMBINED:
                baseMinutes = targetCount * 25;
                break;
            case PASSIVE:
                baseMinutes = targetCount * 2;
                break;
        }
        
        // Adjust based on optimization strategy
        if (scanRequest.getScanOptimization() != null) {
            switch (scanRequest.getScanOptimization().getStrategy()) {
                case FAST:
                    baseMinutes = (int) (baseMinutes * 0.5);
                    break;
                case THOROUGH:
                    baseMinutes = (int) (baseMinutes * 2.0);
                    break;
                case BALANCED:
                default:
                    // No adjustment
                    break;
            }
        }
        
        return Math.max(baseMinutes, 1); // At least 1 minute
    }
    
    /**
     * Register report generation routes
     */
    private void registerReportRoutes(Javalin app) {
        
        logger.info("Report generation routes registered");
    }
} 