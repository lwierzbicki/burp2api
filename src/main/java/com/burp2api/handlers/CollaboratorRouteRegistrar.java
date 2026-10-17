package com.burp2api.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.collaborator.InteractionFilter;
import com.burp2api.config.ApiConfig;
import com.burp2api.database.DatabaseService;
import com.burp2api.services.CollaboratorService;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Responsible for registering collaborator-related API routes.
 * Extracted from RouteHandler for modularity and maintainability.
 */
public class CollaboratorRouteRegistrar {
    private static final Logger logger = LoggerFactory.getLogger(CollaboratorRouteRegistrar.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final CollaboratorService collaboratorService;

    /**
     * Constructor for CollaboratorRouteRegistrar
     * @param api The MontoyaApi instance
     * @param databaseService The database service for data persistence
     * @param config The API configuration
     * @param collaboratorService Shared persistent Collaborator client for pollable payloads
     */
    public CollaboratorRouteRegistrar(MontoyaApi api, DatabaseService databaseService, ApiConfig config,
                                      CollaboratorService collaboratorService) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
        this.collaboratorService = collaboratorService;
    }
    
    /**
     * Register all collaborator-related routes.
     * @param app The Javalin app instance
     */
    public void registerRoutes(Javalin app) {
        // Collaborator status endpoint
        app.get("/collaborator/status", ctx -> {
            try {
                Map<String, Object> response = new HashMap<>();
                
                // Check if collaborator is available
                boolean isAvailable = true;
                String serverAddress = null;
                String statusMessage = "Collaborator is operational";
                
                try {
                    burp.api.montoya.collaborator.CollaboratorClient testClient = api.collaborator().createClient();
                    burp.api.montoya.collaborator.CollaboratorServer server = testClient.server();
                    if (server != null) {
                        serverAddress = server.address();
                    }
                } catch (IllegalStateException e) {
                    isAvailable = false;
                    statusMessage = "Collaborator is disabled or not configured";
                } catch (Exception e) {
                    isAvailable = false;
                    statusMessage = "Collaborator error: " + e.getMessage();
                }
                
                response.put("available", isAvailable);
                response.put("server_address", serverAddress);
                response.put("status", statusMessage);
                response.put("timestamp", Instant.now().toEpochMilli());
                
                ctx.json(response);
            } catch (Exception e) {
                logger.error("Error checking collaborator status", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to check collaborator status",
                    "message", e.getMessage()
                ));
            }
        });

        // NEW: Secret discovery endpoint
        app.get("/collaborator/discover-secrets", ctx -> {
            try {
                Map<String, Object> response = new HashMap<>();
                List<Map<String, Object>> discoveredSecrets = new ArrayList<>();
                
                // Create multiple clients and capture their secret keys
                int numClients = ctx.queryParam("count") != null ? 
                    Integer.parseInt(ctx.queryParam("count")) : 5;
                
                for (int i = 0; i < numClients; i++) {
                    try {
                        burp.api.montoya.collaborator.CollaboratorClient client = api.collaborator().createClient();
                        burp.api.montoya.collaborator.SecretKey secretKey = client.getSecretKey();
                        burp.api.montoya.collaborator.CollaboratorServer server = client.server();
                        
                        Map<String, Object> clientInfo = new HashMap<>();
                        clientInfo.put("client_index", i);
                        clientInfo.put("secret_key", secretKey.toString());
                        clientInfo.put("server_address", server.address());
                        clientInfo.put("created_timestamp", Instant.now().toEpochMilli());
                        
                        // Generate sample hostname to verify
                        try {
                            burp.api.montoya.collaborator.CollaboratorPayload payload = client.generatePayload();
                            clientInfo.put("sample_hostname", payload.toString());
                        } catch (Exception e) {
                            clientInfo.put("payload_error", e.getMessage());
                        }
                        
                        discoveredSecrets.add(clientInfo);
                        
                    } catch (Exception e) {
                        logger.warn("Failed to create collaborator client {}: {}", i, e.getMessage());
                    }
                }
                
                response.put("discovered_secrets", discoveredSecrets);
                response.put("total_discovered", discoveredSecrets.size());
                response.put("timestamp", Instant.now().toEpochMilli());
                
                // Try to access internal collaborator state through reflection
                Map<String, Object> reflectionAttempts = new HashMap<>();
                try {
                    // Get the collaborator API object
                    Object collaboratorApi = api.collaborator();
                    Class<?> collaboratorClass = collaboratorApi.getClass();
                    
                    reflectionAttempts.put("collaborator_class", collaboratorClass.getName());
                    reflectionAttempts.put("collaborator_methods", 
                        java.util.Arrays.stream(collaboratorClass.getMethods())
                            .map(m -> m.getName())
                            .collect(java.util.stream.Collectors.toList()));
                    
                    // Try to find fields that might contain existing clients
                    reflectionAttempts.put("collaborator_fields",
                        java.util.Arrays.stream(collaboratorClass.getDeclaredFields())
                            .map(f -> f.getName() + ":" + f.getType().getSimpleName())
                            .collect(java.util.stream.Collectors.toList()));
                            
                } catch (Exception e) {
                    reflectionAttempts.put("reflection_error", e.getMessage());
                }
                response.put("reflection_attempts", reflectionAttempts);
                
                ctx.json(response);
                
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid count parameter",
                    "message", "Count must be a valid integer"
                ));
            } catch (Exception e) {
                logger.error("Error in secret discovery", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to discover secrets",
                    "message", e.getMessage()
                ));
            }
        });

        // NEW: Global interactions endpoint using discovered secrets
        app.get("/collaborator/global-interactions", ctx -> {
            try {
                // Get secret keys from query params or stored cache
                String secretKeysParam = ctx.queryParam("secret_keys");
                if (secretKeysParam == null || secretKeysParam.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing secret_keys parameter",
                        "message", "Provide comma-separated secret keys to query global interactions",
                        "example", "/collaborator/global-interactions?secret_keys=key1,key2,key3"
                    ));
                    return;
                }
                
                String[] secretKeys = secretKeysParam.split(",");
                List<Map<String, Object>> allInteractions = new ArrayList<>();
                Map<String, Object> secretResults = new HashMap<>();
                
                for (String secretKey : secretKeys) {
                    secretKey = secretKey.trim();
                    if (secretKey.isEmpty()) continue;
                    
                    try {
                        // Restore client from secret key
                        burp.api.montoya.collaborator.CollaboratorClient client = 
                            api.collaborator().restoreClient(burp.api.montoya.collaborator.SecretKey.secretKey(secretKey));
                        
                        // Get all interactions for this client
                        List<burp.api.montoya.collaborator.Interaction> interactions = client.getAllInteractions();
                        
                        Map<String, Object> secretResult = new HashMap<>();
                        secretResult.put("secret_key", secretKey.substring(0, 8) + "...");
                        secretResult.put("interaction_count", interactions.size());
                        
                        List<Map<String, Object>> formattedInteractions = new ArrayList<>();
                        for (burp.api.montoya.collaborator.Interaction interaction : interactions) {
                            formattedInteractions.add(formatCollaboratorInteraction(interaction));
                        }
                        
                        secretResult.put("interactions", formattedInteractions);
                        allInteractions.addAll(formattedInteractions);
                        secretResults.put("secret_" + secretKey.substring(0, 8), secretResult);
                        
                    } catch (Exception e) {
                        secretResults.put("secret_" + secretKey.substring(0, 8), Map.of(
                            "error", e.getMessage(),
                            "secret_key", secretKey.substring(0, 8) + "..."
                        ));
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("total_interactions", allInteractions.size());
                response.put("total_secrets_processed", secretKeys.length);
                response.put("secret_results", secretResults);
                response.put("all_interactions", allInteractions);
                response.put("timestamp", Instant.now().toEpochMilli());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Error retrieving global collaborator interactions", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve global interactions",
                    "message", e.getMessage()
                ));
            }
        });

        // POST /collaborator/payloads - Generate API-pollable payloads from the shared client
        app.post("/collaborator/payloads", ctx -> {
            try {
                Map<String, Object> requestData = new HashMap<>();

                // Try to parse JSON body, but don't fail if it's empty or invalid
                try {
                    String body = ctx.body();
                    if (body != null && !body.trim().isEmpty()) {
                        requestData = ctx.bodyAsClass(Map.class);
                    }
                } catch (Exception e) {
                    logger.debug("No valid JSON body provided, using defaults: {}", e.getMessage());
                    // Continue with empty requestData - this is fine
                }

                // Parse options
                String customData = (String) requestData.get("custom_data");
                @SuppressWarnings("unchecked")
                List<String> optionStrings = (List<String>) requestData.getOrDefault("options", new ArrayList<>());
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_collaborator_payloads");
                int count = Integer.parseInt(requestData.getOrDefault("count", "1").toString());

                // Validate count
                if (count <= 0 || count > 50) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid count",
                        "message", "Count must be between 1 and 50",
                        "received", count
                    ));
                    return;
                }

                // Parse payload options
                List<burp.api.montoya.collaborator.PayloadOption> options = new ArrayList<>();
                for (String optionStr : optionStrings) {
                    try {
                        options.add(burp.api.montoya.collaborator.PayloadOption.valueOf(optionStr.toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid payload option",
                            "message", "Unknown payload option: " + optionStr,
                            "valid_options", List.of("INCLUDE_COLLABORATOR_SERVER_LOCATION", "EXCLUDE_COLLABORATOR_SERVER_LOCATION")
                        ));
                        return;
                    }
                }

                burp.api.montoya.collaborator.PayloadOption[] optionArray =
                    options.toArray(new burp.api.montoya.collaborator.PayloadOption[0]);
                List<Map<String, Object>> generatedPayloads = new ArrayList<>();

                // Generate payloads from the shared, API-pollable client
                for (int i = 0; i < count; i++) {
                    try {
                        burp.api.montoya.collaborator.CollaboratorPayload payload =
                            collaboratorService.generatePayload(customData, optionArray);

                        // Extract payload information
                        Map<String, Object> payloadInfo = new HashMap<>();
                        payloadInfo.put("payload", payload.toString());
                        payloadInfo.put("interaction_id", payload.id().toString());
                        payloadInfo.put("poll_url", "/collaborator/interactions?payload=" + payload.toString());

                        if (payload.customData().isPresent()) {
                            payloadInfo.put("custom_data", payload.customData().get());
                        }

                        if (payload.server().isPresent()) {
                            burp.api.montoya.collaborator.CollaboratorServer server = payload.server().get();
                            Map<String, Object> serverInfo = new HashMap<>();
                            serverInfo.put("address", server.address());
                            serverInfo.put("is_literal_address", server.isLiteralAddress());
                            payloadInfo.put("server", serverInfo);
                        }

                        generatedPayloads.add(payloadInfo);

                        // Store payload generation in database for tracking (never store the client secret)
                        if (databaseService != null && databaseService.isInitialized()) {
                            databaseService.storeRawTraffic(
                                "COLLABORATOR_PAYLOADS", payload.toString(), "collaborator_server",
                                "Interaction-ID: " + payload.id().toString() +
                                (payload.customData().isPresent() ? "\nCustom-Data: " + payload.customData().get() : "") +
                                "\nOptions: " + String.join(",", optionStrings) + "\nGenerator-Type: api_client",
                                "", "", "", null, sessionTag
                            );
                        }

                    } catch (Exception e) {
                        logger.error("Failed to generate collaborator payload {}", i + 1, e);
                        break;
                    }
                }

                Map<String, Object> response = new HashMap<>();
                response.put("payloads_generated", generatedPayloads.size());
                response.put("payloads", generatedPayloads);
                response.put("generator_type", "api_client");
                // #12: these payloads come from a private API Collaborator client,
                // not Burp's default (interactive) client, so they never appear in
                // the operator's Collaborator tab and API polling *consumes* their
                // interactions. Flag that explicitly so an operator watching the UI
                // does not assume a silent OOB means "no hit". To keep the hit
                // visible in the tab, mint the payload there (or via
                // POST /collaborator/payloads/url) and fire that value instead.
                response.put("ui_visible", false);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                response.put("note", "API-client payloads: NOT shown in Burp's interactive Collaborator tab. "
                    + "Poll via GET /collaborator/interactions?payload=<payload> (no client_secret needed); "
                    + "API polling consumes interactions. For a UI-visible hit, use "
                    + "POST /collaborator/payloads/url and poll your own Collaborator tab.");

                ctx.json(response);

            } catch (IllegalStateException e) {
                logger.error("Collaborator service not available", e);
                ctx.status(503).json(Map.of(
                    "error", "Collaborator not available",
                    "message", "Burp Collaborator is disabled or not configured",
                    "burp_requirement", "Burp Suite Professional with Collaborator enabled"
                ));
            } catch (Exception e) {
                logger.error("Failed to generate collaborator payloads", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to generate collaborator payloads",
                    "message", e.getMessage()
                ));
            }
        });
        
        // POST /collaborator/payloads/url - Generate single URL (plain text, like copy to clipboard)
        app.post("/collaborator/payloads/url", ctx -> {
            try {
                // Use Burp's default payload generator to create a URL that shows in Collaborator tab
                burp.api.montoya.collaborator.CollaboratorPayloadGenerator defaultGenerator = 
                    api.collaborator().defaultPayloadGenerator();
                
                // Generate a single payload
                burp.api.montoya.collaborator.CollaboratorPayload payload = defaultGenerator.generatePayload();
                
                // Store in database for tracking
                String sessionTag = config.getSessionTag() + "_collaborator_url";
                
                try {
                    databaseService.storeRawTraffic(
                        "COLLABORATOR_URL", payload.toString(), "collaborator_server",
                        "Interaction-ID: " + payload.id().toString() + 
                        "\nGenerator-Type: url_single" +
                        "\nGenerated-Via: POST /collaborator/payloads/url",
                        "", "", "", null, sessionTag
                    );
                } catch (Exception e) {
                    logger.debug("Failed to store collaborator URL generation", e);
                    // Don't fail the request if storage fails
                }
                
                // Return just the URL as plain text (like copy to clipboard)
                ctx.contentType("text/plain").result(payload.toString());
                
            } catch (IllegalStateException e) {
                logger.error("Collaborator service not available", e);
                ctx.status(503).contentType("text/plain").result("ERROR: Burp Collaborator is disabled or not configured");
            } catch (Exception e) {
                logger.error("Failed to generate collaborator URL", e);
                ctx.status(500).contentType("text/plain").result("ERROR: Failed to generate collaborator URL");
            }
        });
        
        // POST /collaborator/payloads/client - Create pollable collaborator client with payloads
        app.post("/collaborator/payloads/client", ctx -> {
            try {
                Map<String, Object> requestData = new HashMap<>();
                
                // Try to parse JSON body
                try {
                    String body = ctx.body();
                    if (body != null && !body.trim().isEmpty()) {
                        requestData = ctx.bodyAsClass(Map.class);
                    }
                } catch (Exception e) {
                    logger.debug("No valid JSON body provided, using defaults: {}", e.getMessage());
                }
                
                // Create custom collaborator client (allows API polling)
                burp.api.montoya.collaborator.CollaboratorClient client = api.collaborator().createClient();
                
                // Parse parameters
                String customData = (String) requestData.get("custom_data");
                @SuppressWarnings("unchecked")
                List<String> optionStrings = (List<String>) requestData.getOrDefault("options", new ArrayList<>());
                String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_api_client");
                int count = Integer.parseInt(requestData.getOrDefault("count", "1").toString());
                
                // Validate count
                if (count <= 0 || count > 50) {
                    ctx.status(400).json(Map.of(
                        "error", "Invalid count",
                        "message", "Count must be between 1 and 50",
                        "received", count
                    ));
                    return;
                }
                
                // Parse payload options
                List<burp.api.montoya.collaborator.PayloadOption> options = new ArrayList<>();
                for (String optionStr : optionStrings) {
                    try {
                        options.add(burp.api.montoya.collaborator.PayloadOption.valueOf(optionStr.toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        ctx.status(400).json(Map.of(
                            "error", "Invalid payload option",
                            "message", "Unknown payload option: " + optionStr,
                            "valid_options", List.of("INCLUDE_COLLABORATOR_SERVER_LOCATION", "EXCLUDE_COLLABORATOR_SERVER_LOCATION")
                        ));
                        return;
                    }
                }
                
                List<Map<String, Object>> generatedPayloads = new ArrayList<>();
                
                // Generate payloads using custom client
                for (int i = 0; i < count; i++) {
                    try {
                        burp.api.montoya.collaborator.CollaboratorPayload payload = 
                            client.generatePayload(options.toArray(new burp.api.montoya.collaborator.PayloadOption[0]));
                        
                        // Extract payload information
                        Map<String, Object> payloadInfo = new HashMap<>();
                        payloadInfo.put("payload", payload.toString());
                        payloadInfo.put("interaction_id", payload.id().toString());
                        
                        if (payload.customData().isPresent()) {
                            payloadInfo.put("custom_data", payload.customData().get());
                        }
                        
                        if (payload.server().isPresent()) {
                            burp.api.montoya.collaborator.CollaboratorServer server = payload.server().get();
                            Map<String, Object> serverInfo = new HashMap<>();
                            serverInfo.put("address", server.address());
                            serverInfo.put("is_literal_address", server.isLiteralAddress());
                            payloadInfo.put("server", serverInfo);
                        }
                        
                        generatedPayloads.add(payloadInfo);
                        
                        // Store in database for tracking
                        if (databaseService != null && databaseService.isInitialized()) {
                            databaseService.storeRawTraffic(
                                "COLLABORATOR_CLIENT", payload.toString(), "collaborator_server",
                                "Interaction-ID: " + payload.id().toString() + 
                                (payload.customData().isPresent() ? "\nCustom-Data: " + payload.customData().get() : "") +
                                "\nClient-Secret: " + client.getSecretKey().toString() +
                                "\nGenerator-Type: custom_client",
                                "", "", "", null, sessionTag
                            );
                        }
                        
                    } catch (Exception e) {
                        logger.error("Failed to generate client payload {}", i + 1, e);
                        break;
                    }
                }
                
                Map<String, Object> response = new HashMap<>();
                response.put("client_secret", client.getSecretKey().toString());
                response.put("payloads_generated", generatedPayloads.size());
                response.put("payloads", generatedPayloads);
                response.put("generator_type", "custom_client");
                // #12: a fresh API client, like POST /collaborator/payloads, is not
                // Burp's interactive client — its payloads never surface in the
                // Collaborator tab and API polling consumes the interactions.
                response.put("ui_visible", false);
                response.put("session_tag", sessionTag);
                response.put("timestamp", System.currentTimeMillis());
                response.put("note", "Custom API-client payloads: NOT shown in Burp's interactive Collaborator tab. "
                    + "Use client_secret to poll via API; polling consumes interactions. "
                    + "For a UI-visible hit, use POST /collaborator/payloads/url and poll your own tab.");
                response.put("usage", "GET /collaborator/interactions?client_secret=" + client.getSecretKey().toString().substring(0, 20) + "...");
                
                ctx.json(response);
                
            } catch (IllegalStateException e) {
                logger.error("Collaborator service not available", e);
                ctx.status(503).json(Map.of(
                    "error", "Collaborator not available",
                    "message", "Burp Collaborator is disabled or not configured",
                    "burp_requirement", "Burp Suite Professional with Collaborator enabled"
                ));
            } catch (Exception e) {
                logger.error("Failed to create collaborator client", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to create collaborator client",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Get Collaborator interactions. Defaults to the shared API client so payloads
        // minted via POST /collaborator/payloads are pollable without a client_secret.
        app.get("/collaborator/interactions", ctx -> {
            try {
                // Optional filters / overrides
                String clientSecret = ctx.queryParam("client_secret");
                String payload = ctx.queryParam("payload");
                String interactionId = ctx.queryParam("interaction_id");
                String sessionTag = ctx.queryParam("session_tag");

                boolean useSharedClient = (clientSecret == null || clientSecret.trim().isEmpty());

                // Resolve the client: shared API client by default, or a restored custom client
                burp.api.montoya.collaborator.CollaboratorClient client;
                if (useSharedClient) {
                    client = collaboratorService.client();
                } else {
                    SecretKey key = SecretKey.secretKey(clientSecret.trim());
                    client = api.collaborator().restoreClient(key);
                }

                // Apply filters server-side via Burp's InteractionFilter
                List<Interaction> interactions;
                if (interactionId != null && !interactionId.trim().isEmpty()) {
                    interactions = client.getInteractions(InteractionFilter.interactionIdFilter(interactionId.trim()));
                } else if (payload != null && !payload.trim().isEmpty()) {
                    interactions = client.getInteractions(InteractionFilter.interactionPayloadFilter(payload.trim()));
                } else {
                    interactions = client.getAllInteractions();
                }

                // Format interactions for API response
                List<Map<String, Object>> formattedInteractions = interactions.stream()
                    .map(this::formatCollaboratorInteraction)
                    .collect(Collectors.toList());

                Map<String, Object> response = new HashMap<>();
                response.put("interactions", formattedInteractions);
                response.put("count", formattedInteractions.size());
                response.put("source", useSharedClient ? "api_client" : "client_secret");
                response.put("timestamp", System.currentTimeMillis());

                if (sessionTag != null) {
                    response.put("session_tag", sessionTag);
                }

                ctx.json(response);

                // Store interaction retrieval in database for audit (never store the client secret)
                if (databaseService != null && databaseService.isInitialized()) {
                    String auditSessionTag = sessionTag != null ? sessionTag : config.getSessionTag() + "_collaborator_interactions";
                    try {
                        databaseService.storeRawTraffic(
                            "COLLABORATOR_INTERACTIONS", "/collaborator/interactions", "api_server",
                            "Source: " + (useSharedClient ? "api_client" : "client_secret") + "\n" +
                            "Interactions-Retrieved: " + formattedInteractions.size() + "\n" +
                            "Filters-Applied: " +
                            (payload != null ? "payload=" + payload + " " : "") +
                            (interactionId != null ? "interaction_id=" + interactionId + " " : "") +
                            "API-Endpoint: /collaborator/interactions",
                            "", "", "", null, auditSessionTag
                        );
                    } catch (Exception e) {
                        logger.debug("Failed to store collaborator interaction retrieval audit", e);
                        // Don't fail the request if audit storage fails
                    }
                }

            } catch (IllegalStateException e) {
                logger.error("Collaborator service not available", e);
                ctx.status(503).json(Map.of(
                    "error", "Collaborator not available",
                    "message", "Burp Collaborator is disabled or not configured",
                    "burp_requirement", "Burp Suite Professional with Collaborator enabled"
                ));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid client secret provided", e);
                ctx.status(400).json(Map.of(
                    "error", "Invalid client secret",
                    "message", "The provided client_secret is not valid or has expired",
                    "note", "Omit client_secret to poll the shared API client, or create one with POST /collaborator/payloads/client"
                ));
            } catch (Exception e) {
                logger.error("Failed to retrieve collaborator interactions", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to retrieve collaborator interactions",
                    "message", e.getMessage()
                ));
            }
        });
    }
    
    /**
     * Formats a Collaborator interaction for API response.
     * @param interaction The interaction to format
     * @return Formatted interaction data
     */
    public Map<String, Object> formatCollaboratorInteraction(Interaction interaction) {
        Map<String, Object> formattedInteraction = new HashMap<>();
        
        formattedInteraction.put("id", interaction.id().toString());
        formattedInteraction.put("type", interaction.type().toString());
        formattedInteraction.put("timestamp", interaction.timeStamp().toInstant().toEpochMilli());
        
        // Add basic details - simplified to avoid API complexity
        formattedInteraction.put("has_dns_details", interaction.dnsDetails().isPresent());
        formattedInteraction.put("has_http_details", interaction.httpDetails().isPresent());
        formattedInteraction.put("has_smtp_details", interaction.smtpDetails().isPresent());
        
        // Add DNS details if available
        if (interaction.dnsDetails().isPresent()) {
            DnsDetails dns = interaction.dnsDetails().get();
            Map<String, Object> dnsInfo = new HashMap<>();
            dnsInfo.put("query", dns.query());
            dnsInfo.put("query_type", dns.queryType().toString());
            formattedInteraction.put("dns_details", dnsInfo);
        }
        
        // Add SMTP details if available  
        if (interaction.smtpDetails().isPresent()) {
            SmtpDetails smtp = interaction.smtpDetails().get();
            Map<String, Object> smtpInfo = new HashMap<>();
            smtpInfo.put("protocol", smtp.protocol().toString());
            // Note: Other SMTP details can be added later based on API
            formattedInteraction.put("smtp_details", smtpInfo);
        }
        
        // Note: HttpDetails methods simplified - can be enhanced later
        if (interaction.httpDetails().isPresent()) {
            formattedInteraction.put("http_interaction_detected", true);
        }
        
        return formattedInteraction;
    }
}