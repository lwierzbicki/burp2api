package com.burp2api.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thin client for the Burp Suite built-in REST API (ticket #13, Phase 2). Used
 * as the backend for URL/crawl+audit scans so burp2api can apply named
 * {@code scan_configurations} and a {@code resource_pool} (which the Montoya API
 * cannot) and read Burp's authoritative {@code scan_status}/{@code scan_metrics}.
 *
 * <p>Loopback service by default ({@code http://127.0.0.1:1337}); supports both
 * keyless ("allow access without API key") and keyed access. The API key is
 * authentication material and is never logged.
 */
public class BurpRestScannerClient {

    private static final Logger logger = LoggerFactory.getLogger(BurpRestScannerClient.class);

    private final String baseUrl;
    private final String key;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public BurpRestScannerClient(String baseUrl, String key) {
        this(baseUrl, key, HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build());
    }

    // Package-visible for injecting a client in tests.
    BurpRestScannerClient(String baseUrl, String key, HttpClient http) {
        this.baseUrl = baseUrl;
        this.key = key == null ? "" : key;
        this.http = http;
    }

    /**
     * Whether the REST service answers at all. A 2xx or 4xx both mean "up";
     * only a connection failure means unavailable. Never surfaces the key.
     */
    public boolean isAvailable() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(RestScanMapper.buildPath(baseUrl, key, "knowledge_base/issue_definitions")))
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
            HttpResponse<Void> resp = http.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.statusCode() > 0;
        } catch (Exception e) {
            logger.debug("Burp REST API not reachable at {}: {}", safeBase(), e.getMessage());
            return false;
        }
    }

    /**
     * Start a scan. Returns the task id parsed from the {@code Location} header
     * (falling back to a {@code task_id} in the body).
     *
     * @throws Exception if the request fails or the service rejects the scan.
     */
    public String startScan(Map<String, Object> body) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(RestScanMapper.buildPath(baseUrl, key, "scan")))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("Burp REST API returned HTTP " + resp.statusCode() + " for scan start");
        }

        Optional<String> location = resp.headers().firstValue("Location");
        if (location.isPresent() && !location.get().isBlank()) {
            String loc = location.get();
            int slash = loc.lastIndexOf('/');
            return slash >= 0 ? loc.substring(slash + 1) : loc;
        }

        // Fallback: some builds echo the id in the body.
        String bodyStr = resp.body();
        if (bodyStr != null && !bodyStr.isBlank()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = mapper.readValue(bodyStr, Map.class);
            Object id = parsed.get("task_id");
            if (id != null) {
                return String.valueOf(id);
            }
        }
        throw new IllegalStateException("Burp REST API scan start returned no task id");
    }

    /**
     * Fetch and normalize a scan's status into the unified task schema.
     *
     * @return normalized status map, or {@code null} if the task is not found.
     * @throws Exception on transport or unexpected HTTP failure.
     */
    public Map<String, Object> getScanStatus(String taskId) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(RestScanMapper.buildPath(baseUrl, key, "scan/" + taskId)))
            .timeout(Duration.ofSeconds(10))
            .GET()
            .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 404) {
            return null;
        }
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("Burp REST API returned HTTP " + resp.statusCode() + " for scan status");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = mapper.readValue(resp.body(), Map.class);
        return RestScanMapper.normalizeStatusResponse(parsed);
    }

    /** Base URL without any key segment, safe for logs. */
    private String safeBase() {
        return baseUrl;
    }
}
