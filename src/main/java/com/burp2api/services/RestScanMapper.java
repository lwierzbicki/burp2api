package com.burp2api.services;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure helpers for the Burp built-in REST API scanner backend (ticket #13,
 * Phase 2): build the versioned URL path (keyless or keyed), build the
 * {@code POST /scan} request body, and normalize the {@code scan_status} /
 * {@code scan_metrics} response into burp2api's unified task schema (the same
 * {@code status} vocabulary as the Montoya path). No HTTP, no Burp, no I/O.
 */
public final class RestScanMapper {

    private RestScanMapper() {
    }

    /**
     * Build a versioned endpoint URL. With no key (keyless "allow access without
     * API key" mode) the key segment is omitted: {@code <base>/v0.1/<suffix>};
     * with a key: {@code <base>/<key>/v0.1/<suffix>}.
     */
    public static String buildPath(String baseUrl, String key, String suffix) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        StringBuilder sb = new StringBuilder(base);
        if (key != null && !key.isEmpty()) {
            sb.append('/').append(key);
        }
        sb.append("/v0.1/").append(suffix);
        return sb.toString();
    }

    /** Map Burp's {@code scan_status} to the unified state vocabulary. */
    public static String normalizeState(String scanStatus) {
        String s = scanStatus == null ? "" : scanStatus.trim().toLowerCase();
        switch (s) {
            case "succeeded":
                return ScanStatusMapper.DONE;
            case "paused":
                return ScanStatusMapper.PAUSED;
            case "failed":
                return ScanStatusMapper.ERRORED;
            case "cancelled":
            case "canceled":
                return ScanStatusMapper.CANCELLED;
            case "crawling":
            case "auditing":
                return ScanStatusMapper.RUNNING;
            case "initializing":
            case "":
            default:
                return ScanStatusMapper.PENDING;
        }
    }

    /**
     * Normalize a {@code GET /scan/{id}} response into the unified task schema.
     * Surfaces {@code status}, whether audit traffic has started, issue count,
     * and progress, while preserving the raw {@code scan_metrics}.
     */
    public static Map<String, Object> normalizeStatusResponse(Map<String, Object> rest) {
        Map<String, Object> out = new HashMap<>();
        out.put("backend", "rest");

        String scanStatus = asString(rest.get("scan_status"));
        out.put("status", normalizeState(scanStatus));
        out.put("scan_status", scanStatus);
        if (rest.get("task_id") != null) {
            out.put("task_id", rest.get("task_id"));
        }

        Map<String, Object> metrics = asMap(rest.get("scan_metrics"));
        int auditRequests = asInt(metrics.get("audit_requests_made"));
        int crawlRequests = asInt(metrics.get("crawl_requests_made"));
        out.put("audit_requests_made", auditRequests);
        out.put("crawl_requests_made", crawlRequests);
        out.put("request_count", auditRequests + crawlRequests);
        out.put("audit_traffic_started", auditRequests > 0);
        if (metrics.containsKey("crawl_and_audit_progress")) {
            out.put("progress_percent", asInt(metrics.get("crawl_and_audit_progress")));
        }
        if (!metrics.isEmpty()) {
            out.put("scan_metrics", metrics);
        }

        Object issueEvents = rest.get("issue_events");
        if (issueEvents instanceof List) {
            out.put("issues_found", ((List<?>) issueEvents).size());
        } else if (metrics.containsKey("issue_events")) {
            out.put("issues_found", asInt(metrics.get("issue_events")));
        }

        return out;
    }

    /**
     * Build the {@code POST /scan} body. {@code urls} is always present; named
     * {@code scan_configurations} (accepting plain names or pre-shaped maps),
     * {@code resource_pool}, and {@code scope.include} rules are added only when
     * supplied.
     */
    public static Map<String, Object> buildScanBody(List<String> urls,
                                                    List<?> scanConfigurations,
                                                    String resourcePool,
                                                    List<String> scopeIncludeUrls) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("urls", new ArrayList<>(urls));

        if (scanConfigurations != null && !scanConfigurations.isEmpty()) {
            List<Map<String, Object>> configs = new ArrayList<>();
            for (Object cfg : scanConfigurations) {
                if (cfg instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> asMap = (Map<String, Object>) cfg;
                    configs.add(asMap);
                } else if (cfg != null) {
                    Map<String, Object> named = new LinkedHashMap<>();
                    named.put("name", String.valueOf(cfg));
                    named.put("type", "NamedConfiguration");
                    configs.add(named);
                }
            }
            if (!configs.isEmpty()) {
                body.put("scan_configurations", configs);
            }
        }

        if (resourcePool != null && !resourcePool.isEmpty()) {
            body.put("resource_pool", resourcePool);
        }

        if (scopeIncludeUrls != null && !scopeIncludeUrls.isEmpty()) {
            List<Map<String, Object>> include = new ArrayList<>();
            for (String url : scopeIncludeUrls) {
                Map<String, Object> rule = new LinkedHashMap<>();
                rule.put("rule", url);
                include.add(rule);
            }
            Map<String, Object> scope = new LinkedHashMap<>();
            scope.put("include", include);
            body.put("scope", scope);
        }

        return body;
    }

    private static String asString(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }

    private static int asInt(Object o) {
        if (o instanceof Number) {
            return ((Number) o).intValue();
        }
        try {
            return o == null ? 0 : Integer.parseInt(String.valueOf(o).trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
