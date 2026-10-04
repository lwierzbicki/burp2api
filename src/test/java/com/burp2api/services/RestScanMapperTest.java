package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Ticket #13 (Phase 2): pure mapping for the Burp built-in REST API backend —
 * URL path (keyless vs keyed), scan-request body, and normalization of
 * {@code scan_status}/{@code scan_metrics} into burp2api's unified task schema.
 * All offline; the HTTP I/O lives in {@link BurpRestScannerClient}.
 */
class RestScanMapperTest {

    @Test
    void keylessPathOmitsTheKeySegment() {
        assertThat(RestScanMapper.buildPath("http://127.0.0.1:1337", "", "scan"))
            .isEqualTo("http://127.0.0.1:1337/v0.1/scan");
        // Trailing slash on the base is tolerated.
        assertThat(RestScanMapper.buildPath("http://127.0.0.1:1337/", null, "scan/3"))
            .isEqualTo("http://127.0.0.1:1337/v0.1/scan/3");
    }

    @Test
    void keyedPathIncludesTheKeySegment() {
        assertThat(RestScanMapper.buildPath("http://127.0.0.1:1337", "SECRET", "scan"))
            .isEqualTo("http://127.0.0.1:1337/SECRET/v0.1/scan");
    }

    @Test
    void scanStatusValuesMapToUnifiedStates() {
        assertThat(RestScanMapper.normalizeState("initializing")).isEqualTo(ScanStatusMapper.PENDING);
        assertThat(RestScanMapper.normalizeState("crawling")).isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(RestScanMapper.normalizeState("auditing")).isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(RestScanMapper.normalizeState("succeeded")).isEqualTo(ScanStatusMapper.DONE);
        assertThat(RestScanMapper.normalizeState("paused")).isEqualTo(ScanStatusMapper.PAUSED);
        assertThat(RestScanMapper.normalizeState("failed")).isEqualTo(ScanStatusMapper.ERRORED);
        assertThat(RestScanMapper.normalizeState("cancelled")).isEqualTo(ScanStatusMapper.CANCELLED);
        // Unknown -> PENDING (conservative).
        assertThat(RestScanMapper.normalizeState("something-new")).isEqualTo(ScanStatusMapper.PENDING);
    }

    @Test
    void normalizeStatusResponseSurfacesStateAndTrafficSignals() {
        Map<String, Object> metrics = Map.of(
            "crawl_requests_made", 3,
            "audit_requests_made", 644,
            "audit_queue_items_waiting", 0,
            "audit_network_errors", 2,
            "crawl_and_audit_progress", 100);
        Map<String, Object> rest = Map.of(
            "task_id", "3",
            "scan_status", "auditing",
            "scan_metrics", metrics,
            "issue_events", List.of(Map.of("id", "1"), Map.of("id", "2")));

        Map<String, Object> out = RestScanMapper.normalizeStatusResponse(rest);

        assertThat(out.get("status")).isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(out.get("backend")).isEqualTo("rest");
        assertThat(out.get("audit_traffic_started")).isEqualTo(true);
        assertThat(out.get("audit_requests_made")).isEqualTo(644);
        assertThat(out.get("issues_found")).isEqualTo(2);
        assertThat(out.get("progress_percent")).isEqualTo(100);
        // Raw metrics preserved for callers that want detail.
        assertThat(out).containsKey("scan_metrics");
    }

    @Test
    void auditTrafficNotStartedWhenOnlyCrawling() {
        Map<String, Object> rest = Map.of(
            "scan_status", "crawling",
            "scan_metrics", Map.of("crawl_requests_made", 5, "audit_requests_made", 0));

        Map<String, Object> out = RestScanMapper.normalizeStatusResponse(rest);

        assertThat(out.get("status")).isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(out.get("audit_traffic_started")).isEqualTo(false);
    }

    @Test
    void buildScanBodyIncludesUrlsConfigsAndResourcePool() {
        Map<String, Object> body = RestScanMapper.buildScanBody(
            List.of("https://t/"),
            List.of("Audit checks - light active", "Audit checks - all except JavaScript analysis"),
            "b2a-throttled",
            List.of("https://t/"));

        assertThat(body.get("urls")).isEqualTo(List.of("https://t/"));
        assertThat(body.get("resource_pool")).isEqualTo("b2a-throttled");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> configs = (List<Map<String, Object>>) body.get("scan_configurations");
        assertThat(configs).hasSize(2);
        assertThat(configs.get(0)).containsEntry("name", "Audit checks - light active")
            .containsEntry("type", "NamedConfiguration");

        @SuppressWarnings("unchecked")
        Map<String, Object> scope = (Map<String, Object>) body.get("scope");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> include = (List<Map<String, Object>>) scope.get("include");
        assertThat(include.get(0)).containsEntry("rule", "https://t/");
    }

    @Test
    void buildScanBodyOmitsOptionalFieldsWhenAbsent() {
        Map<String, Object> body = RestScanMapper.buildScanBody(
            List.of("https://t/"), List.of(), null, List.of());

        assertThat(body).containsOnlyKeys("urls");
    }
}
