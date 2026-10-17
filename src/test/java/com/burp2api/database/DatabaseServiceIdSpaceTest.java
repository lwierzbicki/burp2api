package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.project.Project;
import com.burp2api.config.ApiConfig;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #20 follow-up: {@code proxy_traffic} and {@code traffic_meta} are written
 * by different loggers ({@code ProxyLogger} via queueRequest/queueResponse, the
 * others via queueRawTraffic) and each has its own AUTOINCREMENT counter, so the
 * two id spaces drift apart. Every read endpoint hands clients a
 * {@code proxy_traffic.id}, so an id-addressed endpoint must resolve that table —
 * otherwise it silently answers about a different captured request.
 */
class DatabaseServiceIdSpaceTest {

    @TempDir
    Path tempDir;

    private DatabaseService databaseService;

    @BeforeEach
    void setUp() {
        ApiConfig config = mock(ApiConfig.class);
        when(config.getDatabasePath()).thenReturn(tempDir.resolve("burp2api.db").toString());
        when(config.getSessionTag()).thenReturn("");
        when(config.getMaxStoredContentChars()).thenReturn(10 * 1024 * 1024);

        Project project = mock(Project.class);
        when(project.name()).thenReturn("idspace-test");
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.project()).thenReturn(project);

        databaseService = new DatabaseService(api, config);
        databaseService.initialize();
    }

    @AfterEach
    void tearDown() {
        if (databaseService != null) {
            databaseService.shutdown();
        }
    }

    /**
     * Same id, two different requests — exactly the drift observed live, where
     * id 16000 was one URL in {@code proxy_traffic} and another in
     * {@code traffic_meta}. The curl export must describe the record that
     * {@code /proxy/search} means by that id.
     */
    @Test
    void getFullRequestDataForCurlResolvesTheProxyTrafficIdSpace() throws Exception {
        long sharedId = 4242L;
        insertProxyTraffic(sharedId, "POST", "http://proxy.test/wanted",
            "[Host: proxy.test, X-Marker: proxy-row, Accept: a, b]", "proxy-body");
        insertTrafficMeta(sharedId, "GET", "http://meta.test/unwanted",
            "[Host: meta.test, X-Marker: meta-row]", "meta-body");

        Map<String, Object> data = databaseService.getFullRequestDataForCurl(sharedId);

        assertThat(data).isNotNull();
        assertThat(data.get("url")).isEqualTo("http://proxy.test/wanted");
        assertThat(data.get("method")).isEqualTo("POST");
        assertThat((String) data.get("request_headers")).contains("X-Marker: proxy-row");
        assertThat(data.get("request_body")).isEqualTo("proxy-body");
    }

    /** An id that exists only in the legacy table must still resolve. */
    @Test
    void getFullRequestDataForCurlFindsARowThatHasNoNormalizedCounterpart() throws Exception {
        insertProxyTraffic(77L, "GET", "http://proxy.test/only",
            "[Host: proxy.test, Accept: text/html, application/xml]", null);

        Map<String, Object> data = databaseService.getFullRequestDataForCurl(77L);

        assertThat(data).isNotNull();
        assertThat(data.get("url")).isEqualTo("http://proxy.test/only");
        assertThat((String) data.get("request_headers")).contains("Accept: text/html, application/xml");
    }

    @Test
    void getFullRequestDataForCurlReturnsNullForAnUnknownId() {
        assertThat(databaseService.getFullRequestDataForCurl(999_999L)).isNull();
    }

    /**
     * Ticket #21, the core regression: a client tags {@code proxy_traffic.id} 500,
     * but a {@code traffic_meta} row minted by the normalized logger already holds
     * id 500 and describes a different request. Keying the update on the raw id
     * labelled that unrelated row. The tag must land on the metadata row whose
     * {@code proxy_traffic_id} link is 500 -- the one that describes the request
     * the analyst is looking at.
     */
    @Test
    void taggingResolvesThroughTheProxyTrafficIdLinkNotTheRawId() throws Exception {
        // The request the analyst sees.
        insertProxyTraffic(500L, "POST", "http://proxy.test/real", "[Host: proxy.test]", null);
        // A drifted normalized row that happens to hold id 500 but is a different
        // capture, linked to its own (other) proxy_traffic id. The old code tagged this.
        insertProxyTraffic(777L, "GET", "http://meta.test/other", "[Host: meta.test]", null);
        insertTrafficMetaHashed(500L, "GET", "http://meta.test/other", "H-OTHER", "other", 777L);
        // The correctly-linked normalized row for proxy_traffic 500.
        insertTrafficMetaHashed(8000L, "POST", "http://proxy.test/real", "H-REAL", "real", 500L);

        databaseService.ensureTrafficMetaForProxyId(500L);
        assertThat(databaseService.updateTrafficTags(500L, "sqli,confirmed")).isTrue();

        assertThat(tagsOf(8000L)).isEqualTo("sqli,confirmed"); // linked row labelled
        assertThat(tagsOf(500L)).isNull();                     // unrelated row untouched
    }

    @Test
    void commentingResolvesThroughTheProxyTrafficIdLinkNotTheRawId() throws Exception {
        insertProxyTraffic(600L, "POST", "http://proxy.test/real", "[Host: proxy.test]", null);
        insertProxyTraffic(888L, "GET", "http://meta.test/other", "[Host: meta.test]", null);
        insertTrafficMetaHashed(600L, "GET", "http://meta.test/other", "H-OTHER2", "other", 888L);
        insertTrafficMetaHashed(8100L, "POST", "http://proxy.test/real", "H-REAL2", "real", 600L);

        databaseService.ensureTrafficMetaForProxyId(600L);
        assertThat(databaseService.updateTrafficComment(600L, "auth bypass")).isTrue();

        assertThat(commentOf(8100L)).isEqualTo("auth bypass");
        assertThat(commentOf(600L)).isNull();
    }

    /**
     * A proxy-only capture (no normalized row, so no proxy_traffic_id link yet):
     * ensure creates a fresh linked metadata row copied from proxy_traffic, and
     * the tag lands there.
     */
    @Test
    void ensureCreatesALinkedRowWhenTheNormalizedPathSkippedTheRequest() throws Exception {
        insertProxyTraffic(700L, "GET", "http://proxy.test/only-proxy", "[Host: proxy.test]", null);

        long metaId = databaseService.ensureTrafficMetaForProxyId(700L);
        assertThat(metaId).isGreaterThan(0);
        assertThat(databaseService.updateTrafficTags(700L, "interesting")).isTrue();

        assertThat(tagsOf(metaId)).isEqualTo("interesting");
        assertThat(proxyLinkOf(metaId)).isEqualTo(700L);
        assertThat(urlOf(metaId)).isEqualTo("http://proxy.test/only-proxy");
    }

    /** Calling ensure twice reuses the same linked row rather than duplicating it. */
    @Test
    void ensureIsIdempotentForTheSameProxyTrafficId() throws Exception {
        insertProxyTraffic(710L, "GET", "http://proxy.test/idem", "[Host: proxy.test]", null);

        long first = databaseService.ensureTrafficMetaForProxyId(710L);
        long second = databaseService.ensureTrafficMetaForProxyId(710L);

        assertThat(second).isEqualTo(first);
        assertThat(linkedRowCount(710L)).isEqualTo(1);
    }

    /** No proxy_traffic row: nothing to copy, so ensure refuses and existence is false. */
    @Test
    void ensureRefusesWhenNoProxyTrafficRowHoldsTheId() {
        assertThat(databaseService.proxyTrafficExists(999_000L)).isFalse();
        assertThat(databaseService.ensureTrafficMetaForProxyId(999_000L)).isEqualTo(-1L);
    }

    private String tagsOf(long trafficMetaId) throws Exception {
        return scalarString("SELECT tags FROM traffic_meta WHERE id = ?", trafficMetaId);
    }

    private String commentOf(long trafficMetaId) throws Exception {
        return scalarString("SELECT comment FROM traffic_meta WHERE id = ?", trafficMetaId);
    }

    private String urlOf(long trafficMetaId) throws Exception {
        return scalarString("SELECT url FROM traffic_meta WHERE id = ?", trafficMetaId);
    }

    private Long proxyLinkOf(long trafficMetaId) throws Exception {
        try (PreparedStatement stmt = databaseService.getConnection()
                .prepareStatement("SELECT proxy_traffic_id FROM traffic_meta WHERE id = ?")) {
            stmt.setLong(1, trafficMetaId);
            try (var rs = stmt.executeQuery()) {
                if (!rs.next()) return null;
                long v = rs.getLong(1);
                return rs.wasNull() ? null : v;
            }
        }
    }

    private int linkedRowCount(long proxyTrafficId) throws Exception {
        try (PreparedStatement stmt = databaseService.getConnection()
                .prepareStatement("SELECT COUNT(*) FROM traffic_meta WHERE proxy_traffic_id = ?")) {
            stmt.setLong(1, proxyTrafficId);
            try (var rs = stmt.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private String scalarString(String sql, long id) throws Exception {
        try (PreparedStatement stmt = databaseService.getConnection().prepareStatement(sql)) {
            stmt.setLong(1, id);
            try (var rs = stmt.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    /**
     * Ticket #28: {@code /proxy/search/request-body} used to hand back a
     * {@code traffic_meta.id}, which {@code /proxy/replay} then resolved against
     * {@code proxy_traffic.id} and silently replayed a different request. The
     * search now returns the public {@code proxy_traffic.id} (resolved via the
     * shared content_hash) as {@code id}, keeping {@code traffic_meta_id} visible.
     */
    @Test
    void requestBodySearchReturnsThePublicProxyTrafficId() throws Exception {
        // Same request captured in both tables, but under drifted ids; the
        // normalized row carries the exact proxy_traffic.id link (schema v14).
        insertProxyTrafficHashed(9001L, "POST", "https://target.test/signin", "H-SIGNIN");
        insertTrafficMetaHashed(8001L, "POST", "https://target.test/signin", "H-SIGNIN",
            "{\"user\":\"wantedneedle\"}", 9001L);

        java.util.List<Map<String, Object>> results =
            databaseService.searchRequestBodies("wantedneedle", 100, 0);

        assertThat(results).hasSize(1);
        Map<String, Object> row = results.get(0);
        assertThat(row.get("id")).isEqualTo(9001L);          // proxy_traffic.id, replayable
        assertThat(row.get("traffic_meta_id")).isEqualTo(8001L);
        assertThat(row.get("replayable")).isEqualTo(true);
    }

    /**
     * A request-body hit with no {@code proxy_traffic} counterpart (e.g. Repeater
     * traffic, or a row whose content_hash never matched) has no replayable id, so
     * {@code id} is null and {@code replayable} is false rather than a stray number.
     */
    @Test
    void requestBodySearchMarksAnUnmappableHitAsNotReplayable() throws Exception {
        insertTrafficMetaHashed(8002L, "POST", "https://target.test/only-meta", "H-ORPHAN",
            "{\"token\":\"lonelyneedle\"}");

        java.util.List<Map<String, Object>> results =
            databaseService.searchRequestBodies("lonelyneedle", 100, 0);

        assertThat(results).hasSize(1);
        Map<String, Object> row = results.get(0);
        assertThat(row.get("id")).isNull();
        assertThat(row.get("traffic_meta_id")).isEqualTo(8002L);
        assertThat(row.get("replayable")).isEqualTo(false);
    }

    /**
     * Ticket #28 residual gap: when a request was captured more than once, every
     * duplicate shares content_hash+method+url, so the old resolver's
     * {@code MAX(pt.id) WHERE hash+method+url match} always returned the newest
     * duplicate regardless of which capture the search hit belonged to — a silent
     * wrong-request replay that {@code expect{method,url}} could not catch. The
     * exact {@code proxy_traffic_id} link must win: a hit linked to the older
     * duplicate resolves to that id, not the newest one.
     */
    @Test
    void requestBodySearchReturnsTheExactLinkedIdNotTheNewestDuplicate() throws Exception {
        // Same request captured twice -> two proxy_traffic rows sharing the hash.
        insertProxyTrafficHashed(9001L, "POST", "https://target.test/dup", "H-DUP");
        insertProxyTrafficHashed(9500L, "POST", "https://target.test/dup", "H-DUP");
        // The search hit belongs to the FIRST capture; MAX(pt.id) would say 9500.
        insertTrafficMetaHashed(8001L, "POST", "https://target.test/dup", "H-DUP",
            "{\"q\":\"dupneedle\"}", 9001L);

        java.util.List<Map<String, Object>> results =
            databaseService.searchRequestBodies("dupneedle", 100, 0);

        assertThat(results).hasSize(1);
        Map<String, Object> row = results.get(0);
        assertThat(row.get("id")).isEqualTo(9001L);          // exact link, not MAX(id)=9500
        assertThat(row.get("traffic_meta_id")).isEqualTo(8001L);
        assertThat(row.get("replayable")).isEqualTo(true);
    }

    /**
     * #29: request_index was external-content FTS5 over traffic_requests but
     * declared columns (request_headers/request_body/url/method) absent from
     * that table, so every MATCH raised "no such column" and searchRequestBodies
     * silently fell back to LIKE. A prefix query, which only the FTS5 grammar
     * understands, proves the FTS path is live: under the broken schema
     * {@code uniqueftsneedl*} reaches LIKE as the literal {@code %uniqueftsneedl*%}
     * and matches nothing.
     */
    @Test
    void requestBodySearchRunsOnTheFtsIndexNotJustLike() throws Exception {
        insertProxyTrafficHashed(9100L, "POST", "https://target.test/fts", "H-FTS");
        insertTrafficMetaHashed(8100L, "POST", "https://target.test/fts", "H-FTS",
            "{\"q\":\"uniqueftsneedle\"}", 9100L);

        java.util.List<Map<String, Object>> results =
            databaseService.searchRequestBodies("uniqueftsneedl*", 100, 0);

        assertThat(results).hasSize(1);
        Map<String, Object> row = results.get(0);
        assertThat(row.get("id")).isEqualTo(9100L);
        assertThat(row.get("traffic_meta_id")).isEqualTo(8100L);
    }

    private void insertProxyTrafficHashed(long id, String method, String url, String contentHash)
            throws Exception {
        Connection conn = databaseService.getConnection();
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO proxy_traffic (id, timestamp, method, url, host, content_hash) "
                    + "VALUES (?, ?, ?, ?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setLong(2, 1_700_000_000_000L);
            stmt.setString(3, method);
            stmt.setString(4, url);
            stmt.setString(5, "target.test");
            stmt.setString(6, contentHash);
            stmt.executeUpdate();
        }
    }

    private void insertTrafficMetaHashed(long id, String method, String url, String contentHash,
            String body) throws Exception {
        insertTrafficMetaHashed(id, method, url, contentHash, body, null);
    }

    private void insertTrafficMetaHashed(long id, String method, String url, String contentHash,
            String body, Long proxyTrafficId) throws Exception {
        Connection conn = databaseService.getConnection();
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO traffic_meta (id, timestamp, method, url, host, content_hash, proxy_traffic_id) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setLong(2, 1_700_000_000_000L);
            stmt.setString(3, method);
            stmt.setString(4, url);
            stmt.setString(5, "target.test");
            stmt.setString(6, contentHash);
            if (proxyTrafficId != null) {
                stmt.setLong(7, proxyTrafficId);
            } else {
                stmt.setNull(7, java.sql.Types.INTEGER);
            }
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO traffic_requests (traffic_meta_id, headers, body) VALUES (?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setString(2, "[Host: target.test]");
            stmt.setString(3, body);
            stmt.executeUpdate();
        }
    }

    private void insertProxyTraffic(long id, String method, String url, String headers, String body)
            throws Exception {
        Connection conn = databaseService.getConnection();
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO proxy_traffic (id, timestamp, method, url, host, headers, body) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setLong(2, 1_700_000_000_000L);
            stmt.setString(3, method);
            stmt.setString(4, url);
            stmt.setString(5, "proxy.test");
            stmt.setString(6, headers);
            stmt.setString(7, body);
            stmt.executeUpdate();
        }
    }

    private void insertTrafficMeta(long id, String method, String url, String headers, String body)
            throws Exception {
        Connection conn = databaseService.getConnection();
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO traffic_meta (id, timestamp, method, url, host) VALUES (?, ?, ?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setLong(2, 1_700_000_000_000L);
            stmt.setString(3, method);
            stmt.setString(4, url);
            stmt.setString(5, "meta.test");
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO traffic_requests (traffic_meta_id, headers, body) VALUES (?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setString(2, headers);
            stmt.setString(3, body);
            stmt.executeUpdate();
        }
    }
}
