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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #33: the {@code /proxy/search} {@code url} filter is a substring match, so pinning one
 * endpoint returns every captured request whose URL contains that text (e.g. a search for
 * {@code /orders} also returns {@code /orders/42} and {@code /api/orders/export}). The default is
 * unchanged, but {@code match=exact} must anchor the filter to one full URL so a caller can pin a
 * single endpoint, and {@code getSearchCount} must agree with {@code searchTraffic}.
 */
class DatabaseServiceSearchMatchTest {

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
        when(project.name()).thenReturn("search-match-test");
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

    private static final String EXACT = "https://target.test/orders";

    @BeforeEach
    void seedTraffic() throws Exception {
        // One endpoint we want to pin, plus neighbours that share the "/orders" path fragment.
        insert(1L, "POST", EXACT, "target.test");
        insert(2L, "GET", "https://target.test/orders/42", "target.test");
        insert(3L, "GET", "https://target.test/api/orders/export", "target.test");
        insert(4L, "GET", "https://target.test/unrelated", "target.test");
    }

    @Test
    void substringMatchIsTheDefaultAndSweepsInNeighbours() {
        List<Map<String, Object>> results = databaseService.searchTraffic(params("url", "/orders"));

        assertThat(results).extracting(r -> r.get("url"))
            .containsExactlyInAnyOrder(
                "https://target.test/orders",
                "https://target.test/orders/42",
                "https://target.test/api/orders/export");
        assertThat(databaseService.getSearchCount(params("url", "/orders"))).isEqualTo(3);
    }

    @Test
    void exactMatchPinsOneFullUrl() {
        Map<String, String> p = params("url", EXACT);
        p.put("match", "exact");

        List<Map<String, Object>> results = databaseService.searchTraffic(p);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).get("url")).isEqualTo(EXACT);
        assertThat(results.get(0).get("id")).isEqualTo(1L);
        assertThat(databaseService.getSearchCount(p)).isEqualTo(1);
    }

    @Test
    void exactMatchOnAPathFragmentMatchesNothingBecauseUrlIsTheFullUrl() {
        Map<String, String> p = params("url", "/orders");
        p.put("match", "exact");

        assertThat(databaseService.searchTraffic(p)).isEmpty();
        assertThat(databaseService.getSearchCount(p)).isEqualTo(0);
    }

    @Test
    void exactMatchHonoursCaseInsensitiveFlag() {
        Map<String, String> p = params("url", "https://TARGET.test/ORDERS");
        p.put("match", "exact");
        p.put("case_insensitive", "true");

        List<Map<String, Object>> results = databaseService.searchTraffic(p);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).get("url")).isEqualTo(EXACT);
        assertThat(databaseService.getSearchCount(p)).isEqualTo(1);
    }

    @Test
    void wildcardMatchingStillWorksRegardlessOfMatchMode() {
        // A prefix wildcard anchors at the start, so /api/orders/export is excluded.
        Map<String, String> p = params("url", "https://target.test/orders*");
        p.put("match", "exact"); // wildcards take precedence over match=exact

        List<Map<String, Object>> results = databaseService.searchTraffic(p);

        assertThat(results).extracting(r -> r.get("url"))
            .containsExactlyInAnyOrder(
                "https://target.test/orders",
                "https://target.test/orders/42");
        assertThat(databaseService.getSearchCount(p)).isEqualTo(2);
    }

    private Map<String, String> params(String key, String value) {
        Map<String, String> p = new HashMap<>();
        p.put(key, value);
        return p;
    }

    private void insert(long id, String method, String url, String host) throws Exception {
        Connection conn = databaseService.getConnection();
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO proxy_traffic (id, timestamp, method, url, host) "
                    + "VALUES (?, ?, ?, ?, ?)")) {
            stmt.setLong(1, id);
            stmt.setLong(2, 1_700_000_000_000L);
            stmt.setString(3, method);
            stmt.setString(4, url);
            stmt.setString(5, host);
            stmt.executeUpdate();
        }
    }
}
