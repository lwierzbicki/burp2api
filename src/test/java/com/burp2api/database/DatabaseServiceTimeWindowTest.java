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
 * Ticket #54: reconstructing a login flow from proxy history needs server-side
 * time-window filtering on {@code /proxy/search}. These tests pin the
 * {@code since}/{@code until} contract: epoch-ms values compared numerically
 * against the stored millisecond timestamps, {@code since} exclusive,
 * {@code until} inclusive, applied in the WHERE clause so out-of-window noise
 * cannot crowd in-window rows out of the row cap.
 */
class DatabaseServiceTimeWindowTest {

    private static final long T0 = 1_700_000_000_000L;

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
        when(project.name()).thenReturn("time-window-test");
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

    @Test
    void windowReturnsOnlyInWindowRowsWhenNoiseExceedsRowCap() {
        // SPA-polling noise outside the window, far more than the limit.
        for (int i = 1; i <= 50; i++) {
            insert(i, "GET", "https://target.test/poll?n=" + i, "target.test", T0 - 60_000L - i);
        }
        // The login flow inside the window.
        insert(101L, "POST", "https://target.test/login", "target.test", T0);
        insert(102L, "GET", "https://target.test/sso/callback", "target.test", T0 + 1_000L);
        insert(103L, "POST", "https://target.test/mfa", "target.test", T0 + 2_000L);
        // Newer noise after the window.
        for (int i = 1; i <= 50; i++) {
            insert(200L + i, "GET", "https://target.test/poll?after=" + i, "target.test", T0 + 120_000L + i);
        }

        Map<String, String> p = params("host", "target.test");
        p.put("since", String.valueOf(T0));
        p.put("until", String.valueOf(T0 + 2_000L));
        p.put("limit", "10");
        p.put("order", "oldest");

        List<Map<String, Object>> results = databaseService.searchTraffic(p);

        // since is exclusive, until is inclusive: T0 itself is dropped, the two
        // later flow rows survive, and no noise leaks in despite the small cap.
        assertThat(results).extracting(r -> ((Number) r.get("id")).longValue())
            .containsExactly(102L, 103L);
    }

    @Test
    void untilAloneBoundsTheResultSet() {
        insert(1L, "GET", "https://target.test/a", "target.test", T0);
        insert(2L, "GET", "https://target.test/b", "target.test", T0 + 1_000L);
        insert(3L, "GET", "https://target.test/c", "target.test", T0 + 2_000L);

        Map<String, String> p = params("host", "target.test");
        p.put("until", String.valueOf(T0 + 1_000L));
        p.put("order", "oldest");

        assertThat(databaseService.searchTraffic(p))
            .extracting(r -> ((Number) r.get("id")).longValue())
            .containsExactly(1L, 2L);
    }

    @Test
    void sinceWithEpochMillisMatchesStoredMillisecondTimestamps() {
        insert(1L, "GET", "https://target.test/a", "target.test", T0);
        insert(2L, "GET", "https://target.test/b", "target.test", T0 + 500L);

        Map<String, String> p = params("host", "target.test");
        p.put("since", String.valueOf(T0));

        assertThat(databaseService.searchTraffic(p))
            .extracting(r -> ((Number) r.get("id")).longValue())
            .containsExactly(2L);
    }

    @Test
    void invalidWindowValuesAreIgnored() {
        insert(1L, "GET", "https://target.test/a", "target.test", T0);

        Map<String, String> p = params("host", "target.test");
        p.put("since", "not-a-timestamp");
        p.put("until", "also-bad");

        assertThat(databaseService.searchTraffic(p)).hasSize(1);
    }

    private Map<String, String> params(String key, String value) {
        Map<String, String> p = new HashMap<>();
        p.put(key, value);
        return p;
    }

    private void insert(long id, String method, String url, String host, long timestamp) {
        try {
            Connection conn = databaseService.getConnection();
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO proxy_traffic (id, timestamp, method, url, host) "
                        + "VALUES (?, ?, ?, ?, ?)")) {
                stmt.setLong(1, id);
                stmt.setLong(2, timestamp);
                stmt.setString(3, method);
                stmt.setString(4, url);
                stmt.setString(5, host);
                stmt.executeUpdate();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to seed row " + id, e);
        }
    }
}
