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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #52: the {@code /proxy/search} {@code url} filter intermittently returned empty/closed
 * responses under concurrent load, and pagination ordering over a large history was undocumented
 * and non-deterministic when many rows shared a timestamp. These tests pin the ordering contract
 * (newest-first by default, {@code order=newest|oldest} aliases, id tiebreaker for stable paging)
 * and exercise concurrent searches to guard against the shared-connection collision.
 */
class DatabaseServiceSearchOrderingTest {

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
        when(project.name()).thenReturn("search-ordering-test");
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
    void defaultOrderReturnsNewestFirst() {
        // Ascending ids captured at ascending timestamps: id 3 is the newest.
        insert(1L, "GET", "https://target.test/a", "target.test", 1_700_000_000_000L);
        insert(2L, "GET", "https://target.test/b", "target.test", 1_700_000_001_000L);
        insert(3L, "GET", "https://target.test/c", "target.test", 1_700_000_002_000L);

        List<Map<String, Object>> results = databaseService.searchTraffic(params("host", "target.test"));

        assertThat(results).extracting(r -> r.get("id")).containsExactly(3L, 2L, 1L);
    }

    @Test
    void orderNewestAndOldestAreAliasesForTimestampDirection() {
        insert(1L, "GET", "https://target.test/a", "target.test", 1_700_000_000_000L);
        insert(2L, "GET", "https://target.test/b", "target.test", 1_700_000_001_000L);
        insert(3L, "GET", "https://target.test/c", "target.test", 1_700_000_002_000L);

        Map<String, String> newest = params("host", "target.test");
        newest.put("order", "newest");
        assertThat(databaseService.searchTraffic(newest)).extracting(r -> r.get("id"))
            .containsExactly(3L, 2L, 1L);

        Map<String, String> oldest = params("host", "target.test");
        oldest.put("order", "oldest");
        assertThat(databaseService.searchTraffic(oldest)).extracting(r -> r.get("id"))
            .containsExactly(1L, 2L, 3L);
    }

    @Test
    void paginationIsStableWhenTimestampsAreTied() {
        // All rows share one timestamp - the worst case the plain timestamp sort mishandled.
        int total = 25;
        for (int i = 1; i <= total; i++) {
            insert(i, "GET", "https://target.test/set-password?n=" + i, "target.test", 1_700_000_000_000L);
        }

        // Page through with a small limit and assert every id appears exactly once, in order.
        int pageSize = 7;
        List<Long> paged = new ArrayList<>();
        for (int offset = 0; offset < total; offset += pageSize) {
            Map<String, String> p = params("url", "set-password");
            p.put("order", "oldest"); // ascending: expect ids 1..25 in order
            p.put("limit", String.valueOf(pageSize));
            p.put("offset", String.valueOf(offset));
            for (Map<String, Object> row : databaseService.searchTraffic(p)) {
                paged.add(((Number) row.get("id")).longValue());
            }
        }

        List<Long> expected = new ArrayList<>();
        for (long i = 1; i <= total; i++) {
            expected.add(i);
        }
        assertThat(paged).containsExactlyElementsOf(expected);
    }

    @Test
    void concurrentUrlSearchesAllReturnResults() throws Exception {
        // A history large enough that each query holds its connection for a while, plus the
        // specific substrings from the ticket. Before the pooled-read-connection fix, overlapping
        // searches on the single shared connection aborted mid-query and returned empty responses.
        int filler = 6000;
        for (int i = 1; i <= filler; i++) {
            insert(i, "GET", "https://target.test/noise/" + i, "target.test", 1_700_000_000_000L + i);
        }
        insert(9001L, "POST", "https://target.test/verify-user-please", "target.test", 1_700_000_100_000L);
        insert(9002L, "POST", "https://target.test/set-password", "target.test", 1_700_000_100_001L);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<Integer>> tasks = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                String needle = (i % 2 == 0) ? "verify-user-please" : "set-password";
                tasks.add(() -> databaseService.searchTraffic(params("url", needle)).size());
            }
            List<Future<Integer>> futures = pool.invokeAll(tasks, 60, TimeUnit.SECONDS);
            for (Future<Integer> f : futures) {
                // Each query matches exactly one row; a 0 here is the #52 empty-response regression.
                assertThat(f.get()).isEqualTo(1);
            }
        } finally {
            pool.shutdownNow();
        }
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
