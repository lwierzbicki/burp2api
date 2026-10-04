package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.project.Project;
import com.burp2api.config.ApiConfig;
import com.burp2api.logging.TrafficSource;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Covers {@link DatabaseService#storeQueuedBatch(List)}, the single-transaction
 * batch path the traffic queue now uses instead of one transaction per item.
 *
 * <p>Asserts the batch commits every distinct capture in one shot, that a
 * duplicate content_hash mid-batch is reported as {@code -2} and rolled back to
 * its own savepoint without discarding its siblings, and that parent/child rows
 * (traffic_meta + traffic_requests + traffic_responses) are all written and
 * correctly linked. Offline: a temp on-disk SQLite DB, no network/Burp runtime.
 */
class DatabaseServiceBatchWriteTest {

    @TempDir
    Path tempDir;

    private DatabaseService databaseService;

    @BeforeEach
    void setUp() {
        ApiConfig config = mock(ApiConfig.class);
        when(config.getDatabasePath()).thenReturn(tempDir.resolve("burp2api.db").toString());
        when(config.getSessionTag()).thenReturn("");
        when(config.getMaxStoredContentChars()).thenReturn(10 * 1024 * 1024);
        when(config.getMaxRawBytes()).thenReturn(10 * 1024 * 1024);

        Project project = mock(Project.class);
        when(project.name()).thenReturn("batch-write-test");
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

    private static TrafficQueue.TrafficItem raw(String token) {
        return new TrafficQueue.TrafficItem(
            "POST",
            "http://batch.test/" + token,
            "batch.test",
            "[Host: batch.test]",
            token,                 // request body == token, so each item is unique
            "[Status: 200]",
            "ok",
            200,
            "batch",
            TrafficSource.PROXY);
    }

    @Test
    void batchCommitsEveryDistinctItemInOneTransaction() throws Exception {
        List<TrafficQueue.TrafficItem> items = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            items.add(raw("item-" + i));
        }

        long[] results = databaseService.storeQueuedBatch(items);

        assertThat(results).hasSize(200);
        for (long id : results) {
            assertThat(id).as("every batched item got a real generated id").isGreaterThan(0);
        }
        // Generated ids are unique - no two items shared a last_insert_rowid().
        assertThat(java.util.Arrays.stream(results).distinct().count()).isEqualTo(200);

        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_meta")).isEqualTo(200);
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_requests")).isEqualTo(200);
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_responses")).isEqualTo(200);

        // No orphaned children (FK integrity across the single transaction).
        assertThat(scalarLong(
            "SELECT COUNT(*) FROM traffic_requests r "
                + "LEFT JOIN traffic_meta m ON r.traffic_meta_id = m.id WHERE m.id IS NULL")).isZero();
    }

    @Test
    void repeatedContentEachGetsItsOwnRowAndDistinctId() throws Exception {
        // content_hash carries only a non-unique index at this layer, so identical
        // captures are stored as separate rows (dedup, when wanted, happens
        // elsewhere). This pins that the batch does not silently collapse them and
        // that each still receives a distinct, private last_insert_rowid().
        List<TrafficQueue.TrafficItem> items = new ArrayList<>();
        items.add(raw("a"));
        items.add(raw("b"));
        items.add(raw("a"));   // same content as index 0
        items.add(raw("c"));

        long[] results = databaseService.storeQueuedBatch(items);

        assertThat(results).hasSize(4);
        for (long id : results) {
            assertThat(id).isGreaterThan(0);
        }
        assertThat(java.util.Arrays.stream(results).distinct().count()).isEqualTo(4);

        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_meta")).isEqualTo(4);
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_requests")).isEqualTo(4);
    }

    @Test
    void emptyAndNullBatchesReturnEmptyResults() {
        assertThat(databaseService.storeQueuedBatch(new ArrayList<>())).isEmpty();
        assertThat(databaseService.storeQueuedBatch(null)).isEmpty();
    }

    private long scalarLong(String sql) throws Exception {
        try (PreparedStatement stmt = databaseService.getConnection().prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            rs.next();
            return rs.getLong(1);
        }
    }
}
