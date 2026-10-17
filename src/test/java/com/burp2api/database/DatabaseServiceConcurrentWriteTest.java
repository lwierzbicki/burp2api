package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.project.Project;
import com.burp2api.config.ApiConfig;
import com.burp2api.logging.TrafficSource;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CyclicBarrier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #37 regression: {@code DatabaseService} used to hand one shared JDBC
 * connection to every writer thread (proxy/tool loggers, the traffic queue, HTTP
 * handlers). A concurrent {@code INSERT} advanced {@code last_insert_rowid()}, so
 * the normalized path read back another thread's rowid and linked the
 * {@code traffic_requests}/{@code traffic_responses} child to a
 * {@code traffic_meta} id that either did not exist yet (SQLITE_CONSTRAINT_FOREIGNKEY)
 * or described a different capture. Writes now run on per-operation pooled
 * connections, so each operation's generated id is private to it.
 *
 * <p>This drives many parallel writers - normalized inserts (parent + child, the
 * exact crash path) interleaved with proxy-style raw inserts - and asserts every
 * write succeeded, every child row links to its own parent, and no ids collided.
 * Offline: a temp on-disk SQLite DB, no network/Burp runtime.
 */
class DatabaseServiceConcurrentWriteTest {

    @TempDir
    Path tempDir;

    private DatabaseService databaseService;

    private static final int THREADS = 8;
    private static final int ITERATIONS = 120;

    @BeforeEach
    void setUp() {
        ApiConfig config = mock(ApiConfig.class);
        when(config.getDatabasePath()).thenReturn(tempDir.resolve("burp2api.db").toString());
        when(config.getSessionTag()).thenReturn("");
        when(config.getMaxStoredContentChars()).thenReturn(10 * 1024 * 1024);

        Project project = mock(Project.class);
        when(project.name()).thenReturn("concurrent-write-test");
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
    void parallelWritersProduceNoForeignKeyFailuresAndCorrectIdLinkage() throws Exception {
        // Each token is globally unique across all threads/iterations, so no write
        // is skipped as a content-hash duplicate and every parent row carries a
        // token we can match against its own child row.
        ConcurrentLinkedQueue<Long> metaIds = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Long> rawIds = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();

        CyclicBarrier startLine = new CyclicBarrier(THREADS);
        List<Thread> workers = new ArrayList<>();

        for (int t = 0; t < THREADS; t++) {
            final int threadIndex = t;
            Thread worker = new Thread(() -> {
                try {
                    startLine.await(); // release all threads together for maximum contention
                    for (int i = 0; i < ITERATIONS; i++) {
                        String token = threadIndex + "-" + i;

                        // Normalized insert: traffic_meta + traffic_requests +
                        // traffic_responses, the parent/child FK path that crashed.
                        long metaId = databaseService.storeTrafficNormalized(
                            "POST",
                            "http://norm.test/" + token,
                            "norm.test",
                            "[Host: norm.test]",
                            token,                       // request body == token
                            "[Status: 200]",
                            "ok",
                            200,
                            "concurrent",
                            TrafficSource.PROXY);
                        metaIds.add(metaId);

                        // Proxy-style raw insert onto proxy_traffic in the same loop,
                        // so a raw INSERT can land between another thread's meta
                        // INSERT and its last_insert_rowid() read.
                        long rawId = databaseService.storeRawTrafficWithSource(
                            "GET",
                            "http://raw.test/" + token,
                            "raw.test",
                            "[Host: raw.test]",
                            token,
                            "[Status: 200]",
                            "ok",
                            200,
                            "concurrent",
                            TrafficSource.PROXY);
                        rawIds.add(rawId);
                    }
                } catch (Throwable ex) {
                    failures.add(ex);
                }
            }, "writer-" + t);
            workers.add(worker);
            worker.start();
        }

        for (Thread worker : workers) {
            worker.join(60_000);
            assertThat(worker.isAlive()).as("writer thread finished within timeout").isFalse();
        }

        int expected = THREADS * ITERATIONS;

        // No thread threw, and every write returned a real generated id: no -1
        // (failure, including a caught FK violation) and no -2 (duplicate skip).
        assertThat(failures).as("no writer threw").isEmpty();
        assertThat(metaIds).hasSize(expected);
        assertThat(rawIds).hasSize(expected);
        assertThat(metaIds).as("no normalized write failed or was skipped").allMatch(id -> id > 0);
        assertThat(rawIds).as("no raw write failed or was skipped").allMatch(id -> id > 0);

        // Generated ids are unique: a corrupted last_insert_rowid() would hand the
        // same rowid to two operations.
        assertThat(distinctCount(metaIds)).as("traffic_meta ids unique").isEqualTo(expected);
        assertThat(distinctCount(rawIds)).as("proxy_traffic ids unique").isEqualTo(expected);

        // Row counts match the successful writes.
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_meta")).isEqualTo(expected);
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_requests")).isEqualTo(expected);
        assertThat(scalarLong("SELECT COUNT(*) FROM traffic_responses")).isEqualTo(expected);
        assertThat(scalarLong("SELECT COUNT(*) FROM proxy_traffic")).isEqualTo(expected);

        // Every child links to an existing parent (FK integrity, no orphans).
        assertThat(scalarLong(
            "SELECT COUNT(*) FROM traffic_requests r "
                + "LEFT JOIN traffic_meta m ON r.traffic_meta_id = m.id WHERE m.id IS NULL"))
            .as("no orphaned traffic_requests").isZero();
        assertThat(scalarLong(
            "SELECT COUNT(*) FROM traffic_responses r "
                + "LEFT JOIN traffic_meta m ON r.traffic_meta_id = m.id WHERE m.id IS NULL"))
            .as("no orphaned traffic_responses").isZero();

        // Correct linkage: each parent's child carries the SAME token. The parent
        // url is "http://norm.test/<token>" and its request body is "<token>", so a
        // child linked to the wrong parent (a stolen last_insert_rowid()) shows up
        // as m.url not ending in r.body.
        assertThat(scalarLong(
            "SELECT COUNT(*) FROM traffic_meta m "
                + "JOIN traffic_requests r ON r.traffic_meta_id = m.id "
                + "WHERE m.url IS NULL OR r.body IS NULL OR m.url NOT LIKE '%' || r.body"))
            .as("every traffic_requests row links to its own traffic_meta row").isZero();
    }

    private static long distinctCount(ConcurrentLinkedQueue<Long> ids) {
        return ids.stream().distinct().count();
    }

    private long scalarLong(String sql) throws Exception {
        try (PreparedStatement stmt = databaseService.getConnection().prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            rs.next();
            return rs.getLong(1);
        }
    }
}
