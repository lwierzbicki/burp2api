package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Regression test for #51: {@code PRAGMA cache_size=50000} budgeted 50,000
 * <em>pages</em> (~195 MiB at the default 4 KiB page size) per pooled
 * connection — up to ~1.5 GiB across the max=8 pool inside Burp's shared JVM.
 * The cache must instead be expressed as a negative KiB value so the memory
 * budget is explicit and independent of page size.
 */
class ConnectionPoolCacheSizeTest {

    @TempDir
    Path tempDir;

    @Test
    void pooledConnectionsUseKibBudgetedCache() throws Exception {
        Path db = tempDir.resolve("cache-size-test.db");
        ConnectionPool pool = new ConnectionPool("jdbc:sqlite:" + db, 1, 1, 1000);
        try {
            try (Connection conn = pool.getConnection();
                 Statement stmt = conn.createStatement();
                 var rs = stmt.executeQuery("PRAGMA cache_size")) {
                assertThat(rs.next()).isTrue();
                // Negative = KiB budget; must equal the pool's 32 MiB target.
                assertThat(rs.getInt(1)).isEqualTo(-ConnectionPool.CACHE_SIZE_KIB);
            }
        } finally {
            pool.shutdown();
        }
    }

    @Test
    void cacheTargetBoundsPoolFootprint() {
        // 32 MiB x max=8 connections must stay well under the old ~1.5 GiB worst case.
        assertThat((long) ConnectionPool.CACHE_SIZE_KIB * 8)
                .isLessThanOrEqualTo(256L * 1024);
    }

    @Test
    void readConnectionsKeepTheSameBudget() throws Exception {
        Path db = tempDir.resolve("cache-size-read-test.db");
        ConnectionPool pool = new ConnectionPool("jdbc:sqlite:" + db, 1, 1, 1000);
        try {
            try (Connection conn = pool.getReadConnection();
                 Statement stmt = conn.createStatement();
                 var rs = stmt.executeQuery("PRAGMA cache_size")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getInt(1)).isEqualTo(-ConnectionPool.CACHE_SIZE_KIB);
            }
        } finally {
            pool.shutdown();
        }
    }
}
