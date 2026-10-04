package com.burp2api.services;

import com.burp2api.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Database Maintenance Service
 * 
 * Provides automated SQLite performance maintenance:
 * - Periodic ANALYZE for optimal query planning
 * - Scheduled VACUUM for space reclamation
 * - WAL checkpoint management
 * - Index statistics refresh
 * - Performance monitoring and alerts
 * 
 * @version 1.0.0
 */
public class DatabaseMaintenanceService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseMaintenanceService.class);
    
    // OPTIMAL MAINTENANCE INTERVALS for high-performance systems
    private static final long ANALYZE_INTERVAL_HOURS = 6;     // Every 6 hours
    private static final long VACUUM_INTERVAL_HOURS = 24;     // Daily vacuum
    private static final long CHECKPOINT_INTERVAL_HOURS = 1;  // Hourly WAL checkpoints
    private static final long INDEX_REFRESH_HOURS = 12;       // Twice daily index stats

    // Initial delays (minutes) are staggered so the jobs do not all fire together
    // at startup. Steady-state collisions are made safe by the DatabaseService
    // write lock - each op waits its turn instead of racing into SQLITE_BUSY - so
    // these offsets only smooth the startup burst.
    private static final long CHECKPOINT_INITIAL_MIN = 17;
    private static final long INDEX_REFRESH_INITIAL_MIN = 43;
    private static final long ANALYZE_INITIAL_MIN = 71;
    private static final long VACUUM_INITIAL_MIN = 149;

    // Maintenance yields to live traffic: if it cannot take the write lock within
    // this window it skips the cycle rather than stalling the traffic writer.
    private static final long MAINTENANCE_LOCK_TIMEOUT_MS = 2000;

    // Only VACUUM when there is enough free space to justify rewriting the whole
    // file under an exclusive lock (the operation that used to block everything).
    private static final long VACUUM_MIN_FREE_PAGES = 1000;
    private static final double VACUUM_MIN_FREE_RATIO = 0.10; // 10% of the file
    
    private final DatabaseService databaseService;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Maintenance statistics
    private final AtomicLong analyzeOperations = new AtomicLong(0);
    private final AtomicLong vacuumOperations = new AtomicLong(0);
    private final AtomicLong checkpointOperations = new AtomicLong(0);
    private final AtomicLong indexRefreshOperations = new AtomicLong(0);
    private volatile LocalDateTime lastAnalyze;
    private volatile LocalDateTime lastVacuum;
    private volatile LocalDateTime lastCheckpoint;
    
    /**
     * Constructor for DatabaseMaintenanceService.
     * 
     * @param databaseService The database service to maintain
     */
    public DatabaseMaintenanceService(DatabaseService databaseService) {
        this.databaseService = databaseService;
        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "DatabaseMaintenance");
            t.setDaemon(true);
            return t;
        });
    }
    
    /**
     * Start the maintenance service with scheduled operations.
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("DatabaseMaintenanceService already running");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot start maintenance service - database service not available");
            return;
        }
        
        logger.info("Starting Database Maintenance Service...");
        logger.info("   ANALYZE: every {} hours", ANALYZE_INTERVAL_HOURS);
        logger.info("   VACUUM: every {} hours", VACUUM_INTERVAL_HOURS);
        logger.info("   CHECKPOINT: every {} hours", CHECKPOINT_INTERVAL_HOURS);
        logger.info("   INDEX REFRESH: every {} hours", INDEX_REFRESH_HOURS);
        
        // Schedule maintenance operations
        scheduleAnalyzeOperations();
        scheduleVacuumOperations();
        scheduleCheckpointOperations();
        scheduleIndexRefreshOperations();
        
        // Run initial maintenance after startup delay
        scheduler.schedule(this::performInitialMaintenance, 5, TimeUnit.MINUTES);
        
        logger.info("Database Maintenance Service started successfully");
    }
    
    /**
     * Schedule periodic ANALYZE operations for optimal query planning.
     */
    private void scheduleAnalyzeOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performAnalyze();
            } catch (Exception e) {
                logger.error("Scheduled ANALYZE operation failed", e);
            }
        }, ANALYZE_INITIAL_MIN, ANALYZE_INTERVAL_HOURS * 60, TimeUnit.MINUTES);
    }
    
    /**
     * Schedule periodic VACUUM operations for space reclamation.
     */
    private void scheduleVacuumOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performVacuum();
            } catch (Exception e) {
                logger.error("Scheduled VACUUM operation failed", e);
            }
        }, VACUUM_INITIAL_MIN, VACUUM_INTERVAL_HOURS * 60, TimeUnit.MINUTES);
    }
    
    /**
     * Schedule periodic WAL checkpoint operations.
     */
    private void scheduleCheckpointOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performCheckpoint();
            } catch (Exception e) {
                logger.error("Scheduled CHECKPOINT operation failed", e);
            }
        }, CHECKPOINT_INITIAL_MIN, CHECKPOINT_INTERVAL_HOURS * 60, TimeUnit.MINUTES);
    }
    
    /**
     * Schedule periodic index statistics refresh.
     */
    private void scheduleIndexRefreshOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performIndexRefresh();
            } catch (Exception e) {
                logger.error("Scheduled INDEX REFRESH operation failed", e);
            }
        }, INDEX_REFRESH_INITIAL_MIN, INDEX_REFRESH_HOURS * 60, TimeUnit.MINUTES);
    }
    
    /**
     * Perform initial maintenance operations after startup.
     */
    private void performInitialMaintenance() {
        logger.info("Performing initial database maintenance...");
        
        try {
            // Light maintenance on startup
            performCheckpoint();
            performIndexRefresh();
            
            logger.info("Initial maintenance completed");
        } catch (Exception e) {
            logger.error("Initial maintenance failed", e);
        }
    }
    
    /**
     * Perform ANALYZE operation to update query planner statistics.
     */
    public void performAnalyze() {
        if (shutdown.get()) return;

        logger.info("Starting ANALYZE operation...");
        long startTime = System.currentTimeMillis();

        boolean ran = runLocked("ANALYZE", conn -> {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ANALYZE"); // Analyze all tables for optimal query planning
            }
        });

        if (ran) {
            analyzeOperations.incrementAndGet();
            lastAnalyze = LocalDateTime.now();
            logger.info("ANALYZE completed in {}ms - query planner statistics updated",
                       System.currentTimeMillis() - startTime);
        }
    }
    
    /**
     * Perform VACUUM operation to reclaim space and defragment.
     */
    public void performVacuum() {
        if (shutdown.get()) return;

        long startTime = System.currentTimeMillis();

        runLocked("VACUUM", conn -> {
            // A full VACUUM rewrites the entire database under an exclusive lock -
            // the operation that used to block every writer for minutes. Only pay
            // that cost when there is meaningful space to reclaim; otherwise skip.
            long freePages = pragmaLong(conn, "PRAGMA freelist_count");
            long totalPages = pragmaLong(conn, "PRAGMA page_count");
            if (totalPages <= 0
                    || freePages < VACUUM_MIN_FREE_PAGES
                    || (double) freePages / totalPages < VACUUM_MIN_FREE_RATIO) {
                logger.debug("VACUUM skipped - {} free pages of {} (below threshold)", freePages, totalPages);
                return;
            }

            logger.info("Starting VACUUM operation... ({} free pages of {})", freePages, totalPages);
            long pageSize = pragmaLong(conn, "PRAGMA page_size");
            long sizeBefore = totalPages * pageSize;

            try (Statement stmt = conn.createStatement()) {
                stmt.execute("VACUUM");
            }

            long sizeAfter = pragmaLong(conn, "PRAGMA page_count") * pageSize;
            vacuumOperations.incrementAndGet();
            lastVacuum = LocalDateTime.now();
            logger.info("VACUUM completed in {}ms - reclaimed {} KB",
                       System.currentTimeMillis() - startTime, (sizeBefore - sizeAfter) / 1024);
        });
    }
    
    /**
     * Perform WAL checkpoint to move data from WAL to main database.
     */
    public void performCheckpoint() {
        if (shutdown.get()) return;
        
        logger.debug("Starting WAL CHECKPOINT...");
        long startTime = System.currentTimeMillis();

        // Runs under the global write lock (see runLocked) on a dedicated pooled
        // connection, never the shared singleton. Checkpointing on a connection
        // that request threads read through yields SQLITE_LOCKED (a same-connection
        // table lock), which busy_timeout does NOT retry; a separate, serialized
        // connection avoids that and turns any remaining contention into a benign
        // busy result column.
        runLocked("WAL CHECKPOINT", conn -> {
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)")) {

                // wal_checkpoint returns (busy, log, checkpointed). A non-zero
                // busy column means readers blocked the truncate; it is not an
                // error and self-corrects on the next tick.
                boolean busy = rs.next() && rs.getInt(1) != 0;

                long duration = System.currentTimeMillis() - startTime;
                checkpointOperations.incrementAndGet();
                lastCheckpoint = LocalDateTime.now();

                if (busy) {
                    logger.debug("WAL CHECKPOINT skipped after {}ms - readers active, will retry next cycle", duration);
                } else {
                    logger.debug("WAL CHECKPOINT completed in {}ms", duration);
                }
            }
        });
    }
    
    /**
     * Refresh index statistics for optimal performance.
     */
    public void performIndexRefresh() {
        if (shutdown.get()) return;
        
        logger.debug("Refreshing index statistics...");
        long startTime = System.currentTimeMillis();

        boolean ran = runLocked("PRAGMA optimize", conn -> {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA optimize"); // Optimize indexes and refresh statistics
            }
        });

        if (ran) {
            indexRefreshOperations.incrementAndGet();
            logger.debug("Index statistics refreshed in {}ms", System.currentTimeMillis() - startTime);
        }
    }
    
    /** A maintenance statement run against a leased write connection. */
    @FunctionalInterface
    private interface MaintenanceOp {
        void run(Connection conn) throws SQLException;
    }

    /**
     * Run a maintenance operation under the DatabaseService global write lock, so
     * it serializes with live traffic writes instead of racing them into
     * {@code SQLITE_BUSY}. If the lock cannot be acquired within
     * {@link #MAINTENANCE_LOCK_TIMEOUT_MS}, the cycle is skipped - best-effort
     * maintenance yields to traffic rather than stalling it. A {@code SQLITE_BUSY}
     * or {@code SQLITE_LOCKED} surfaced despite the lock is logged at debug (a
     * skip), not error.
     *
     * @return {@code true} if the operation completed without throwing
     */
    private boolean runLocked(String label, MaintenanceOp op) {
        if (shutdown.get()) return false;

        if (!databaseService.tryWriteLock(MAINTENANCE_LOCK_TIMEOUT_MS)) {
            logger.debug("{} skipped - writers busy, will retry next cycle", label);
            return false;
        }
        try (Connection conn = databaseService.getWriteConnection()) {
            op.run(conn);
            return true;
        } catch (SQLException e) {
            if (isBusy(e)) {
                logger.debug("{} skipped - database busy, will retry next cycle", label);
            } else {
                logger.error("{} failed", label, e);
            }
            return false;
        } finally {
            databaseService.writeUnlock();
        }
    }

    /** True for SQLITE_BUSY / SQLITE_LOCKED, which are transient contention, not real errors. */
    private static boolean isBusy(SQLException e) {
        if (e.getErrorCode() == 5 || e.getErrorCode() == 6) { // SQLITE_BUSY / SQLITE_LOCKED
            return true;
        }
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase().contains("locked");
    }

    /** Read the single long value returned by a scalar PRAGMA. */
    private static long pragmaLong(Connection conn, String pragma) throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(pragma)) {
            return rs.next() ? rs.getLong(1) : 0L;
        }
    }
    
    /**
     * Get maintenance statistics.
     */
    public MaintenanceStats getStats() {
        return new MaintenanceStats(
            analyzeOperations.get(),
            vacuumOperations.get(),
            checkpointOperations.get(),
            indexRefreshOperations.get(),
            lastAnalyze,
            lastVacuum,
            lastCheckpoint
        );
    }
    
    /**
     * Check if maintenance service is healthy.
     */
    public boolean isHealthy() {
        return running.get() && !shutdown.get() && !scheduler.isShutdown();
    }
    
    /**
     * Shutdown the maintenance service.
     */
    public void shutdown() {
        if (!shutdown.getAndSet(true)) {
            logger.info("Shutting down Database Maintenance Service...");
            
            running.set(false);
            scheduler.shutdown();
            
            try {
                if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            
            logger.info("Database Maintenance Service shutdown complete");
        }
    }
    
    /**
     * Maintenance statistics for monitoring.
     */
    public static class MaintenanceStats {
        public final long analyzeOperations;
        public final long vacuumOperations;
        public final long checkpointOperations;
        public final long indexRefreshOperations;
        public final LocalDateTime lastAnalyze;
        public final LocalDateTime lastVacuum;
        public final LocalDateTime lastCheckpoint;
        
        public MaintenanceStats(long analyzeOps, long vacuumOps, long checkpointOps, long indexRefreshOps,
                               LocalDateTime lastAnalyze, LocalDateTime lastVacuum, LocalDateTime lastCheckpoint) {
            this.analyzeOperations = analyzeOps;
            this.vacuumOperations = vacuumOps;
            this.checkpointOperations = checkpointOps;
            this.indexRefreshOperations = indexRefreshOps;
            this.lastAnalyze = lastAnalyze;
            this.lastVacuum = lastVacuum;
            this.lastCheckpoint = lastCheckpoint;
        }
        
        @Override
        public String toString() {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            return String.format("MaintenanceStats{analyze=%d, vacuum=%d, checkpoint=%d, indexRefresh=%d, " +
                               "lastAnalyze=%s, lastVacuum=%s, lastCheckpoint=%s}",
                               analyzeOperations, vacuumOperations, checkpointOperations, indexRefreshOperations,
                               lastAnalyze != null ? lastAnalyze.format(formatter) : "never",
                               lastVacuum != null ? lastVacuum.format(formatter) : "never",
                               lastCheckpoint != null ? lastCheckpoint.format(formatter) : "never");
        }
    }
}