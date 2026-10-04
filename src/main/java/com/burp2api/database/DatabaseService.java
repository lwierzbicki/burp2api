package com.burp2api.database;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.MontoyaApi;
import com.burp2api.config.ApiConfig;
import com.burp2api.database.schema.SchemaManager;
import com.burp2api.logging.TrafficSource;
import com.burp2api.utils.RawCapture;
import com.burp2api.utils.StoredText;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Savepoint;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Service class for managing database operations.
 * Handles SQLite database initialization, schema management,
 * and storage/retrieval of proxy traffic data.
 * Supports project-specific databases to prevent data contamination between different Burp projects.
 * 
 * @version 1.0.0
 */
public class DatabaseService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseService.class);
    
    private final ApiConfig config;
    private final MontoyaApi api;
    private final SchemaManager schemaManager;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    private Connection connection;
    private ConnectionPool connectionPool;

    // Serializes EVERY writer (proxy/tool loggers, the traffic queue, HTTP
    // handlers, and database maintenance) onto a single application-level lock.
    // SQLite in WAL mode allows only one writer at a time; spreading writes over
    // many pooled connections adds no write parallelism, it only turns contention
    // into cross-connection SQLITE_BUSY under load (the ANALYZE failure and
    // multi-second batch stalls this lock fixes). Held for the duration of one
    // logical write via WriteLease; maintenance takes it through
    // tryWriteLock()/writeUnlock() so it waits its turn instead of colliding.
    // Reads are unaffected - they use the pool concurrently without this lock.
    // Reentrant, so a write path that retries itself stays safe. (#37)
    private final ReentrantLock sharedWriteLock = new ReentrantLock();
    private String currentProjectName;
    private String currentDatabasePath;
    
    /**
     * Constructor for DatabaseService.
     * 
     * @param api The MontoyaApi instance to access project information
     * @param config The API configuration
     */
    public DatabaseService(MontoyaApi api, ApiConfig config) {
        this.api = api;
        this.config = config;
        this.schemaManager = new SchemaManager();
    }
    
    /**
     * Initializes the database service.
     * Creates connection and ensures schema is up to date.
     * Automatically detects project changes and creates project-specific databases.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("DatabaseService already initialized");
            return;
        }
        
        try {
            logger.info("Starting database initialization...");
            
            // Detect current project and create project-specific database path
            String projectName = detectCurrentProject();
            String projectDbPath = generateProjectSpecificDatabasePath(projectName);
            
            logger.info("Current Burp project: {}", projectName);
            logger.info("DATABASE DEBUG: Config database path: {}", config.getDatabasePath());
            logger.info("Project-specific database path: {}", projectDbPath);
            
            this.currentProjectName = projectName;
            this.currentDatabasePath = projectDbPath;
            
            // Test ClassLoader and SQLite availability with detailed logging
            try {
                logger.info("Step 1: Loading SQLite JDBC driver...");
                Class<?> sqliteDriver = Class.forName("org.sqlite.JDBC");
                logger.info("SQLite JDBC driver loaded successfully: {}", sqliteDriver.getName());
            } catch (ClassNotFoundException e) {
                logger.error("CRITICAL: SQLite JDBC driver not found in classpath", e);
                throw e;
            }
            
            // Test DriverManager registration
            try {
                logger.info("Step 2: Testing DriverManager SQLite support...");
                java.sql.Driver driver = java.sql.DriverManager.getDriver("jdbc:sqlite:test");
                logger.info("DriverManager SQLite support confirmed: {}", driver.getClass().getName());
            } catch (SQLException e) {
                logger.warn("DriverManager test failed, will try direct connection: {}", e.getMessage());
            }
            
            // Create database connection with corruption detection and recovery
            String dbUrl = "jdbc:sqlite:" + currentDatabasePath;
            logger.info("Step 3: Creating database connection to: {}", dbUrl);
            
            // Ensure directory exists
            java.io.File dbFile = new java.io.File(currentDatabasePath);
            java.io.File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                boolean created = parentDir.mkdirs();
                logger.info("Created database directory {}: {}", parentDir.getAbsolutePath(), created);
            }
            
            // Skip aggressive integrity check that was causing false positives
            if (dbFile.exists()) {
                logger.info("Step 3a: Database file exists, proceeding with connection...");
            }
            
            logger.info("Step 4: Establishing database connection...");
            connection = DriverManager.getConnection(dbUrl);
            logger.info("Database connection established successfully");
            
            // Test basic SQL functionality
            try {
                logger.info("Step 5: Testing basic SQL functionality...");
                try (java.sql.Statement testStmt = connection.createStatement()) {
                    testStmt.execute("SELECT 1");
                    logger.info("Basic SQL test successful");
                }
            } catch (SQLException e) {
                logger.error("Basic SQL test failed", e);
                throw e;
            }
            
            // Configure connection
            logger.info("Step 6: Configuring SQLite connection...");
            configureConnection();
            logger.info("Connection configured successfully");
            
            // Initialize or upgrade schema
            logger.info("Step 7: Initializing database schema...");
            schemaManager.initializeSchema(connection);
            logger.info("Schema initialization completed");
            
            // Migrate schema to add missing columns (timing data)
            logger.info("Step 8: Migrating database schema for compatibility...");
            migrateSchemaIfNeeded();
            logger.info("Schema migration completed");
            
            // Create database indexes for better query performance
            createIndexes();
            
            // Initialize connection pool AFTER schema operations are complete
            logger.info("Step 9: Initializing connection pool for runtime operations...");
            try {
                // Writes are serialized on sharedWriteLock, so the pool only needs
                // enough connections for concurrent READS plus the one active
                // writer. A smaller pool cuts connection churn and the per-connection
                // page-cache footprint without limiting write throughput.
                connectionPool = new ConnectionPool(dbUrl, 8, 2, 5000); // max=8, min=2, timeout=5s
                logger.info("Connection pool initialized successfully");
            } catch (Exception poolEx) {
                logger.warn("Connection pool initialization failed, will use single connection: {}", poolEx.getMessage());
                connectionPool = null;
            }
            
            logger.info("Database service initialized successfully with project-specific database");
            logger.info("Project: {} | Database: {}", projectName, currentDatabasePath);
            
        } catch (ClassNotFoundException e) {
            logger.error("STEP FAILED: SQLite JDBC driver not available - this is a critical classpath issue", e);
            initialized.set(false);
            throw new RuntimeException("SQLite JDBC driver not found: " + e.getMessage(), e);
        } catch (SQLException e) {
            logger.error("STEP FAILED: SQL error during database initialization", e);
            logger.error("Database URL attempted: jdbc:sqlite:{}", currentDatabasePath);
            logger.error("Database file parent directory: {}", new java.io.File(currentDatabasePath).getParent());
            initialized.set(false);
            throw new RuntimeException("Database connection failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("STEP FAILED: Unexpected error during database initialization", e);
            logger.error("Database path: {}", currentDatabasePath);
            logger.error("Working directory: {}", System.getProperty("user.dir"));
            logger.error("Java version: {}", System.getProperty("java.version"));
            initialized.set(false);
            throw new RuntimeException("Failed to initialize database service: " + e.getMessage(), e);
        }
    }
    
    /**
     * Detects the current Burp project name.
     * 
     * @return The current project name, or a default name if not available
     */
    private String detectCurrentProject() {
        try {
            String projectName = api.project().name();
            
            // Handle various project name scenarios
            if (projectName == null || projectName.trim().isEmpty()) {
                projectName = "Temporary project";
                logger.info("Project name is null/empty, using: {}", projectName);
            } else {
                logger.info("Detected project name from Burp API: {}", projectName);
            }
            
            // Sanitize project name for file system use
            String sanitizedName = sanitizeProjectNameForFileSystem(projectName);
            logger.info("Sanitized project name for database: {}", sanitizedName);
            
            return sanitizedName;
            
        } catch (Exception e) {
            logger.warn("Failed to detect project name from Burp API: {}", e.getMessage());
            String fallbackName = "unknown-project-" + System.currentTimeMillis();
            logger.info("Using fallback project name: {}", fallbackName);
            return fallbackName;
        }
    }
    
    /**
     * Sanitizes a project name for safe use in file system paths.
     * 
     * @param projectName The original project name
     * @return A sanitized project name safe for file paths
     */
    private String sanitizeProjectNameForFileSystem(String projectName) {
        if (projectName == null) {
            return "unnamed-project";
        }
        
        // Replace unsafe characters with underscores and limit length
        String sanitized = projectName
            .replaceAll("[^a-zA-Z0-9\\-_\\s]", "_")  // Replace unsafe chars
            .replaceAll("\\s+", "_")                  // Replace spaces with underscores
            .replaceAll("_{2,}", "_")                 // Collapse multiple underscores
            .replaceAll("^_+|_+$", "");               // Remove leading/trailing underscores
        
        // Ensure it's not empty and not too long
        if (sanitized.isEmpty()) {
            sanitized = "unnamed_project";
        }
        
        if (sanitized.length() > 100) {
            sanitized = sanitized.substring(0, 100);
        }
        
        return sanitized;
    }
    
    /**
     * Generates a project-specific database path based on the configured base path and project name.
     *
     * <p>When a disk-based Burp project (a {@code .burp} file) is open and the database location
     * has not been explicitly overridden, the database is co-located with the project file so it
     * travels with the project instead of accumulating in the home directory. Temporary projects
     * and explicit path overrides keep the configured directory.
     *
     * @param projectName The sanitized project name
     * @return The complete path to the project-specific database file
     */
    private String generateProjectSpecificDatabasePath(String projectName) {
        String defaultStateDir = System.getProperty("user.home") + java.io.File.separator + ".burp2api";
        String projectFilePath = detectProjectFilePath();
        String path = resolveProjectDatabasePath(config.getDatabasePath(), projectName,
                projectFilePath, defaultStateDir);
        if (projectFilePath != null) {
            logger.info("Co-locating project database with Burp project file: {}", projectFilePath);
        }
        return path;
    }

    /**
     * Resolves the on-disk path for a project-specific database.
     *
     * <p>Pure helper (no I/O, no environment access) so the placement rules are unit-testable.
     * The project database is co-located with the {@code .burp} file only when a project file is
     * known and the configured base directory is still the default state directory — an explicit
     * override to any other directory is always respected.
     *
     * @param configuredBasePath The configured base database path (may be relative-name only)
     * @param projectName        The sanitized project name
     * @param projectFilePath     The open Burp project file path, or {@code null} if unknown
     * @param defaultStateDir     The default state directory ({@code ~/.burp2api})
     * @return The resolved project-specific database path
     */
    static String resolveProjectDatabasePath(String configuredBasePath, String projectName,
                                             String projectFilePath, String defaultStateDir) {
        java.io.File baseFile = new java.io.File(configuredBasePath);
        String configuredDir = baseFile.getParent();
        String baseFileName = baseFile.getName();

        // Remove .db extension if present to add project name
        String baseNameWithoutExt = baseFileName;
        if (baseFileName.toLowerCase().endsWith(".db")) {
            baseNameWithoutExt = baseFileName.substring(0, baseFileName.length() - 3);
        }

        String targetDir = configuredDir;
        if (projectFilePath != null && !projectFilePath.isBlank()) {
            java.io.File projectDir = new java.io.File(projectFilePath).getAbsoluteFile().getParentFile();
            boolean usingDefaultDir = configuredDir == null || sameDir(configuredDir, defaultStateDir);
            if (projectDir != null && usingDefaultDir) {
                targetDir = projectDir.getAbsolutePath();
            }
        }

        // Create project-specific filename
        String projectDbFileName = baseNameWithoutExt + "_" + projectName + ".db";

        // Combine directory and filename
        if (targetDir != null) {
            return targetDir + java.io.File.separator + projectDbFileName;
        } else {
            return projectDbFileName;
        }
    }

    /** Compares two directory paths by normalized absolute form. */
    private static boolean sameDir(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return new java.io.File(a).getAbsoluteFile().equals(new java.io.File(b).getAbsoluteFile());
    }

    /**
     * Detects the open Burp project file path from the JVM process arguments.
     *
     * <p>Burp's launcher relaunches the JVM with {@code --project-file=<path>} when a disk project
     * is opened, so the path is recoverable from the current process arguments. Returns {@code null}
     * for temporary projects or when the path cannot be determined.
     *
     * @return The absolute {@code .burp} project file path, or {@code null} if unknown
     */
    private String detectProjectFilePath() {
        try {
            java.util.Optional<String[]> args = ProcessHandle.current().info().arguments();
            if (args.isPresent()) {
                String fromArgs = extractProjectFileFromArgs(args.get());
                if (fromArgs != null) {
                    return fromArgs;
                }
            }
            // Fallback: the program arguments as a single string (main class/jar + args).
            String cmd = System.getProperty("sun.java.command");
            if (cmd != null && !cmd.isBlank()) {
                return extractProjectFileFromArgs(cmd.trim().split("\\s+"));
            }
        } catch (Exception e) {
            logger.debug("Unable to determine Burp project file path: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Parses a {@code .burp} project file path out of a process argument list.
     *
     * <p>Recognizes {@code --project-file=<path>}, {@code --project-file <path>}, and a bare
     * positional argument ending in {@code .burp}. Pure helper for unit testing.
     *
     * @param args The process argument tokens (may be {@code null})
     * @return The project file path, or {@code null} if none is present
     */
    static String extractProjectFileFromArgs(String[] args) {
        if (args == null) {
            return null;
        }
        final String flag = "--project-file";
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a == null) {
                continue;
            }
            if (a.startsWith(flag + "=")) {
                String value = stripQuotes(a.substring((flag + "=").length()));
                if (!value.isBlank()) {
                    return value;
                }
            } else if (a.equals(flag) && i + 1 < args.length && args[i + 1] != null) {
                String value = stripQuotes(args[i + 1]);
                if (!value.isBlank()) {
                    return value;
                }
            }
        }
        // Fall back to a bare positional project file argument.
        for (String a : args) {
            if (a != null && a.toLowerCase().endsWith(".burp")) {
                String value = stripQuotes(a);
                if (!value.isBlank()) {
                    return value;
                }
            }
        }
        return null;
    }

    /** Removes a single pair of surrounding single or double quotes. */
    private static String stripQuotes(String value) {
        String v = value.trim();
        if (v.length() >= 2
                && ((v.charAt(0) == '"' && v.charAt(v.length() - 1) == '"')
                    || (v.charAt(0) == '\'' && v.charAt(v.length() - 1) == '\''))) {
            return v.substring(1, v.length() - 1);
        }
        return v;
    }
    
    // REMOVED: checkForProjectChangeAndReinitialize() function was causing database instability
    // Project changes will be handled during normal initialization only
    
    /**
     * Gets the current project name.
     * 
     * @return The current project name
     */
    public String getCurrentProjectName() {
        return currentProjectName;
    }
    
    /**
     * Gets the current database path.
     * 
     * @return The current database path
     */
    public String getCurrentDatabasePath() {
        return currentDatabasePath;
    }
    
    /**
     * Configures the SQLite connection with stable, minimal settings.
     */
    private void configureConnection() throws SQLException {
        // Use connection directly here, not getConnection() to avoid recursion
        try (Statement stmt = connection.createStatement()) {
            // CRITICAL: Ensure autocommit is enabled for SQLite
            connection.setAutoCommit(true);
            logger.info("Database autocommit enabled: {}", connection.getAutoCommit());
            
            // Configure optimized PRAGMA settings for high performance
            try {
                // CRITICAL: Enable WAL mode for 10-100x performance improvement
                stmt.execute("PRAGMA journal_mode=WAL");
                logger.info("WAL mode enabled for concurrent access");
                
                // CRITICAL: Per-connection page cache, budgeted in KiB (negative value)
                // so it is independent of page size (#51). 32 MiB keeps a full
                // 8-connection pool under ~256 MiB worst case.
                stmt.execute("PRAGMA cache_size=-" + ConnectionPool.CACHE_SIZE_KIB);
                logger.info("Cache size set to {} KiB per connection", ConnectionPool.CACHE_SIZE_KIB);
                
                // CRITICAL: Use memory for temporary tables (5-10x faster complex queries)
                stmt.execute("PRAGMA temp_store=memory");
                logger.info("Temporary storage set to memory");
                
                // CRITICAL: Enable 256MB memory mapping for 2-3x faster table scans
                stmt.execute("PRAGMA mmap_size=268435456");
                logger.info("Memory mapping enabled (256MB)");
                
                // Increase busy timeout for high-volume concurrent access
                stmt.execute("PRAGMA busy_timeout=30000");
                logger.info("Busy timeout increased to 30 seconds");
                
                // Use NORMAL synchronous mode (optimal for WAL mode)
                stmt.execute("PRAGMA synchronous=NORMAL");
                logger.info("Synchronous mode set to NORMAL (optimal for WAL)");
                
                // Manage WAL file size automatically
                stmt.execute("PRAGMA wal_autocheckpoint=1000");
                logger.info("WAL auto-checkpoint set to 1000 pages");
                
                // Enable foreign key constraints
                stmt.execute("PRAGMA foreign_keys=ON");
                logger.info("Foreign keys enabled");
                
                // Auto-optimize indexes periodically
                stmt.execute("PRAGMA optimize");
                logger.info("Database optimization triggered");
                
                // VALIDATE: Verify PRAGMA settings were applied successfully
                validatePragmaSettings(stmt);
                
                logger.info("SQLite connection configured with HIGH-PERFORMANCE settings");
                
            } catch (SQLException pragmaEx) {
                logger.error("Failed to configure PRAGMA settings: {}", pragmaEx.getMessage());
                logger.error("Exception details: {}", pragmaEx.getClass().getSimpleName());
                pragmaEx.printStackTrace();
                
                // Try to apply settings individually to identify the problem
                logger.warn("Attempting to apply PRAGMA settings individually...");
                tryApplyPragmaIndividually(stmt);
                
                logger.warn("Continuing with whatever settings were successfully applied");
            }
        }
    }
    
    /**
     * Validate that PRAGMA settings were applied successfully.
     */
    private void validatePragmaSettings(Statement stmt) throws SQLException {
        logger.info("Validating PRAGMA settings...");
        
        try (var rs = stmt.executeQuery("PRAGMA cache_size")) {
            if (rs.next()) {
                int cacheSize = rs.getInt(1);
                // Negative value = KiB budget (our mode since #51); positive = pages.
                boolean applied = cacheSize < 0
                        ? -cacheSize >= ConnectionPool.CACHE_SIZE_KIB
                        : cacheSize >= ConnectionPool.CACHE_SIZE_KIB;
                if (applied) {
                    logger.info("Cache size validated: {} (target {} KiB)",
                            cacheSize, ConnectionPool.CACHE_SIZE_KIB);
                } else {
                    logger.warn("Cache size not applied: {} (expected <= -{})",
                            cacheSize, ConnectionPool.CACHE_SIZE_KIB);
                }
            }
        }
        
        try (var rs = stmt.executeQuery("PRAGMA temp_store")) {
            if (rs.next()) {
                int tempStore = rs.getInt(1);
                if (tempStore == 2) {
                    logger.info("Temp store validated: memory");
                } else {
                    logger.warn("Temp store not applied: {} (expected 2 for memory)", tempStore);
                }
            }
        }
        
        try (var rs = stmt.executeQuery("PRAGMA mmap_size")) {
            if (rs.next()) {
                long mmapSize = rs.getLong(1);
                if (mmapSize > 0) {
                    logger.info("Memory mapping validated: {}MB", mmapSize / 1024 / 1024);
                } else {
                    logger.warn("Memory mapping not applied: {} (expected 268435456)", mmapSize);
                }
            }
        }
    }
    
    /**
     * Try to apply PRAGMA settings individually to identify issues.
     */
    private void tryApplyPragmaIndividually(Statement stmt) {
        // Try cache_size
        try {
            stmt.execute("PRAGMA cache_size=-" + ConnectionPool.CACHE_SIZE_KIB);
            logger.info("Cache size applied individually ({} KiB)", ConnectionPool.CACHE_SIZE_KIB);
        } catch (SQLException e) {
            logger.error("Cache size failed: {}", e.getMessage());
        }
        
        // Try temp_store
        try {
            stmt.execute("PRAGMA temp_store=memory");
            logger.info("Temp store applied individually");
        } catch (SQLException e) {
            logger.error("Temp store failed: {}", e.getMessage());
        }
        
        // Try mmap_size  
        try {
            stmt.execute("PRAGMA mmap_size=268435456");
            logger.info("Memory mapping applied individually");
        } catch (SQLException e) {
            logger.error("Memory mapping failed: {}", e.getMessage());
        }
        
        // Try foreign_keys
        try {
            stmt.execute("PRAGMA foreign_keys=ON");
            logger.info("Foreign keys applied individually");
        } catch (SQLException e) {
            logger.error("Foreign keys failed: {}", e.getMessage());
        }
        
        // Validate after individual application
        try {
            validatePragmaSettings(stmt);
        } catch (SQLException e) {
            logger.error("Validation after individual application failed: {}", e.getMessage());
        }
    }
    
    /**
     * Migrates database schema to add missing timing columns.
     */
    private void migrateSchemaIfNeeded() throws SQLException {
        logger.info("Checking and migrating database schema if needed...");
        
        try (Statement stmt = connection.createStatement()) {
            // Check if timing columns exist
            try {
                stmt.executeQuery("SELECT request_http_version FROM proxy_traffic LIMIT 1").close();
                logger.info("Database schema is up to date");
                return;
            } catch (SQLException e) {
                logger.info("Missing timing columns detected, adding them...");
            }
            
            // Add missing timing and HTTP version columns
            String[] newColumns = {
                "ALTER TABLE proxy_traffic ADD COLUMN request_http_version VARCHAR(10) DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN response_http_version VARCHAR(10) DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN dns_resolution_time INTEGER DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN connection_time INTEGER DEFAULT NULL", 
                "ALTER TABLE proxy_traffic ADD COLUMN tls_negotiation_time INTEGER DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN request_time INTEGER DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN response_time INTEGER DEFAULT NULL",
                "ALTER TABLE proxy_traffic ADD COLUMN total_time INTEGER DEFAULT NULL"
            };
            
            for (String alterSql : newColumns) {
                try {
                    stmt.execute(alterSql);
                    logger.info("Added column: {}", alterSql.substring(alterSql.indexOf("ADD COLUMN") + 11, alterSql.indexOf(" ", alterSql.indexOf("ADD COLUMN") + 11)));
                } catch (SQLException e) {
                    // Column might already exist, continue
                    logger.debug("Column already exists or error adding: {}", e.getMessage());
                }
            }
            
            logger.info("Database schema migration completed successfully");
        }
    }
    
    /**
     * Creates database indexes for better query performance.
     */
    private void createIndexes() throws SQLException {
        logger.info("Creating database indexes for optimal query performance...");
        
        // OPTIMIZED INDEXES: Composite indexes for common query patterns
        String[] indexes = {
            // PRIMARY: Time-range queries (most common) - timestamp DESC for latest-first ordering
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_timestamp_desc ON proxy_traffic(timestamp DESC)",
            
            // SEARCH: URL + method combinations (common in filtering)
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_url_method ON proxy_traffic(url, method)",
            
            // FILTERING: Host + timestamp (common for site-specific analysis)
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_host_timestamp ON proxy_traffic(host, timestamp DESC)",
            
            // STATUS: Status code + timestamp (error analysis, success filtering)
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_status_timestamp ON proxy_traffic(status_code, timestamp DESC)",
            
            // SESSION: Session tag + timestamp (session-based filtering)  
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_session_timestamp ON proxy_traffic(session_tag, timestamp DESC)",
            
            // SCOPE: Partial index for completed requests only (reduces index size)
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_scope_complete ON proxy_traffic(url, timestamp DESC, method) WHERE status_code IS NOT NULL",
            
            // LEGACY: Keep compound index for complex multi-column queries
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_compound ON proxy_traffic(timestamp DESC, host, method)"
        };
        
        try (Statement stmt = getConnection().createStatement()) {
            for (String indexSql : indexes) {
                try {
                    stmt.execute(indexSql);
                    logger.debug("Created index: {}", indexSql.substring(indexSql.indexOf("idx_")));
                } catch (SQLException e) {
                    logger.warn("Failed to create index: {}", e.getMessage());
                }
            }
        }
        
        logger.info("Database indexes created successfully");
    }
    
    /**
     * Stores a proxy request in the database.
     * 
     * @param request The intercepted request to store
     */
    public void storeRequest(InterceptedRequest request) {
        if (shutdown.get() || connection == null) {
            return;
        }

        // Isolate the INSERT on a leased write connection so its
        // last_insert_rowid() cannot be clobbered by another thread's write (#37).
        try (WriteLease lease = new WriteLease()) {
            storeRequestOnConnection(lease.conn, request);
            logger.debug("Stored request: {} {}", request.method(), request.url());
        } catch (SQLException e) {
            logger.error("Failed to store request", e);
        }
    }

    /**
     * Core proxy-request INSERT on a caller-supplied connection. Manages no
     * lease/commit of its own, so it runs either standalone (one autocommit
     * statement via {@link #storeRequest}) or inside a shared batch transaction
     * (see {@link #storeQueuedBatch}).
     */
    private void storeRequestOnConnection(Connection conn, InterceptedRequest request) throws SQLException {
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, session_tag, request_http_version, " +
                    "request_raw, request_raw_omitted" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(request.method(), 10));
            stmt.setString(3, sanitizeString(request.url(), 8192));
            stmt.setString(4, sanitizeString(request.httpService().host(), 255));
            stmt.setString(5, sanitizeContent(request.headers().toString()));
            stmt.setString(6, sanitizeContent(request.bodyToString()));
            stmt.setString(7, sanitizeString(config.getSessionTag(), 100));
            stmt.setString(8, sanitizeString(request.httpVersion(), 10));
            bindRaw(stmt, 9, rawBytes(request.toByteArray()));

            stmt.executeUpdate();
        }
    }
    
    /**
     * Stores a proxy response and updates the corresponding request.
     * 
     * @param response The intercepted response to store
     */
    public void storeResponse(InterceptedResponse response) {
        if (shutdown.get() || connection == null) {
            return;
        }
        try (WriteLease lease = new WriteLease()) {
            storeResponseOnConnection(lease.conn, response);
        } catch (SQLException e) {
            logger.error("Failed to store response", e);
        }
    }

    /**
     * Core response-correlation logic on a caller-supplied connection: three
     * time-windowed UPDATE strategies to attach the response to its pending
     * request, then an orphaned-response INSERT fallback. Opens no lease and runs
     * every statement on {@code conn}, so it works standalone (via
     * {@link #storeResponse}) or inside a shared batch transaction (see
     * {@link #storeQueuedBatch}). Individual strategy failures are logged and
     * skipped, exactly as the single-connection version did.
     */
    private void storeResponseOnConnection(Connection conn, InterceptedResponse response) throws SQLException {
        String requestUrl = response.initiatingRequest().url();
        String requestMethod = response.initiatingRequest().method();
        byte[] respRaw = rawBytes(response.toByteArray());

        logger.debug("Attempting to store response: {} for {} {}",
                    response.statusCode(), requestMethod, requestUrl);

        // Strategy 1: Try exact URL + method match within recent time window (last 60 seconds)
        String exactMatchSql = "UPDATE proxy_traffic " +
                              "SET status_code = ?, response_headers = ?, response_body = ?, response_http_version = ?, " +
                              "response_raw = ?, response_raw_omitted = ? " +
                              "WHERE id = (SELECT id FROM proxy_traffic " +
                              "WHERE url = ? AND method = ? AND status_code IS NULL " +
                              "AND timestamp > datetime('now', '-60 seconds') " +
                              "ORDER BY timestamp DESC LIMIT 1)";

        try (PreparedStatement stmt = conn.prepareStatement(exactMatchSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeContent(response.headers().toString()));
            stmt.setString(3, sanitizeContent(response.bodyToString()));
            stmt.setString(4, sanitizeString(response.httpVersion(), 10));
            bindRaw(stmt, 5, respRaw);
            stmt.setString(7, sanitizeString(requestUrl, 8192));
            stmt.setString(8, sanitizeString(requestMethod, 10));

            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("Exact match - Updated response: {} for {} {}", 
                           response.statusCode(), requestMethod, requestUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed exact match for response", e);
        }
        
        // Strategy 2: Try fuzzy URL match (without query params) + method within time window
        String baseUrl = requestUrl.split("\\?")[0]; // Remove query parameters
        String fuzzyMatchSql = "UPDATE proxy_traffic " +
                              "SET status_code = ?, response_headers = ?, response_body = ?, response_http_version = ?, " +
                              "response_raw = ?, response_raw_omitted = ? " +
                              "WHERE id = (SELECT id FROM proxy_traffic " +
                              "WHERE url LIKE ? AND method = ? AND status_code IS NULL " +
                              "AND timestamp > datetime('now', '-60 seconds') " +
                              "ORDER BY timestamp DESC LIMIT 1)";

        try (PreparedStatement stmt = conn.prepareStatement(fuzzyMatchSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeContent(response.headers().toString()));
            stmt.setString(3, sanitizeContent(response.bodyToString()));
            stmt.setString(4, sanitizeString(response.httpVersion(), 10));
            bindRaw(stmt, 5, respRaw);
            stmt.setString(7, sanitizeString(baseUrl, 8192) + "%");
            stmt.setString(8, sanitizeString(requestMethod, 10));

            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("Fuzzy match - Updated response: {} for {} {} (base: {})", 
                           response.statusCode(), requestMethod, requestUrl, baseUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed fuzzy match for response", e);
        }
        
        // Strategy 3: Fallback to most recent unmatched request within time window
        String fallbackSql = "UPDATE proxy_traffic " +
                            "SET status_code = ?, response_headers = ?, response_body = ?, response_http_version = ?, " +
                            "response_raw = ?, response_raw_omitted = ? " +
                            "WHERE id = (SELECT id FROM proxy_traffic " +
                            "WHERE status_code IS NULL " +
                            "AND timestamp > datetime('now', '-120 seconds') " +
                            "ORDER BY timestamp DESC LIMIT 1)";

        try (PreparedStatement stmt = conn.prepareStatement(fallbackSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeContent(response.headers().toString()));
            stmt.setString(3, sanitizeContent(response.bodyToString()));
            stmt.setString(4, sanitizeString(response.httpVersion(), 10));
            bindRaw(stmt, 5, respRaw);

            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("Fallback match - Updated response: {} for {} {}", 
                           response.statusCode(), requestMethod, requestUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed fallback match for response", e);
        }
        
        // Strategy 4: No match found - create orphaned response record.
        // This is routine for async/SPA traffic where the response is seen
        // before its request is matched, so it stays at debug to avoid
        // flooding the console.
        logger.debug("No matching request found for response: {} {} - URL: {} (creating orphaned record)",
                  requestMethod, response.statusCode(), requestUrl);
        storeOrphanedResponseOnConnection(conn, response);
    }

    /**
     * Stores an orphaned response (response without a matching request) as a new
     * record, on a caller-supplied connection (no lease of its own).
     */
    private void storeOrphanedResponseOnConnection(Connection conn, InterceptedResponse response) throws SQLException {
        // #12: record request_http_version/response_http_version too. Both are
        // known here (the response carries its initiatingRequest), and omitting
        // them left every orphaned-response row reporting a null HTTP version —
        // which read as "unknown protocol" for HTTP/2 traffic whose response
        // fell through the request-correlation window into this path.
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, status_code, response_headers, response_body, session_tag, " +
                    "request_raw, request_raw_omitted, response_raw, response_raw_omitted, " +
                    "request_http_version, response_http_version" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(response.initiatingRequest().method(), 10));
            stmt.setString(3, sanitizeString(response.initiatingRequest().url(), 8192));
            stmt.setString(4, sanitizeString(response.initiatingRequest().httpService().host(), 255));
            stmt.setString(5, sanitizeContent(response.initiatingRequest().headers().toString()));
            stmt.setString(6, sanitizeContent(response.initiatingRequest().bodyToString()));
            stmt.setInt(7, response.statusCode());
            stmt.setString(8, sanitizeContent(response.headers().toString()));
            stmt.setString(9, sanitizeContent(response.bodyToString()));
            stmt.setString(10, sanitizeString(config.getSessionTag(), 100));
            bindRaw(stmt, 11, rawBytes(response.initiatingRequest().toByteArray()));
            bindRaw(stmt, 13, rawBytes(response.toByteArray()));
            stmt.setString(15, sanitizeString(response.initiatingRequest().httpVersion(), 10));
            stmt.setString(16, sanitizeString(response.httpVersion(), 10));

            stmt.executeUpdate();
            logger.debug("Stored orphaned response as new record");

        } catch (SQLException e) {
            logger.error("Failed to store orphaned response", e);
        }
    }
    
    /**
     * Sanitizes a string by removing control characters and null bytes,
     * and truncating to the specified maximum length.
     * 
     * @param input The input string to sanitize
     * @param maxLength The maximum allowed length
     * @return The sanitized string
     */
    private String sanitizeString(String input, int maxLength) {
        return StoredText.scalar(input, maxLength);
    }

    /**
     * Prepares a captured header block or body for storage. Unlike
     * {@link #sanitizeString}, this never removes a character - the content is
     * evidence, and Burp's {@code bodyToString()} maps one raw byte to one
     * char, so stripping control characters here deleted bytes outright (#20).
     * The cap is a sanity ceiling only, configurable through
     * {@code BURP2API_MAX_STORED_CONTENT_CHARS}.
     */
    private String sanitizeContent(String input) {
        return StoredText.content(input, config.getMaxStoredContentChars());
    }

    /** Null-safe Montoya {@code ByteArray} to {@code byte[]} for raw capture (#24). */
    private static byte[] rawBytes(burp.api.montoya.core.ByteArray byteArray) {
        return byteArray == null ? null : byteArray.getBytes();
    }

    /**
     * Binds a raw-capture pair - the BLOB at {@code idx} and the omitted flag at
     * {@code idx + 1} - applying the {@code BURP2API_MAX_RAW_BYTES} cap (#24).
     * Over-cap bytes are stored NULL with the flag set, never truncated.
     */
    private void bindRaw(PreparedStatement stmt, int idx, byte[] raw) throws SQLException {
        RawCapture capture = RawCapture.cap(raw, config.getMaxRawBytes());
        if (capture.present()) {
            stmt.setBytes(idx, capture.bytes());
        } else {
            stmt.setNull(idx, Types.BLOB);
        }
        stmt.setInt(idx + 1, capture.omitted() ? 1 : 0);
    }

    /**
     * Byte-exact raw request/response capture for a stored row (#24). {@code null}
     * bytes with {@code omitted == false} means the row predates raw capture or
     * was stored through a path that only had a reconstructed string.
     */
    public static final class RawCaptureRow {
        public final byte[] requestRaw;
        public final byte[] responseRaw;
        public final boolean requestRawOmitted;
        public final boolean responseRawOmitted;

        RawCaptureRow(byte[] requestRaw, byte[] responseRaw,
                      boolean requestRawOmitted, boolean responseRawOmitted) {
            this.requestRaw = requestRaw;
            this.responseRaw = responseRaw;
            this.requestRawOmitted = requestRawOmitted;
            this.responseRawOmitted = responseRawOmitted;
        }
    }

    /**
     * Attaches byte-exact raw bytes to an already-stored {@code proxy_traffic}
     * row (#24). Used by the send/replay/all-tools paths, which get a record id
     * back from the store call and hold the live Montoya message. A side whose
     * argument is {@code null} is left untouched; a side over the cap is stored
     * NULL and flagged omitted.
     */
    public void setRawBytes(long id, byte[] requestRaw, byte[] responseRaw) {
        if (shutdown.get() || connection == null || (requestRaw == null && responseRaw == null)) {
            return;
        }

        List<String> setClauses = new ArrayList<>();
        if (requestRaw != null) {
            setClauses.add("request_raw = ?");
            setClauses.add("request_raw_omitted = ?");
        }
        if (responseRaw != null) {
            setClauses.add("response_raw = ?");
            setClauses.add("response_raw_omitted = ?");
        }

        String sql = "UPDATE proxy_traffic SET " + String.join(", ", setClauses) + " WHERE id = ?";
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            int idx = 1;
            if (requestRaw != null) {
                bindRaw(stmt, idx, requestRaw);
                idx += 2;
            }
            if (responseRaw != null) {
                bindRaw(stmt, idx, responseRaw);
                idx += 2;
            }
            stmt.setLong(idx, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            logger.error("Failed to set raw bytes for traffic id {}", id, e);
        }
    }

    /**
     * Reads back the byte-exact raw capture for a {@code proxy_traffic} row (#24),
     * or {@code null} if the id is unknown.
     */
    public RawCaptureRow getRawCapture(long id) {
        if (connection == null) {
            return null;
        }
        String sql = "SELECT request_raw, response_raw, request_raw_omitted, response_raw_omitted "
                   + "FROM proxy_traffic WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new RawCaptureRow(
                        rs.getBytes("request_raw"),
                        rs.getBytes("response_raw"),
                        rs.getInt("request_raw_omitted") != 0,
                        rs.getInt("response_raw_omitted") != 0);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to read raw capture for traffic id {}", id, e);
        }
        return null;
    }
    
    /**
     * Searches for proxy traffic based on criteria with advanced filtering options.
     * Optimized for large databases with safety limits and performance hints.
     * 
     * @param searchParams Map of search parameters
     * @return List of traffic records
     */
    public List<Map<String, Object>> searchTraffic(Map<String, String> searchParams) {
        if (shutdown.get()) {
            logger.warn("Database service is shut down, returning empty results");
            return new ArrayList<>();
        }
        
        // Check if we need to join with traffic_meta for tag/comment filtering
        boolean needsMetaJoin = searchParams.containsKey("tags") || searchParams.containsKey("has_tags") || 
                               searchParams.containsKey("has_comments") || searchParams.containsKey("comment");
        
        StringBuilder sql = new StringBuilder("SELECT ");
        if (needsMetaJoin) {
            sql.append("p.id, p.timestamp, p.method, p.url, p.host, p.status_code, p.headers, p.body, p.response_headers, p.response_body, p.session_tag, p.content_hash, p.traffic_source, p.request_http_version, p.response_http_version, p.dns_resolution_time, p.connection_time, p.tls_negotiation_time, p.request_time, p.response_time, p.total_time, tm.tags, tm.comment ");
            sql.append("FROM proxy_traffic p LEFT JOIN traffic_meta tm ON p.id = tm.id WHERE 1=1");
        } else {
            sql.append("id, timestamp, method, url, host, status_code, headers, body, response_headers, response_body, session_tag, content_hash, traffic_source, request_http_version, response_http_version, dns_resolution_time, connection_time, tls_negotiation_time, request_time, response_time, total_time ");
            sql.append("FROM proxy_traffic WHERE 1=1");
        }
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity and table aliases
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        String tablePrefix = needsMetaJoin ? "p." : "";
        String likeOperator = caseInsensitive ? " AND LOWER(" + tablePrefix + "url) LIKE LOWER(?)" : " AND " + tablePrefix + "url LIKE ?";
        String hostLikeOperator = caseInsensitive ? " AND LOWER(" + tablePrefix + "host) LIKE LOWER(?)" : " AND " + tablePrefix + "host LIKE ?";
        
        // Add search filters
        if (searchParams.containsKey("url")) {
            String urlPattern = searchParams.get("url");
            boolean exactMatch = "exact".equalsIgnoreCase(searchParams.getOrDefault("match", "contains"));
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            if (urlPattern.contains("*") || urlPattern.contains("?")) {
                sql.append(likeOperator);
                params.add(urlPattern.replace("*", "%").replace("?", "_"));
            } else if (exactMatch) {
                // Anchored exact match on the full URL (match=exact); no substring wrapping
                if (caseInsensitive) {
                    sql.append(" AND LOWER(").append(tablePrefix).append("url) = LOWER(?)");
                } else {
                    sql.append(" AND ").append(tablePrefix).append("url = ?");
                }
                params.add(urlPattern);
            } else {
                // Default behavior: wrap with % for substring search
                sql.append(likeOperator);
                params.add("%" + urlPattern + "%");
            }
        }
        
        // Add url_pattern filter (always uses wildcard conversion)
        if (searchParams.containsKey("url_pattern")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url_pattern");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            urlPattern = urlPattern.replace("*", "%").replace("?", "_");
            params.add(urlPattern);
        }
        
        if (searchParams.containsKey("method")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(method) = LOWER(?)");
            } else {
                sql.append(" AND method = ?");
            }
            params.add(searchParams.get("method"));
        }
        
        // Handle host filtering (single or multiple)
        addHostFiltering(sql, params, searchParams, caseInsensitive);
        
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("session_tag")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(session_tag) = LOWER(?)");
            } else {
                sql.append(" AND session_tag = ?");
            }
            params.add(searchParams.get("session_tag"));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        // Add incremental update support with "since" parameter
        addTimestampFiltering(sql, params, searchParams);
        
        // Add tag and comment filtering (only when metadata join is available)
        if (needsMetaJoin) {
            if (searchParams.containsKey("tags")) {
                // Support comma-separated tag search: "authentication,critical" 
                String tags = searchParams.get("tags");
                if (tags.contains(",")) {
                    // Multiple tags - check if ANY of them match
                    String[] tagArray = tags.split(",");
                    sql.append(" AND (");
                    for (int i = 0; i < tagArray.length; i++) {
                        if (i > 0) sql.append(" OR ");
                        sql.append("tm.tags LIKE ?");
                        params.add("%" + tagArray[i].trim() + "%");
                    }
                    sql.append(")");
                } else {
                    // Single tag
                    sql.append(" AND tm.tags LIKE ?");
                    params.add("%" + tags + "%");
                }
            }
            
            if (searchParams.containsKey("has_tags") && "true".equalsIgnoreCase(searchParams.get("has_tags"))) {
                sql.append(" AND tm.tags IS NOT NULL AND tm.tags != ''");
            }
            
            if (searchParams.containsKey("has_comments") && "true".equalsIgnoreCase(searchParams.get("has_comments"))) {
                sql.append(" AND tm.comment IS NOT NULL AND tm.comment != ''");
            }
            
            if (searchParams.containsKey("comment")) {
                if (caseInsensitive) {
                    sql.append(" AND LOWER(tm.comment) LIKE LOWER(?)");
                } else {
                    sql.append(" AND tm.comment LIKE ?");
                }
                params.add("%" + searchParams.get("comment") + "%");
            }
        }
        
        // Add ordering - support sort and order parameters
        String sortColumn = searchParams.getOrDefault("sort", "timestamp");
        String sortOrder = searchParams.getOrDefault("order", "desc");

        // Friendly ordering aliases: order=newest|oldest pin the result to capture
        // recency regardless of any sort column, so "give me the newest rows" is
        // unambiguous. newest => timestamp DESC (newest at offset 0), oldest => ASC (#52).
        if ("newest".equalsIgnoreCase(sortOrder) || "oldest".equalsIgnoreCase(sortOrder)) {
            sortColumn = "timestamp";
            sortOrder = "newest".equalsIgnoreCase(sortOrder) ? "desc" : "asc";
        }

        // Validate sort column for security (prevent SQL injection)
        String[] allowedSortColumns = {"id", "timestamp", "method", "host", "status_code", "url"};
        boolean validSortColumn = false;
        for (String allowed : allowedSortColumns) {
            if (allowed.equalsIgnoreCase(sortColumn)) {
                sortColumn = allowed;
                validSortColumn = true;
                break;
            }
        }
        if (!validSortColumn) {
            sortColumn = "timestamp"; // Default fallback
        }

        // Validate sort order
        if (!sortOrder.equalsIgnoreCase("asc") && !sortOrder.equalsIgnoreCase("desc")) {
            sortOrder = "desc"; // Default fallback
        }

        sql.append(" ORDER BY ").append(sortColumn).append(" ").append(sortOrder.toUpperCase());
        // Break ties on the monotonic id so pagination is deterministic across pages
        // when many rows share a timestamp (same-millis captures); otherwise LIMIT/OFFSET
        // slices can drop or duplicate rows between requests (#52).
        if (!"id".equals(sortColumn)) {
            sql.append(", ").append(tablePrefix).append("id ").append(sortOrder.toUpperCase());
        }
        
        // Safety limits and pagination
        int limit = 100; // Default safe limit
        int offset = 0;
        int maxLimit = 50000; // Absolute maximum for safety
        
        if (searchParams.containsKey("limit")) {
            try {
                int requestedLimit = Integer.parseInt(searchParams.get("limit"));
                if (requestedLimit > maxLimit) {
                    logger.warn("Requested limit {} exceeds maximum {}, capping to maximum", requestedLimit, maxLimit);
                    limit = maxLimit;
                } else if (requestedLimit > 0) {
                    limit = requestedLimit;
                }
            } catch (NumberFormatException e) {
                logger.warn("Invalid limit parameter, using default: {}", searchParams.get("limit"));
            }
        }
        
        if (searchParams.containsKey("offset")) {
            try {
                offset = Math.max(0, Integer.parseInt(searchParams.get("offset")));
            } catch (NumberFormatException e) {
                logger.warn("Invalid offset parameter, using 0: {}", searchParams.get("offset"));
                offset = 0;
            }
        }
        
        // Always apply limit to prevent runaway queries
        sql.append(" LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();

        // Acquire a per-thread pooled read connection: SQLite's JDBC driver is not
        // safe for concurrent use of one physical Connection, and overlapping reads
        // on the single shared connection were aborting mid-query and returning
        // empty/closed responses under load (#52). Released in the finally below.
        Connection conn = acquireReadConnection();
        if (conn == null) {
            logger.error("Database connection is null after acquireReadConnection(), returning empty results");
            return results;
        }

        // Debug logging
        logger.debug("searchTraffic: Executing SQL: {}", sql.toString());
        logger.debug("searchTraffic: Parameters: {}", params);
        try {
            logger.debug("searchTraffic: Connection valid: {}", !conn.isClosed());
        } catch (SQLException e) {
            logger.warn("Could not check connection status: {}", e.getMessage());
        }

        try (PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    
                    // Handle both timestamp formats (epoch millis and formatted timestamp)
                    try {
                        Object timestampObj = rs.getObject("timestamp");
                        if (timestampObj instanceof Number) {
                            // Epoch milliseconds
                            record.put("timestamp", new Timestamp(((Number) timestampObj).longValue()));
                        } else {
                            // Formatted timestamp string
                            record.put("timestamp", rs.getTimestamp("timestamp"));
                        }
                    } catch (SQLException e) {
                        logger.warn("Failed to parse timestamp, using raw value: {}", e.getMessage());
                        record.put("timestamp", rs.getObject("timestamp"));
                    }
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("content_hash", rs.getString("content_hash"));
                    record.put("traffic_source", rs.getString("traffic_source"));
                    record.put("request_http_version", rs.getString("request_http_version"));
                    record.put("response_http_version", rs.getString("response_http_version"));
                    
                    // Add timing data
                    record.put("dns_resolution_time", rs.getObject("dns_resolution_time"));
                    record.put("connection_time", rs.getObject("connection_time"));
                    record.put("tls_negotiation_time", rs.getObject("tls_negotiation_time"));
                    record.put("request_time", rs.getObject("request_time"));
                    record.put("response_time", rs.getObject("response_time"));
                    record.put("total_time", rs.getObject("total_time"));
                    
                    // Add tags and comments if metadata join was used
                    if (needsMetaJoin) {
                        try {
                            record.put("tags", rs.getString("tags"));
                            record.put("comment", rs.getString("comment"));
                        } catch (SQLException e) {
                            // These fields might not exist if no JOIN occurred
                            record.put("tags", null);
                            record.put("comment", null);
                        }
                    }
                    
                    results.add(record);
                }
            }
            
            logger.debug("searchTraffic: Found {} results", results.size());
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("Search query completed: {} results in {}ms (limit={}, offset={})", 
                        results.size(), queryTime, limit, offset);
            
            // Log slow queries for performance monitoring
            if (queryTime > 5000) {
                logger.warn("Slow query detected: {}ms for {} results. Consider adding filters or reducing limit.", 
                           queryTime, results.size());
            }
            
        } catch (SQLException e) {
            logger.error("CRITICAL: Failed to search traffic - SQL: {} - Params: {} - Error: {}",
                        sql.toString(), params, e.getMessage(), e);
        } catch (Exception e) {
            logger.error("CRITICAL: Unexpected error in searchTraffic - SQL: {} - Params: {} - Error: {}",
                        sql.toString(), params, e.getMessage(), e);
        } finally {
            releaseReadConnection(conn);
        }

        return results;
    }
    
    /**
     * Gets the total count of records matching the search criteria (for pagination).
     * 
     * @param searchParams Map of search parameters
     * @return Total count of matching records
     */
    public long getSearchCount(Map<String, String> searchParams) {
        if (shutdown.get()) {
            return 0;
        }
        
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        String likeOperator = caseInsensitive ? " AND LOWER(url) LIKE LOWER(?)" : " AND url LIKE ?";
        String hostLikeOperator = caseInsensitive ? " AND LOWER(host) LIKE LOWER(?)" : " AND host LIKE ?";
        
        // Add same filters as searchTraffic (excluding limit/offset)
        if (searchParams.containsKey("url")) {
            String urlPattern = searchParams.get("url");
            boolean exactMatch = "exact".equalsIgnoreCase(searchParams.getOrDefault("match", "contains"));
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            if (urlPattern.contains("*") || urlPattern.contains("?")) {
                sql.append(likeOperator);
                params.add(urlPattern.replace("*", "%").replace("?", "_"));
            } else if (exactMatch) {
                // Anchored exact match on the full URL (match=exact); no substring wrapping
                if (caseInsensitive) {
                    sql.append(" AND LOWER(url) = LOWER(?)");
                } else {
                    sql.append(" AND url = ?");
                }
                params.add(urlPattern);
            } else {
                // Default behavior: wrap with % for substring search
                sql.append(likeOperator);
                params.add("%" + urlPattern + "%");
            }
        }
        
        // Add url_pattern filter (always uses wildcard conversion)
        if (searchParams.containsKey("url_pattern")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url_pattern");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            urlPattern = urlPattern.replace("*", "%").replace("?", "_");
            params.add(urlPattern);
        }
        
        if (searchParams.containsKey("method")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(method) = LOWER(?)");
            } else {
                sql.append(" AND method = ?");
            }
            params.add(searchParams.get("method"));
        }
        
        // Handle host filtering (single or multiple)
        addHostFiltering(sql, params, searchParams, caseInsensitive);
        
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("session_tag")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(session_tag) = LOWER(?)");
            } else {
                sql.append(" AND session_tag = ?");
            }
            params.add(searchParams.get("session_tag"));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        // Add incremental update support with "since" parameter
        addTimestampFiltering(sql, params, searchParams);

        // Per-thread pooled read connection, matching searchTraffic (#52).
        Connection conn = acquireReadConnection();
        if (conn == null) {
            logger.error("Database connection is null in getSearchCount, returning 0");
            return 0;
        }

        try (PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }

        } catch (SQLException e) {
            logger.error("Failed to get search count", e);
        } finally {
            releaseReadConnection(conn);
        }

        return 0;
    }
    
    /**
     * Parses a timestamp string in ISO 8601 format to a SQL Timestamp.
     * 
     * @param timestampStr The timestamp string to parse
     * @return SQL Timestamp object
     */
    private Timestamp parseTimestamp(String timestampStr) {
        try {
            // Handle ISO 8601 format (e.g., "2024-05-30T19:20:00Z" or "2024-05-30T19:20:00")
            LocalDateTime localDateTime;
            if (timestampStr.endsWith("Z")) {
                localDateTime = LocalDateTime.parse(timestampStr.substring(0, timestampStr.length() - 1));
            } else if (timestampStr.contains("T")) {
                localDateTime = LocalDateTime.parse(timestampStr);
            } else {
                // Handle date-only format (e.g., "2024-05-30")
                localDateTime = LocalDateTime.parse(timestampStr + "T00:00:00");
            }
            return Timestamp.valueOf(localDateTime);
        } catch (Exception e) {
            logger.warn("Failed to parse timestamp '{}', using current time", timestampStr);
            return Timestamp.valueOf(LocalDateTime.now());
        }
    }
    
    /**
     * Shuts down the database service and closes connections.
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("Shutting down database service");
        
        // Shutdown connection pool first
        if (connectionPool != null) {
            try {
                connectionPool.shutdown();
                logger.info("Database connection pool shut down");
            } catch (Exception e) {
                logger.error("Error shutting down connection pool", e);
            }
        }
        
        // Close single connection as fallback
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                logger.info("Database connection closed");
            }
        } catch (SQLException e) {
            logger.error("Error closing database connection", e);
        }
        
        initialized.set(false);
    }
    
    /**
     * Checks if the database service is initialized.
     * 
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        // SIMPLE CHECK: Just check the initialization flag
        // Don't test connection pool on every health check - it's too expensive and error-prone
        boolean flagInitialized = initialized.get();
        if (!flagInitialized) {
            return false;
        }
        
        // Additional validation: check if we have basic database components
        return currentDatabasePath != null && currentProjectName != null;
    }
    
    /**
     * Returns connection for external use, reconnecting if necessary.
     */
    public synchronized Connection getConnection() {
        try {
            // REMOVED: checkForProjectChangeAndReinitialize() was causing database instability
            
            // Test connection validity - only do expensive test occasionally
            boolean needsReconnect = false;
            if (connection == null) {
                needsReconnect = true;
                logger.warn("Database connection is null, needs reconnection");
            } else {
                try {
                    if (connection.isClosed()) {
                        needsReconnect = true;
                        logger.warn("Database connection is closed, needs reconnection");
                    }
                } catch (SQLException sqlEx) {
                    logger.warn("Error checking if connection is closed, assuming it needs reconnection: {}", sqlEx.getMessage());
                    needsReconnect = true;
                }
            }
            // Skip the expensive SELECT 1 test - rely on isClosed() check which is much lighter
            // The SELECT 1 test was causing false positives and unnecessary reconnections
            
            if (needsReconnect) {
                logger.info("Reconnecting to database...");
                // Close existing connection if it exists
                try {
                    if (connection != null && !connection.isClosed()) {
                        connection.close();
                    }
                } catch (SQLException e) {
                    logger.debug("Error closing old connection: {}", e.getMessage());
                }
                
                // Reinitialize - CRITICAL: make sure we succeed
                initialized.set(false);
                try {
                    initialize();
                    logger.info("Database reconnection successful");
                } catch (Exception initEx) {
                    logger.error("Failed to initialize database: {}", initEx.getMessage());
                    // Try one more time with a brief delay
                    try {
                        Thread.sleep(50);
                        initialize();
                        logger.info("Database initialization succeeded on retry");
                    } catch (Exception retryEx) {
                        logger.error("Database initialization failed completely: {}", retryEx.getMessage());
                        // Connection will remain null, initialized will be false
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Unexpected error in getConnection: {}", e.getMessage(), e);
            // Last resort: try to reinitialize if we're not initialized
            if (!initialized.get()) {
                try {
                    initialize();
                } catch (Exception lastResortEx) {
                    logger.error("Last resort database initialization failed: {}", lastResortEx.getMessage());
                }
            }
        }
        return connection;
    }
    
    /**
     * Acquire a connection for a read query. Prefers a per-thread pooled read
     * connection so concurrent searches never share the single {@link #connection}
     * object: SQLite's JDBC driver is not safe for concurrent use of one physical
     * Connection, and overlapping reads on the shared connection were intermittently
     * aborting mid-query and returning empty/closed responses under load (#52).
     * Falls back to the shared connection only when no healthy pool exists.
     *
     * <p>The returned connection MUST be released with
     * {@link #releaseReadConnection(Connection)} in a finally block. Releasing a
     * pooled connection returns it to the pool; releasing the shared fallback is a
     * no-op (the shared connection is never closed here).
     *
     * @return a read connection, or {@code null} if none is available
     */
    Connection acquireReadConnection() {
        if (connectionPool != null && connectionPool.isHealthy()) {
            try {
                return connectionPool.getReadConnection();
            } catch (SQLException e) {
                logger.warn("Pooled read connection unavailable, falling back to shared connection: {}",
                    e.getMessage());
            }
        }
        return getConnection();
    }

    /**
     * Release a connection obtained from {@link #acquireReadConnection()}. A
     * {@link PooledConnection} is returned to the pool; anything else (the shared
     * connection fallback) is left open for reuse.
     */
    void releaseReadConnection(Connection conn) {
        if (conn instanceof PooledConnection) {
            try {
                conn.close();
            } catch (SQLException e) {
                logger.debug("Error returning pooled read connection to pool: {}", e.getMessage());
            }
        }
    }

    /**
     * Get READ-OPTIMIZED connection from pool for query operations.
     * Uses connection pool with read-only optimizations for better concurrent performance.
     */
    public Connection getReadConnection() throws SQLException {
        if (connectionPool != null && connectionPool.isHealthy()) {
            return connectionPool.getReadConnection();
        }
        // Fallback to main connection if pool unavailable
        return getConnection();
    }
    
    /**
     * Get WRITE-OPTIMIZED connection from pool for modification operations.
     * Uses connection pool with full write capabilities for optimal performance.
     */
    public Connection getWriteConnection() throws SQLException {
        if (connectionPool != null && connectionPool.isHealthy()) {
            return connectionPool.getWriteConnection();
        }
        // Fallback to main connection if pool unavailable
        return getConnection();
    }

    /**
     * A write connection leased for the duration of a single logical write
     * operation - one {@code INSERT} plus its {@code last_insert_rowid()} read,
     * or one multi-statement transaction (#37).
     *
     * <p>On the normal path the lease wraps a {@link PooledConnection} checked
     * out from {@link #connectionPool}. That physical connection is used by only
     * the leasing thread until {@link #close()} returns it to the pool, so
     * {@code last_insert_rowid()} and autocommit state are private to the
     * operation and no cross-thread lock is required. This is what makes the id
     * retrieval race-free and replaces the coarse {@code synchronized (this)}
     * serialization the earlier stopgap used on the single shared connection.
     *
     * <p>When no healthy pool exists (early startup, or a failed pool init) the
     * lease falls back to the single shared {@link #connection} and serializes
     * on {@link #sharedWriteLock} so shared-connection writers still cannot
     * interleave an {@code INSERT} with another writer's id read. In that mode
     * {@link #close()} only releases the lock; it never physically closes the
     * shared connection. The lock is reentrant, so a write path that retries
     * itself (e.g. {@link #saveQuery}) is safe.
     *
     * <p>Every pooled connection is created with WAL mode and
     * {@code foreign_keys=ON} (see {@link ConnectionPool}), so constraint
     * enforcement and journalling are identical to the shared connection.
     */
    final class WriteLease implements AutoCloseable {
        final Connection conn;
        private final boolean pooled;

        WriteLease() throws SQLException {
            // Take the global write lock for the whole logical write. This
            // serializes all writers (see sharedWriteLock) so SQLite never sees
            // two connections racing for the WAL write lock, and keeps
            // last_insert_rowid() private to this operation. Reentrant, so a
            // caller that already holds it (a batch, or a self-retrying write)
            // nests safely.
            sharedWriteLock.lock();
            try {
                if (connectionPool != null && connectionPool.isHealthy()) {
                    this.conn = connectionPool.getWriteConnection();
                    this.pooled = true;
                } else {
                    // Degraded: no pool - fall back to the single shared connection.
                    this.pooled = false;
                    this.conn = getConnection();
                }
            } catch (SQLException | RuntimeException e) {
                sharedWriteLock.unlock();
                throw e;
            }
        }

        @Override
        public void close() {
            try {
                if (pooled) {
                    try {
                        conn.close(); // PooledConnection.close() returns it to the pool
                    } catch (SQLException e) {
                        logger.debug("Error returning write connection to pool: {}", e.getMessage());
                    }
                }
                // Non-pooled path uses the shared connection, which is never
                // physically closed here.
            } finally {
                sharedWriteLock.unlock();
            }
        }
    }

    /**
     * Try to acquire the global write lock that serializes every writer (see
     * {@link WriteLease}). Database maintenance takes this lock so ANALYZE,
     * VACUUM, {@code PRAGMA optimize} and checkpoints never collide with traffic
     * writes and never surface {@code SQLITE_BUSY}; a failed acquisition means
     * "a writer is busy right now, skip this maintenance cycle" - not an error.
     *
     * @param timeoutMs how long to wait for the lock
     * @return {@code true} if acquired - the caller MUST then call
     *     {@link #writeUnlock()} in a {@code finally} block
     */
    public boolean tryWriteLock(long timeoutMs) {
        try {
            return sharedWriteLock.tryLock(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Release the global write lock acquired via {@link #tryWriteLock(long)}.
     */
    public void writeUnlock() {
        sharedWriteLock.unlock();
    }

    /**
     * Apply performance PRAGMA settings to existing connection.
     * Call this method to force-apply optimizations to already established connections.
     */
    public void forceApplyPerformanceSettings() {
        logger.info("Force-applying performance PRAGMA settings to existing connection...");
        
        try (Statement stmt = getConnection().createStatement()) {
            // Apply the same optimizations as configureConnection()
            stmt.execute("PRAGMA cache_size=-" + ConnectionPool.CACHE_SIZE_KIB);
            logger.info("Cache size force-applied: {} KiB", ConnectionPool.CACHE_SIZE_KIB);
            
            stmt.execute("PRAGMA temp_store=memory");
            logger.info("Temp store force-applied: memory");
            
            stmt.execute("PRAGMA mmap_size=268435456");
            logger.info("Memory mapping force-applied: 256MB");
            
            stmt.execute("PRAGMA busy_timeout=30000");
            logger.info("Busy timeout force-applied: 30s");
            
            stmt.execute("PRAGMA foreign_keys=ON");
            logger.info("Foreign keys force-applied");
            
            stmt.execute("PRAGMA optimize");
            logger.info("Database optimization force-applied");
            
            logger.info("Performance settings successfully force-applied to existing connection");
            
        } catch (SQLException e) {
            logger.error("Failed to force-apply performance settings: {}", e.getMessage());
        }
    }
    
    /**
     * Deletes traffic records by session tag.
     * 
     * @param sessionTag The session tag to delete
     * @return Number of records deleted
     */
    public int deleteTrafficBySessionTag(String sessionTag) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        String sql = "DELETE FROM proxy_traffic WHERE session_tag = ?";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, sessionTag);
            int deleted = stmt.executeUpdate();
            logger.info("Deleted {} records for session tag '{}'", deleted, sessionTag);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete traffic by session tag", e);
            return 0;
        }
    }
    
    /**
     * Deletes all traffic records.
     * 
     * @return Number of records deleted
     */
    public int deleteAllTraffic() {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        String sql = "DELETE FROM proxy_traffic";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            int deleted = stmt.executeUpdate();
            logger.info("Deleted all {} traffic records", deleted);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete all traffic", e);
            return 0;
        }
    }
    
    /**
     * Deletes traffic records within a time range.
     * 
     * @param startTime Start time (inclusive)
     * @param endTime End time (inclusive)
     * @return Number of records deleted
     */
    public int deleteTrafficByTimeRange(String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        StringBuilder sql = new StringBuilder("DELETE FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (startTime != null) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(startTime));
        }
        
        if (endTime != null) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(endTime));
        }
        
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }

            int deleted = stmt.executeUpdate();
            logger.info("Deleted {} records in time range {} to {}", deleted, startTime, endTime);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete traffic by time range", e);
            return 0;
        }
    }
    
    /**
     * Generates a content hash for deduplication based on request/response content.
     * 
     * @param method HTTP method
     * @param url URL
     * @param headers Headers string
     * @param body Body string
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @return SHA-256 hash of the combined content
     */
    private String generateContentHash(String method, String url, String headers, String body, 
                                     String responseHeaders, String responseBody) {
        try {
            StringBuilder content = new StringBuilder();
            content.append(method != null ? method : "");
            content.append("|");
            content.append(url != null ? url : "");
            content.append("|");
            content.append(headers != null ? headers : "");
            content.append("|");
            content.append(body != null ? body : "");
            content.append("|");
            content.append(responseHeaders != null ? responseHeaders : "");
            content.append("|");
            content.append(responseBody != null ? responseBody : "");
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.toString().getBytes(StandardCharsets.UTF_8));
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (Exception e) {
            logger.warn("Failed to generate content hash, using fallback", e);
            // Fallback to a simpler hash
            return String.valueOf((method + url + (headers != null ? headers.hashCode() : "")).hashCode());
        }
    }
    
    /**
     * Checks if a record with the same content already exists.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param contentHash Content hash
     * @return true if duplicate exists, false otherwise
     */
    private boolean isDuplicateRecord(String method, String url, String host, String contentHash) {
        if (shutdown.get() || connection == null) {
            return false;
        }
        
        String sql = "SELECT COUNT(*) FROM proxy_traffic WHERE method = ? AND url = ? AND host = ? AND content_hash = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, method);
            stmt.setString(2, url);
            stmt.setString(3, host);
            stmt.setString(4, contentHash);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            logger.debug("Failed to check for duplicate record", e);
        }
        
        return false;
    }
    
    /**
     * Removes duplicate records from the database and logs the operation.
     * 
     * @param sessionTag Optional session tag to filter duplicates
     * @return Map with deduplication results
     */
    public Map<String, Object> removeDuplicateRecords(String sessionTag) {
        if (shutdown.get() || connection == null) {
            return Map.of("error", "Database not available");
        }
        
        Map<String, Object> result = new HashMap<>();
        int recordsProcessed = 0;
        int duplicatesFound = 0;
        int duplicatesRemoved = 0;
        
        try {
            // First, identify duplicates
            StringBuilder findDuplicatesSql = new StringBuilder(
                "SELECT method, url, host, content_hash, COUNT(*) as count, " +
                "GROUP_CONCAT(id) as ids " +
                "FROM proxy_traffic WHERE 1=1"
            );
            
            List<Object> params = new ArrayList<>();
            if (sessionTag != null && !sessionTag.isEmpty()) {
                findDuplicatesSql.append(" AND session_tag = ?");
                params.add(sessionTag);
            }
            
            findDuplicatesSql.append(" GROUP BY method, url, host, content_hash HAVING count > 1");
            
            try (PreparedStatement stmt = getConnection().prepareStatement(findDuplicatesSql.toString())) {
                for (int i = 0; i < params.size(); i++) {
                    stmt.setObject(i + 1, params.get(i));
                }
                
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        duplicatesFound++;
                        String ids = rs.getString("ids");
                        int count = rs.getInt("count");
                        recordsProcessed += count;
                        
                        // Keep the first record (lowest ID) and delete the rest
                        String[] idArray = ids.split(",");
                        for (int i = 1; i < idArray.length; i++) {
                            try {
                                long idToDelete = Long.parseLong(idArray[i].trim());
                                String deleteSql = "DELETE FROM proxy_traffic WHERE id = ?";
                                try (WriteLease lease = new WriteLease();
                                     PreparedStatement deleteStmt = lease.conn.prepareStatement(deleteSql)) {
                                    deleteStmt.setLong(1, idToDelete);
                                    int deleted = deleteStmt.executeUpdate();
                                    if (deleted > 0) {
                                        duplicatesRemoved++;
                                    }
                                }
                            } catch (NumberFormatException e) {
                                logger.warn("Invalid ID format in duplicate removal: {}", idArray[i]);
                            }
                        }
                    }
                }
            }
            
            // Log the deduplication operation
            String logSql = "INSERT INTO deduplication_log " +
                          "(operation_type, records_processed, duplicates_found, duplicates_removed, session_tag) " +
                          "VALUES (?, ?, ?, ?, ?)";
            
            // Isolate the INSERT on a leased write connection (see storeRequest / #37).
            try (WriteLease lease = new WriteLease();
                 PreparedStatement logStmt = lease.conn.prepareStatement(logSql)) {
                logStmt.setString(1, "MANUAL_DEDUPLICATION");
                logStmt.setInt(2, recordsProcessed);
                logStmt.setInt(3, duplicatesFound);
                logStmt.setInt(4, duplicatesRemoved);
                logStmt.setString(5, sessionTag);
                logStmt.executeUpdate();
            }
            
            result.put("operation", "deduplication_completed");
            result.put("records_processed", recordsProcessed);
            result.put("duplicate_groups_found", duplicatesFound);
            result.put("duplicate_records_removed", duplicatesRemoved);
            result.put("session_tag", sessionTag);
            result.put("timestamp", System.currentTimeMillis());
            
            logger.info("Deduplication completed: {} duplicates removed from {} groups", 
                       duplicatesRemoved, duplicatesFound);
            
        } catch (SQLException e) {
            logger.error("Failed to remove duplicate records", e);
            result.put("error", "Deduplication failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Gets deduplication statistics and history.
     * 
     * @return Map with deduplication information
     */
    public Map<String, Object> getDeduplicationStats() {
        if (shutdown.get() || connection == null) {
            return Map.of("error", "Database not available");
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Get current duplicate count
            String duplicateCountSql = "SELECT COUNT(*) as total_duplicates FROM (" +
                                     "SELECT method, url, host, content_hash, COUNT(*) as count " +
                                     "FROM proxy_traffic " +
                                     "GROUP BY method, url, host, content_hash " +
                                     "HAVING count > 1" +
                                     ")";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(duplicateCountSql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        stats.put("current_duplicate_groups", rs.getInt("total_duplicates"));
                    }
                }
            }
            
            // Get total records with no content hash (need migration)
            String noHashSql = "SELECT COUNT(*) as no_hash_count FROM proxy_traffic WHERE content_hash IS NULL";
            try (PreparedStatement stmt = getConnection().prepareStatement(noHashSql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        stats.put("records_without_hash", rs.getInt("no_hash_count"));
                    }
                }
            }
            
            // Get deduplication history
            String historySql = "SELECT operation_type, operation_timestamp, records_processed, " +
                              "duplicates_found, duplicates_removed, session_tag " +
                              "FROM deduplication_log ORDER BY operation_timestamp DESC LIMIT 10";
            
            List<Map<String, Object>> history = new ArrayList<>();
            try (PreparedStatement stmt = getConnection().prepareStatement(historySql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> operation = new HashMap<>();
                        operation.put("operation_type", rs.getString("operation_type"));
                        operation.put("timestamp", rs.getTimestamp("operation_timestamp"));
                        operation.put("records_processed", rs.getInt("records_processed"));
                        operation.put("duplicates_found", rs.getInt("duplicates_found"));
                        operation.put("duplicates_removed", rs.getInt("duplicates_removed"));
                        operation.put("session_tag", rs.getString("session_tag"));
                        history.add(operation);
                    }
                }
            }
            
            stats.put("deduplication_history", history);
            stats.put("timestamp", System.currentTimeMillis());
            
        } catch (SQLException e) {
            logger.error("Failed to get deduplication statistics", e);
            stats.put("error", "Failed to get statistics: " + e.getMessage());
        }
        
        return stats;
    }
    
    /**
     * Stores raw HTTP traffic data (for uploads/imports) with deduplication.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param headers Headers string
     * @param body Body string
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @param statusCode Status code (optional)
     * @param sessionTag Session tag
     * @return Generated ID of the stored record, -1 if failed, -2 if duplicate skipped
     */
    public long storeRawTraffic(String method, String url, String host, 
                               String headers, String body, String responseHeaders, 
                               String responseBody, Integer statusCode, String sessionTag) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        // Generate content hash for deduplication
        String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
        
        // Check for duplicates
        if (isDuplicateRecord(method, url, host, contentHash)) {
            logger.debug("Skipping duplicate record: {} {} (Source: {})", method, url, sessionTag);
            return -2; // Indicate duplicate was skipped
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, response_headers, response_body, status_code, session_tag, content_hash" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        // Lease a write connection so the INSERT and its last_insert_rowid() run
        // on a connection no other thread uses concurrently; another thread's
        // INSERT can no longer clobber this id (which is what failed the
        // dependent traffic_requests FOREIGN KEY under load). (#37)
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeContent(headers));
            stmt.setString(6, sanitizeContent(body));
            stmt.setString(7, sanitizeContent(responseHeaders));
            stmt.setString(8, sanitizeContent(responseBody));
            stmt.setObject(9, statusCode);
            stmt.setString(10, sanitizeString(sessionTag, 100));
            stmt.setString(11, contentHash);

            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                // Use SQLite's last_insert_rowid() instead of getGeneratedKeys()
                try (PreparedStatement idStmt = lease.conn.prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            long id = rs.getLong(1);
                            logger.debug("Stored raw traffic: {} {} with ID {} (Source: {})",
                                       method, url, id, sessionTag);
                            return id;
                        }
                    }
                }
            }

        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.debug("Duplicate record detected by database constraint: {} {} (Source: {})",
                           method, url, sessionTag);
                return -2; // Indicate duplicate was rejected by database
            }
            logger.error("Failed to store raw traffic", e);
        }

        return -1;
    }
    
    /**
     * Stores raw traffic data with source tracking for unified logging.
     * 
     * @param method HTTP method
     * @param url Request URL  
     * @param host Host name
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @param statusCode Status code (optional)
     * @param sessionTag Session tag
     * @param source Traffic source for tracking
     * @return Generated ID of the stored record, -1 if failed, -2 if duplicate skipped
     */
    public long storeRawTrafficWithSource(String method, String url, String host, 
                                        String headers, String body, String responseHeaders, 
                                        String responseBody, Integer statusCode, String sessionTag,
                                        TrafficSource source, String requestHttpVersion, String responseHttpVersion) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        // Generate content hash for deduplication
        String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
        
        // Check for duplicates
        if (isDuplicateRecord(method, url, host, contentHash)) {
            logger.debug("Skipping duplicate record: {} {} (Source: {})", method, url, source);
            return -2; // Indicate duplicate was skipped
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, response_headers, response_body, status_code, session_tag, content_hash, traffic_source, request_http_version, response_http_version" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        // Lease a write connection so INSERT + last_insert_rowid() are isolated
        // to one thread; see the storeRawTraffic overload above. (#37)
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeContent(headers));
            stmt.setString(6, sanitizeContent(body));
            stmt.setString(7, sanitizeContent(responseHeaders));
            stmt.setString(8, sanitizeContent(responseBody));
            stmt.setObject(9, statusCode);
            stmt.setString(10, sanitizeString(sessionTag, 100));
            stmt.setString(11, contentHash);
            stmt.setString(12, source.getValue());
            stmt.setString(13, sanitizeString(requestHttpVersion, 10));
            stmt.setString(14, sanitizeString(responseHttpVersion, 10));

            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                // Use SQLite's last_insert_rowid() instead of getGeneratedKeys()
                try (PreparedStatement idStmt = lease.conn.prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            long id = rs.getLong(1);
                            logger.debug("Stored raw traffic with source: {} {} with ID {} (Source: {})",
                                       method, url, id, source);
                            return id;
                        }
                    }
                }
            }

        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.debug("Duplicate record detected by database constraint: {} {} (Source: {})",
                           method, url, source);
                return -2; // Indicate duplicate was rejected by database
            }
            logger.error("Failed to store raw traffic with source: " + source, e);
        }

        return -1;
    }
    
    /**
     * Overloaded method for backward compatibility - without HTTP version parameters
     */
    public long storeRawTrafficWithSource(String method, String url, String host, 
                                        String headers, String body, String responseHeaders, 
                                        String responseBody, Integer statusCode, String sessionTag,
                                        TrafficSource source) {
        return storeRawTrafficWithSource(method, url, host, headers, body, responseHeaders,
                responseBody, statusCode, sessionTag, source, null, null);
    }
    
    /**
     * Enhanced method with timing data support
     */
    public long storeRawTrafficWithSource(String method, String url, String host, 
                                        String headers, String body, String responseHeaders, 
                                        String responseBody, Integer statusCode, String sessionTag,
                                        TrafficSource source, String requestHttpVersion, String responseHttpVersion,
                                        com.burp2api.models.TimingData timingData) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        // Generate content hash for deduplication
        String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
        
        // Check for duplicates
        if (isDuplicateRecord(method, url, host, contentHash)) {
            logger.debug("Skipping duplicate record: {} {} (Source: {})", method, url, source);
            return -2; // Indicate duplicate was skipped
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, response_headers, response_body, status_code, session_tag, content_hash, traffic_source, request_http_version, response_http_version, " +
                    "dns_resolution_time, connection_time, tls_negotiation_time, request_time, response_time, total_time" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        // Lease a write connection so INSERT + last_insert_rowid() are isolated
        // to one thread; see the storeRawTraffic overload above. (#37)
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeContent(headers));
            stmt.setString(6, sanitizeContent(body));
            stmt.setString(7, sanitizeContent(responseHeaders));
            stmt.setString(8, sanitizeContent(responseBody));
            stmt.setObject(9, statusCode);
            stmt.setString(10, sanitizeString(sessionTag, 100));
            stmt.setString(11, contentHash);
            stmt.setString(12, source.getValue());
            stmt.setString(13, sanitizeString(requestHttpVersion, 10));
            stmt.setString(14, sanitizeString(responseHttpVersion, 10));

            // Set timing data
            if (timingData != null) {
                stmt.setObject(15, timingData.getDnsResolutionTime());
                stmt.setObject(16, timingData.getConnectionTime());
                stmt.setObject(17, timingData.getTlsNegotiationTime());
                stmt.setObject(18, timingData.getRequestTime());
                stmt.setObject(19, timingData.getResponseTime());
                stmt.setObject(20, timingData.getTotalTime());
            } else {
                stmt.setNull(15, java.sql.Types.INTEGER);
                stmt.setNull(16, java.sql.Types.INTEGER);
                stmt.setNull(17, java.sql.Types.INTEGER);
                stmt.setNull(18, java.sql.Types.INTEGER);
                stmt.setNull(19, java.sql.Types.INTEGER);
                stmt.setNull(20, java.sql.Types.INTEGER);
            }
            
            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Use SQLite's last_insert_rowid() instead of getGeneratedKeys()
                try (PreparedStatement idStmt = lease.conn.prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            long id = rs.getLong(1);
                            logger.debug("Stored raw traffic with timing data: {} {} with ID {} (Source: {})",
                                       method, url, id, source);
                            return id;
                        }
                    }
                }
            }

        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.debug("Duplicate record detected by database constraint: {} {} (Source: {})",
                           method, url, source);
                return -2; // Indicate duplicate was rejected by database
            }
            logger.error("Failed to store raw traffic with timing data: " + source, e);
        }

        return -1;
    }
    
    /**
     * Stores a traffic record using the normalized schema with optimized batch processing.
     * Uses the new traffic_meta, traffic_requests, and traffic_responses tables.
     * 
     * @param method HTTP method
     * @param url Request URL
     * @param host Host header value
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers
     * @param responseBody Response body
     * @param statusCode HTTP response status code
     * @param sessionTag Session identifier
     * @param source Traffic source (PROXY, REPEATER, etc.)
     * @return traffic_meta ID if successful, -1 if failed, -2 if duplicate
     */
    public long storeTrafficNormalized(String method, String url, String host, String headers, String body,
                                      String responseHeaders, String responseBody, Integer statusCode,
                                      String sessionTag, TrafficSource source, String requestHttpVersion, String responseHttpVersion) {
        return storeTrafficNormalized(method, url, host, headers, body, responseHeaders, responseBody,
                                      statusCode, sessionTag, source, requestHttpVersion, responseHttpVersion, -1L);
    }

    /**
     * As the 12-arg overload, but records the {@code proxy_traffic.id} the same
     * capture already wrote (or {@code <= 0} when unknown) as an exact link on
     * the {@code traffic_meta} row, so request-body search and replay resolve the
     * same request instead of bridging the two id spaces heuristically (#28).
     */
    public long storeTrafficNormalized(String method, String url, String host, String headers, String body,
                                      String responseHeaders, String responseBody, Integer statusCode,
                                      String sessionTag, TrafficSource source, String requestHttpVersion, String responseHttpVersion,
                                      long proxyTrafficId) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        try {
            // Check if we should use normalized schema
            if (!schemaManager.isNormalizedSchemaAvailable(connection)) {
                // Fall back to legacy method
                return storeRawTrafficWithSource(method, url, host, headers, body, 
                                               responseHeaders, responseBody, statusCode, sessionTag, source, 
                                               requestHttpVersion, responseHttpVersion);
            }
            
            // Generate content hash for deduplication
            String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);

            // One leased write connection, one transaction (#37). The insert
            // sequence itself lives in storeTrafficNormalizedOnConnection so the
            // same parent/child logic is reused inside the multi-item batch
            // transaction (see storeQueuedBatch) without duplicating it.
            try (WriteLease lease = new WriteLease()) {
                Connection conn = lease.conn;
                boolean originalAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);

                try {
                    long trafficMetaId = storeTrafficNormalizedOnConnection(conn, method, url, host, headers, body,
                            responseHeaders, responseBody, statusCode, sessionTag, source, contentHash, proxyTrafficId);

                    if (trafficMetaId > 0) {
                        conn.commit();
                        logger.debug("Stored normalized traffic: {} {} with ID {} (Source: {})",
                                   method, url, trafficMetaId, source);
                    } else {
                        // Duplicate (-2) or failed parent insert (-1): nothing to persist.
                        conn.rollback();
                    }
                    return trafficMetaId;

                } catch (SQLException e) {
                    conn.rollback();
                    throw e;
                } finally {
                    conn.setAutoCommit(originalAutoCommit);
                }
            }

        } catch (SQLException e) {
            if (isDuplicateContentHash(e)) {
                logger.debug("Duplicate record detected: {} {} (Source: {})", method, url, source);
                return -2;
            }
            logger.error("Failed to store normalized traffic", e);
            return -1;
        }
    }

    /**
     * Insert one normalized capture (traffic_meta + request + optional response)
     * on a caller-supplied connection, inside the caller's transaction. Manages no
     * autocommit/commit/rollback of its own.
     *
     * <p>Because {@code conn} is private to the calling operation for the duration
     * of the insert, {@code last_insert_rowid()} read inside {@link #insertTrafficMeta}
     * returns this operation's own {@code traffic_meta} id, never another writer's
     * (#37). A {@code content_hash} UNIQUE collision on the parent insert is
     * swallowed and reported as {@code -2} (duplicate) so a surrounding batch
     * transaction stays alive; any other {@link SQLException} propagates.
     *
     * @return the new {@code traffic_meta} id ({@code > 0}), {@code -2} duplicate,
     *     or {@code -1} on a failed parent insert
     */
    private long storeTrafficNormalizedOnConnection(Connection conn, String method, String url, String host,
            String headers, String body, String responseHeaders, String responseBody, Integer statusCode,
            String sessionTag, TrafficSource source, String contentHash, long proxyTrafficId) throws SQLException {
        long trafficMetaId;
        try {
            trafficMetaId = insertTrafficMeta(conn, method, url, host, sessionTag, source, contentHash, proxyTrafficId);
        } catch (SQLException e) {
            if (isDuplicateContentHash(e)) {
                return -2;
            }
            throw e;
        }

        if (trafficMetaId <= 0) {
            return trafficMetaId; // -1 error
        }

        // Insert request data
        insertTrafficRequest(conn, trafficMetaId, headers, body);

        // Insert response data (if available). Response time measurement would
        // require timing at the HTTP request level; 0 is a placeholder.
        if (statusCode != null || responseHeaders != null || responseBody != null) {
            insertTrafficResponse(conn, trafficMetaId, statusCode, responseHeaders, responseBody, 0L);
        }

        return trafficMetaId;
    }

    /**
     * Persist a batch of queued traffic items in ONE write transaction on ONE
     * leased connection, committing exactly once. This replaces the previous
     * per-item lease + per-item commit - hundreds of WAL commits and connection
     * checkouts per {@code TrafficQueue} batch - which produced the multi-second
     * batch stalls. Each item is wrapped in a {@code SAVEPOINT} so one bad item
     * rolls back only itself, not the whole batch.
     *
     * @param items the queued items, in order
     * @return one result per input item, positionally aligned: REQUEST/RESPONSE
     *     yield {@code 1} on success and {@code -1} on error; RAW_TRAFFIC yields
     *     the new {@code traffic_meta} id ({@code > 0}), {@code -2} duplicate, or
     *     {@code -1} error
     */
    public long[] storeQueuedBatch(List<TrafficQueue.TrafficItem> items) {
        long[] results = new long[items == null ? 0 : items.size()];
        if (items == null || items.isEmpty()) {
            return results;
        }
        if (shutdown.get() || connection == null) {
            Arrays.fill(results, -1);
            return results;
        }

        boolean normalizedAvailable;
        try {
            normalizedAvailable = schemaManager.isNormalizedSchemaAvailable(connection);
        } catch (SQLException e) {
            logger.error("Could not determine normalized schema availability for batch", e);
            normalizedAvailable = false;
        }
        if (!normalizedAvailable) {
            // Legacy schema (no normalized tables) - a rare/legacy config. Fall
            // back to the per-item public paths, which each lease their own
            // connection and route RAW_TRAFFIC through storeRawTrafficWithSource.
            return storeQueuedBatchLegacy(items);
        }

        try (WriteLease lease = new WriteLease()) {
            Connection conn = lease.conn;
            boolean originalAutoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                for (int i = 0; i < items.size(); i++) {
                    results[i] = storeOneInBatch(conn, items.get(i));
                }
                conn.commit();
            } catch (SQLException e) {
                // A failure outside the per-item savepoints (e.g. commit itself):
                // roll the whole batch back and report every item as failed.
                safeRollback(conn);
                Arrays.fill(results, -1);
                logger.error("Traffic batch write failed and was rolled back", e);
            } finally {
                try {
                    conn.setAutoCommit(originalAutoCommit);
                } catch (SQLException e) {
                    logger.debug("Could not restore autocommit after batch: {}", e.getMessage());
                }
            }
        } catch (SQLException e) {
            logger.error("Could not lease connection for traffic batch", e);
            Arrays.fill(results, -1);
        }
        return results;
    }

    /**
     * Store one queued item inside an open batch transaction, isolated by a
     * savepoint so its failure does not abort sibling items.
     */
    private long storeOneInBatch(Connection conn, TrafficQueue.TrafficItem item) throws SQLException {
        Savepoint sp = conn.setSavepoint();
        try {
            long result;
            switch (item.type) {
                case REQUEST:
                    storeRequestOnConnection(conn, item.request);
                    result = 1;
                    break;
                case RESPONSE:
                    storeResponseOnConnection(conn, item.response);
                    result = 1;
                    break;
                case RAW_TRAFFIC:
                default:
                    String contentHash = generateContentHash(item.method, item.url, item.headers,
                            item.body, item.responseHeaders, item.responseBody);
                    result = storeTrafficNormalizedOnConnection(conn, item.method, item.url, item.host,
                            item.headers, item.body, item.responseHeaders, item.responseBody, item.statusCode,
                            item.sessionTag, item.source, contentHash, item.proxyTrafficId);
                    break;
            }
            conn.releaseSavepoint(sp);
            return result;
        } catch (SQLException e) {
            // Undo just this item; keep the batch transaction alive for the rest.
            conn.rollback(sp);
            if (isDuplicateContentHash(e)) {
                return -2;
            }
            logger.debug("Skipping traffic item after write error: {}", e.getMessage());
            return -1;
        }
    }

    /**
     * Per-item fallback used only when the normalized schema is unavailable.
     */
    private long[] storeQueuedBatchLegacy(List<TrafficQueue.TrafficItem> items) {
        long[] results = new long[items.size()];
        for (int i = 0; i < items.size(); i++) {
            TrafficQueue.TrafficItem item = items.get(i);
            try {
                switch (item.type) {
                    case REQUEST:
                        storeRequest(item.request);
                        results[i] = 1;
                        break;
                    case RESPONSE:
                        storeResponse(item.response);
                        results[i] = 1;
                        break;
                    case RAW_TRAFFIC:
                    default:
                        results[i] = storeTrafficNormalized(item.method, item.url, item.host, item.headers,
                                item.body, item.responseHeaders, item.responseBody, item.statusCode,
                                item.sessionTag, item.source, item.requestHttpVersion, item.responseHttpVersion,
                                item.proxyTrafficId);
                        break;
                }
            } catch (Exception e) {
                results[i] = -1;
                logger.debug("Legacy batch item failed: {}", e.getMessage());
            }
        }
        return results;
    }

    /** True when a SQLException reports a content_hash UNIQUE collision (a duplicate). */
    private static boolean isDuplicateContentHash(SQLException e) {
        String msg = e.getMessage();
        return msg != null && (msg.contains("UNIQUE constraint failed") || msg.contains("content_hash"));
    }

    /** Roll back the current transaction, logging but never rethrowing on failure. */
    private void safeRollback(Connection conn) {
        try {
            conn.rollback();
        } catch (SQLException e) {
            logger.debug("Rollback after batch failure also failed: {}", e.getMessage());
        }
    }
    
    /**
     * Overloaded method for backward compatibility - without HTTP version parameters
     */
    public long storeTrafficNormalized(String method, String url, String host, String headers, String body,
                                      String responseHeaders, String responseBody, Integer statusCode, 
                                      String sessionTag, TrafficSource source) {
        return storeTrafficNormalized(method, url, host, headers, body, responseHeaders, responseBody,
                                     statusCode, sessionTag, source, null, null, -1L);
    }

    /**
     * Insert traffic metadata with optimized prepared statement.
     *
     * @param proxyTrafficId the exact {@code proxy_traffic.id} this capture also
     *     wrote, or {@code <= 0} when unknown (stored as SQL NULL) (#28)
     */
    private long insertTrafficMeta(Connection conn, String method, String url, String host, String sessionTag,
                                   TrafficSource source, String contentHash, long proxyTrafficId) throws SQLException {
        String sql = "INSERT INTO traffic_meta (timestamp, method, url, host, session_tag, tool_source, content_hash, proxy_traffic_id) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeString(sessionTag, 100));
            stmt.setString(6, source.getValue());
            stmt.setString(7, contentHash);
            if (proxyTrafficId > 0) {
                stmt.setLong(8, proxyTrafficId);
            } else {
                stmt.setNull(8, java.sql.Types.INTEGER);
            }

            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Get the generated ID on the same (leased) connection the INSERT
                // ran on, so it is this transaction's own id. (#37)
                try (PreparedStatement idStmt = conn.prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            return rs.getLong(1);
                        }
                    }
                }
            }
        }

        return -1;
    }

    /**
     * Insert request data with content analysis
     */
    private void insertTrafficRequest(Connection conn, long trafficMetaId, String headers, String body) throws SQLException {
        String sql = "INSERT INTO traffic_requests (traffic_meta_id, headers, body, body_size, content_type) " +
                    "VALUES (?, ?, ?, ?, ?)";

        String contentType = extractContentType(headers);
        int bodySize = body != null ? body.length() : 0;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, trafficMetaId);
            stmt.setString(2, sanitizeContent(headers));
            stmt.setString(3, sanitizeContent(body));
            stmt.setInt(4, bodySize);
            stmt.setString(5, sanitizeString(contentType, 100));
            
            stmt.executeUpdate();
        }
    }
    
    /**
     * Insert response data with performance metrics
     */
    private void insertTrafficResponse(Connection conn, long trafficMetaId, Integer statusCode, String responseHeaders,
                                       String responseBody, long responseTimeMs) throws SQLException {
        String sql = "INSERT INTO traffic_responses (traffic_meta_id, status_code, headers, body, body_size, content_type, response_time_ms) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";

        String contentType = extractContentType(responseHeaders);
        int bodySize = responseBody != null ? responseBody.length() : 0;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, trafficMetaId);
            stmt.setObject(2, statusCode);
            stmt.setString(3, sanitizeContent(responseHeaders));
            stmt.setString(4, sanitizeContent(responseBody));
            stmt.setInt(5, bodySize);
            stmt.setString(6, sanitizeString(contentType, 100));
            stmt.setLong(7, responseTimeMs);
            
            stmt.executeUpdate();
        }
    }
    
    /**
     * Extract content type from headers
     */
    private String extractContentType(String headers) {
        if (headers == null || headers.isEmpty()) {
            return "unknown";
        }
        
        String lowerHeaders = headers.toLowerCase();
        int contentTypeIndex = lowerHeaders.indexOf("content-type:");
        if (contentTypeIndex != -1) {
            int start = contentTypeIndex + 13; // Length of "content-type:"
            int end = lowerHeaders.indexOf('\n', start);
            if (end == -1) end = lowerHeaders.indexOf('\r', start);
            if (end == -1) end = headers.length();
            
            String contentType = headers.substring(start, end).trim();
            // Extract just the media type (before semicolon)
            int semicolonIndex = contentType.indexOf(';');
            if (semicolonIndex != -1) {
                contentType = contentType.substring(0, semicolonIndex).trim();
            }
            return contentType;
        }
        
        return "unknown";
    }

    /**
     * Search traffic using the normalized schema with enhanced filtering
     */
    public List<Map<String, Object>> searchTrafficNormalized(Map<String, Object> searchParams, 
                                                             int limit, int offset) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Fall back to legacy search if normalized schema not available
        try {
            if (!schemaManager.isNormalizedSchemaAvailable(connection)) {
                // Convert params and use legacy search
                Map<String, String> legacyParams = new HashMap<>();
                if (searchParams != null) {
                    searchParams.forEach((k, v) -> legacyParams.put(k, v != null ? v.toString() : null));
                }
                return searchTraffic(legacyParams);
            }
        } catch (SQLException e) {
            logger.error("Error checking normalized schema availability", e);
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();
        
        // Build optimized query using normalized tables
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT tm.id, tm.timestamp, tm.method, tm.url, tm.host, tm.session_tag, tm.tool_source, ")
           .append("tm.tags, tm.comment, tm.replayed_from, ")
           .append("tr.headers, tr.body, tr.body_size, tr.content_type as request_content_type, ")
           .append("tres.status_code, tres.headers as response_headers, tres.body as response_body, ")
           .append("tres.body_size as response_body_size, tres.content_type as response_content_type, ")
           .append("tres.response_time_ms ")
           .append("FROM traffic_meta tm ")
           .append("LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id ")
           .append("LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id ");
        
        List<Object> params = new ArrayList<>();
        
        // Add WHERE conditions
        if (searchParams != null && !searchParams.isEmpty()) {
            sql.append("WHERE 1=1 ");
            
            if (searchParams.containsKey("method")) {
                sql.append("AND tm.method = ? ");
                params.add(searchParams.get("method"));
            }
            
            // Handle host filtering (single or multiple)
            addHostFilteringFromObjectMap(sql, params, searchParams, false, "tm.host");
            
            if (searchParams.containsKey("url")) {
                sql.append("AND tm.url LIKE ? ");
                params.add("%" + searchParams.get("url") + "%");
            }
            
            if (searchParams.containsKey("status_code")) {
                sql.append("AND tres.status_code = ? ");
                params.add(searchParams.get("status_code"));
            }
            
            if (searchParams.containsKey("session_tag")) {
                sql.append("AND tm.session_tag = ? ");
                params.add(searchParams.get("session_tag"));
            }
            
            if (searchParams.containsKey("tool_source")) {
                sql.append("AND tm.tool_source = ? ");
                params.add(searchParams.get("tool_source"));
            }
            
            if (searchParams.containsKey("start_time")) {
                sql.append("AND tm.timestamp >= ? ");
                params.add(parseTimestamp(searchParams.get("start_time").toString()));
            }
            
            if (searchParams.containsKey("end_time")) {
                sql.append("AND tm.timestamp <= ? ");
                params.add(parseTimestamp(searchParams.get("end_time").toString()));
            }
            
            // Enhanced search parameters
            if (searchParams.containsKey("tags")) {
                sql.append("AND tm.tags LIKE ? ");
                params.add("%" + searchParams.get("tags") + "%");
            }
            
            if (searchParams.containsKey("comment")) {
                sql.append("AND tm.comment LIKE ? ");
                params.add("%" + searchParams.get("comment") + "%");
            }
            
            if (searchParams.containsKey("replayed_from")) {
                sql.append("AND tm.replayed_from = ? ");
                params.add(searchParams.get("replayed_from"));
            }
            
            if (searchParams.containsKey("request_body_contains")) {
                sql.append("AND tr.body LIKE ? ");
                params.add("%" + searchParams.get("request_body_contains") + "%");
            }
        }
        
        // Add ordering and pagination
        sql.append("ORDER BY tm.timestamp DESC ");
        sql.append("LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getObject("replayed_from"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("body_size", rs.getInt("body_size"));
                    record.put("request_content_type", rs.getString("request_content_type"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("response_body_size", rs.getInt("response_body_size"));
                    record.put("response_content_type", rs.getString("response_content_type"));
                    record.put("response_time_ms", rs.getInt("response_time_ms"));
                    results.add(record);
                }
            }
            
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("Normalized search completed: {} results in {}ms", results.size(), queryTime);
            
            // Log slow queries for performance monitoring
            if (queryTime > 5000) {
                logger.warn("Slow normalized query: {}ms for {} results", queryTime, results.size());
            }
            
        } catch (SQLException e) {
            logger.error("Failed to search normalized traffic", e);
        }
        
        return results;
    }
    
    /**
     * Perform full-text search using FTS5 if available
     */
    public List<Map<String, Object>> searchTrafficFullText(String searchQuery, int limit, int offset) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Check if FTS5 is available
        try {
            if (!schemaManager.isFTS5SearchAvailable(connection)) {
                logger.warn("FTS5 search not available, falling back to LIKE search");
                return searchTrafficLike(searchQuery, limit, offset);
            }
        } catch (SQLException e) {
            logger.error("Error checking FTS5 availability", e);
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();
        
        String sql = "SELECT tm.id, tm.timestamp, tm.method, tm.url, tm.host, tm.session_tag, tm.tool_source, " +
                    "tr.headers, tr.body, tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM response_index ri " +
                    "JOIN traffic_meta tm ON tm.id = ri.traffic_meta_id " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE response_index MATCH ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, searchQuery);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
            
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("FTS5 search completed: {} results in {}ms", results.size(), queryTime);
            
        } catch (SQLException e) {
            logger.error("Failed to perform FTS5 search", e);
        }
        
        return results;
    }
    
    /**
     * Fallback LIKE-based search when FTS5 is not available
     */
    private List<Map<String, Object>> searchTrafficLike(String searchQuery, int limit, int offset) {
        Map<String, Object> searchParams = new HashMap<>();
        // Simple fallback - search in URL
        searchParams.put("url", searchQuery);
        return searchTrafficNormalized(searchParams, limit, offset);
    }

    /**
     * Gets a traffic record by ID for replay purposes.
     * 
     * @param id The record ID
     * @return Traffic record map or null if not found
     */
    public Map<String, Object> getTrafficById(long id) {
        if (shutdown.get() || connection == null) {
            return null;
        }
        
        String sql = "SELECT * FROM proxy_traffic WHERE id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, id);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("content_hash", rs.getString("content_hash"));
                    record.put("traffic_source", rs.getString("traffic_source"));
                    record.put("request_http_version", rs.getString("request_http_version"));
                    record.put("response_http_version", rs.getString("response_http_version"));
                    return record;
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic by ID", e);
        }
        
        return null;
    }
    
    /**
     * Gets traffic statistics grouped by host, method, and status code.
     * 
     * @param searchParams Optional search parameters for filtering
     * @return Statistics data grouped by various dimensions
     */
    public Map<String, Object> getTrafficStats(Map<String, String> searchParams) {
        if (shutdown.get()) {
            return new HashMap<>();
        }
        
        Connection conn = getConnection();
        if (conn == null) {
            logger.error("Database connection is null in getTrafficStats, returning empty stats");
            return new HashMap<>();
        }
        
        Map<String, Object> stats = new HashMap<>();

        logger.debug("getTrafficStats called with params: {}", searchParams);

        try {
            // Build base WHERE clause from search parameters
            StringBuilder whereClause = new StringBuilder("WHERE 1=1");
            List<Object> parameters = new ArrayList<>();
            
            // Handle host filtering (single or multiple)
            addHostFiltering(whereClause, parameters, searchParams, false);
            if (searchParams.containsKey("method")) {
                whereClause.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                whereClause.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            if (searchParams.containsKey("start_time")) {
                whereClause.append(" AND timestamp >= ?");
                parameters.add(parseTimestamp(searchParams.get("start_time")));
            }
            if (searchParams.containsKey("end_time")) {
                whereClause.append(" AND timestamp <= ?");
                parameters.add(parseTimestamp(searchParams.get("end_time")));
            }
            
            // Add incremental update support with "since" parameter
            addTimestampFiltering(whereClause, parameters, searchParams);
            
            // Total count
            String totalSql = "SELECT COUNT(*) as total FROM proxy_traffic " + whereClause;
            try (PreparedStatement stmt = conn.prepareStatement(totalSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("total_requests", rs.getLong("total"));
                }
            }
            
            // Count of requests with responses
            String completedSql = "SELECT COUNT(*) as completed FROM proxy_traffic " + 
                                whereClause + " AND status_code IS NOT NULL";
            try (PreparedStatement stmt = conn.prepareStatement(completedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("completed_requests", rs.getLong("completed"));
                }
            }
            
            // Count of orphaned requests (no response)
            String orphanedSql = "SELECT COUNT(*) as orphaned FROM proxy_traffic " + 
                                whereClause + " AND status_code IS NULL";
            try (PreparedStatement stmt = conn.prepareStatement(orphanedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("orphaned_requests", rs.getLong("orphaned"));
                }
            }
            
            // Recent orphaned requests (last 10 minutes)
            String recentOrphanedSql = "SELECT COUNT(*) as recent_orphaned FROM proxy_traffic " + 
                                     whereClause + " AND status_code IS NULL " +
                                     "AND timestamp > datetime('now', '-10 minutes')";
            try (PreparedStatement stmt = conn.prepareStatement(recentOrphanedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("recent_orphaned_requests", rs.getLong("recent_orphaned"));
                }
            }
            
            // Stats by host - support configurable limit
            String hostLimit = "";
            if (searchParams.containsKey("all_hosts") && "true".equals(searchParams.get("all_hosts"))) {
                // No limit when all_hosts=true
                hostLimit = "";
            } else if (searchParams.containsKey("host_limit")) {
                try {
                    int limit = Integer.parseInt(searchParams.get("host_limit"));
                    if (limit > 0 && limit <= 10000) { // Cap at reasonable maximum
                        hostLimit = " LIMIT " + limit;
                    } else {
                        hostLimit = " LIMIT 50"; // Default fallback
                    }
                } catch (NumberFormatException e) {
                    hostLimit = " LIMIT 50"; // Default fallback
                }
            } else {
                hostLimit = " LIMIT 50"; // Default behavior
            }
            
            String hostSql = "SELECT host, COUNT(*) as count FROM proxy_traffic " + 
                           whereClause + " GROUP BY host ORDER BY count DESC" + hostLimit;
            try (PreparedStatement stmt = conn.prepareStatement(hostSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> hostStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> hostStat = new HashMap<>();
                    hostStat.put("host", rs.getString("host"));
                    hostStat.put("count", rs.getLong("count"));
                    hostStats.add(hostStat);
                }
                stats.put("by_host", hostStats);
            }
            
            // Stats by method
            String methodSql = "SELECT method, COUNT(*) as count FROM proxy_traffic " + 
                             whereClause + " GROUP BY method ORDER BY count DESC";
            try (PreparedStatement stmt = conn.prepareStatement(methodSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> methodStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> methodStat = new HashMap<>();
                    methodStat.put("method", rs.getString("method"));
                    methodStat.put("count", rs.getLong("count"));
                    methodStats.add(methodStat);
                }
                stats.put("by_method", methodStats);
            }
            
            // Stats by status code
            String statusSql = "SELECT status_code, COUNT(*) as count FROM proxy_traffic " + 
                             whereClause + " AND status_code IS NOT NULL GROUP BY status_code ORDER BY count DESC";
            try (PreparedStatement stmt = conn.prepareStatement(statusSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> statusStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> statusStat = new HashMap<>();
                    statusStat.put("status_code", rs.getInt("status_code"));
                    statusStat.put("count", rs.getLong("count"));
                    statusStats.add(statusStat);
                }
                stats.put("by_status_code", statusStats);
            }
            
            // Stats by session tag
            String sessionSql = "SELECT session_tag, COUNT(*) as count FROM proxy_traffic " + 
                              whereClause + " GROUP BY session_tag ORDER BY count DESC LIMIT 20";
            try (PreparedStatement stmt = conn.prepareStatement(sessionSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> sessionStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> sessionStat = new HashMap<>();
                    sessionStat.put("session_tag", rs.getString("session_tag"));
                    sessionStat.put("count", rs.getLong("count"));
                    sessionStats.add(sessionStat);
                }
                stats.put("by_session_tag", sessionStats);
            }
            
        } catch (SQLException e) {
            logger.error("CRITICAL: Failed to get traffic statistics - SQL Error: {}", e.getMessage(), e);
            stats.put("error", "Database query failed: " + e.getMessage());
        } catch (Exception e) {
            logger.error("CRITICAL: Unexpected error in getTrafficStats: {}", e.getMessage(), e);
            stats.put("error", "Unexpected error: " + e.getMessage());
        }
        
        return stats;
    }
    
    /**
     * Gets traffic statistics grouped by traffic source for unified logging analytics.
     * 
     * @return Statistics data grouped by traffic source
     */
    public Map<String, Object> getTrafficStatsBySource() {
        if (shutdown.get()) {
            return new HashMap<>();
        }
        
        Connection conn = getConnection();
        if (conn == null) {
            logger.error("Database connection is null in getTrafficStatsBySource, returning empty stats");
            return new HashMap<>();
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Total count by traffic source
            String sourceSql = "SELECT traffic_source, COUNT(*) as count FROM proxy_traffic " +
                             "GROUP BY traffic_source ORDER BY count DESC";
            
            try (PreparedStatement stmt = conn.prepareStatement(sourceSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> sourceStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> sourceStat = new HashMap<>();
                    sourceStat.put("source", rs.getString("traffic_source"));
                    sourceStat.put("count", rs.getLong("count"));
                    sourceStats.add(sourceStat);
                }
                stats.put("by_source", sourceStats);
            }
            
            // Success rates by source
            String successRateSql = "SELECT traffic_source, " +
                                  "COUNT(*) as total_requests, " +
                                  "COUNT(CASE WHEN status_code IS NOT NULL THEN 1 END) as completed_requests, " +
                                  "COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as success_requests, " +
                                  "COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_requests " +
                                  "FROM proxy_traffic GROUP BY traffic_source ORDER BY total_requests DESC";
            
            try (PreparedStatement stmt = conn.prepareStatement(successRateSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> successRateStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> rateStat = new HashMap<>();
                    long totalRequests = rs.getLong("total_requests");
                    long completedRequests = rs.getLong("completed_requests");
                    long successRequests = rs.getLong("success_requests");
                    long errorRequests = rs.getLong("error_requests");
                    
                    rateStat.put("source", rs.getString("traffic_source"));
                    rateStat.put("total_requests", totalRequests);
                    rateStat.put("completed_requests", completedRequests);
                    rateStat.put("success_requests", successRequests);
                    rateStat.put("error_requests", errorRequests);
                    
                    // Calculate percentages
                    if (totalRequests > 0) {
                        rateStat.put("completion_rate", Math.round((completedRequests * 100.0) / totalRequests));
                    } else {
                        rateStat.put("completion_rate", 0);
                    }
                    
                    if (completedRequests > 0) {
                        rateStat.put("success_rate", Math.round((successRequests * 100.0) / completedRequests));
                        rateStat.put("error_rate", Math.round((errorRequests * 100.0) / completedRequests));
                    } else {
                        rateStat.put("success_rate", 0);
                        rateStat.put("error_rate", 0);
                    }
                    
                    successRateStats.add(rateStat);
                }
                stats.put("success_rates_by_source", successRateStats);
            }
            
            // Recent activity by source (last 24 hours)
            String recentSql = "SELECT traffic_source, COUNT(*) as recent_count " +
                             "FROM proxy_traffic WHERE timestamp > datetime('now', '-24 hours') " +
                             "GROUP BY traffic_source ORDER BY recent_count DESC";
            
            try (PreparedStatement stmt = conn.prepareStatement(recentSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> recentStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> recentStat = new HashMap<>();
                    recentStat.put("source", rs.getString("traffic_source"));
                    recentStat.put("recent_count", rs.getLong("recent_count"));
                    recentStats.add(recentStat);
                }
                stats.put("recent_activity_by_source", recentStats);
            }
            
            // Overall summary
            String totalSql = "SELECT COUNT(*) as total_records FROM proxy_traffic";
            try (PreparedStatement stmt = conn.prepareStatement(totalSql)) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("total_records", rs.getLong("total_records"));
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic statistics by source", e);
        }
        
        return stats;
    }
    
    /**
     * Gets traffic timeline grouped by time intervals.
     * Uses actual request dates from response headers instead of database import timestamps.
     * 
     * @param searchParams Search parameters for filtering
     * @param interval Time interval for grouping (hour, day, minute)
     * @return Timeline data grouped by time intervals
     */
    public List<Map<String, Object>> getTrafficTimeline(Map<String, String> searchParams, String interval) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Since we need to parse response headers to get actual request dates,
        // we'll fetch the data and process it in Java rather than SQL
        Map<String, Map<String, Long>> timelineMap = new HashMap<>();
        
        try {
            // Build WHERE clause for initial filtering
            StringBuilder whereClause = new StringBuilder("WHERE 1=1");
            List<Object> parameters = new ArrayList<>();
            
            // Handle host filtering (single or multiple)
            addHostFiltering(whereClause, parameters, searchParams, false);
            if (searchParams.containsKey("method")) {
                whereClause.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                whereClause.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            // Note: start_time/end_time filtering will be done after parsing response headers
            
            String sql = "SELECT id, status_code, response_headers " +
                        "FROM proxy_traffic " + whereClause + 
                        " AND response_headers IS NOT NULL";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    String responseHeaders = rs.getString("response_headers");
                    int statusCode = rs.getInt("status_code");
                    
                    // Extract Date header from response headers
                    String actualRequestDate = extractDateFromHeaders(responseHeaders);
                    if (actualRequestDate != null) {
                        // Apply time range filtering if specified
                        if (searchParams.containsKey("start_time") || searchParams.containsKey("end_time")) {
                            try {
                                java.time.LocalDateTime requestDateTime = parseHttpDate(actualRequestDate);
                                if (requestDateTime != null) {
                                    if (searchParams.containsKey("start_time")) {
                                        java.time.LocalDateTime startTime = java.time.LocalDateTime.parse(searchParams.get("start_time").replace("T", " "), 
                                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                                        if (requestDateTime.isBefore(startTime)) continue;
                                    }
                                    if (searchParams.containsKey("end_time")) {
                                        java.time.LocalDateTime endTime = java.time.LocalDateTime.parse(searchParams.get("end_time").replace("T", " "), 
                                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                                        if (requestDateTime.isAfter(endTime)) continue;
                                    }
                                }
                            } catch (Exception e) {
                                logger.debug("Failed to parse date for filtering: {}", actualRequestDate);
                                continue;
                            }
                        }
                        
                        String timePeriod = formatDateForInterval(actualRequestDate, interval);
                        if (timePeriod != null) {
                            timelineMap.computeIfAbsent(timePeriod, k -> {
                                Map<String, Long> counts = new HashMap<>();
                                counts.put("total", 0L);
                                counts.put("success", 0L);
                                counts.put("error", 0L);
                                return counts;
                            });
                            
                            Map<String, Long> counts = timelineMap.get(timePeriod);
                            counts.put("total", counts.get("total") + 1);
                            
                            if (statusCode >= 200 && statusCode < 300) {
                                counts.put("success", counts.get("success") + 1);
                            } else if (statusCode >= 400) {
                                counts.put("error", counts.get("error") + 1);
                            }
                        }
                    }
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic timeline", e);
        }
        
        // Convert map to sorted list
        List<Map<String, Object>> timeline = new ArrayList<>();
        timelineMap.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> {
                Map<String, Object> timePoint = new HashMap<>();
                timePoint.put("time_period", entry.getKey());
                timePoint.put("total_count", entry.getValue().get("total"));
                timePoint.put("success_count", entry.getValue().get("success"));
                timePoint.put("error_count", entry.getValue().get("error"));
                timeline.add(timePoint);
            });
        
        return timeline;
    }
    
    /**
     * Extracts the Date header from HTTP response headers.
     */
    private String extractDateFromHeaders(String responseHeaders) {
        if (responseHeaders == null || responseHeaders.isEmpty()) {
            return null;
        }
        
        // Remove array brackets if present
        String headers = responseHeaders;
        if (headers.startsWith("[") && headers.endsWith("]")) {
            headers = headers.substring(1, headers.length() - 1);
        }
        
        // Look for Date: header using regex to handle the comma-separated format properly
        java.util.regex.Pattern datePattern = java.util.regex.Pattern.compile("Date:\\s*([^,]+(?:,\\s*\\d{2}\\s+\\w{3}\\s+\\d{4}\\s+[^,]+GMT))", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = datePattern.matcher(headers);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        
        return null;
    }
    
    /**
     * Parses HTTP date format to LocalDateTime.
     */
    private java.time.LocalDateTime parseHttpDate(String httpDate) {
        try {
            // HTTP dates are in GMT/UTC format like "Fri, 30 May 2025 19:32:36 GMT"
            java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz", java.util.Locale.ENGLISH);
            java.time.ZonedDateTime zonedDateTime = java.time.ZonedDateTime.parse(httpDate, formatter);
            return zonedDateTime.toLocalDateTime();
        } catch (Exception e) {
            logger.debug("Failed to parse HTTP date: {}", httpDate);
            return null;
        }
    }
    
    /**
     * Formats a date string according to the specified interval.
     */
    private String formatDateForInterval(String httpDate, String interval) {
        try {
            java.time.LocalDateTime dateTime = parseHttpDate(httpDate);
            if (dateTime == null) return null;
            
            switch (interval.toLowerCase()) {
                case "minute":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
                case "hour":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH"));
                case "day":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                default:
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH"));
            }
        } catch (Exception e) {
            logger.debug("Failed to format date for interval: {}", httpDate);
            return null;
        }
    }
    
    /**
     * Gets traffic data formatted for HAR export.
     * 
     * @param searchParams Search parameters for filtering
     * @return List of traffic records with full request/response data
     */
    public List<Map<String, Object>> getTrafficForHarExport(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> harEntries = new ArrayList<>();
        
        try {
            StringBuilder sql = new StringBuilder(
                "SELECT id, timestamp, method, url, host, headers, body, " +
                "status_code, response_headers, response_body " +
                "FROM proxy_traffic WHERE 1=1"
            );
            
            List<Object> parameters = new ArrayList<>();
            
            // Apply search filters
            // Handle host filtering (single or multiple)
            boolean caseInsensitive = searchParams.containsKey("case_insensitive") && 
                                    Boolean.parseBoolean(searchParams.get("case_insensitive"));
            addHostFiltering(sql, parameters, searchParams, caseInsensitive);
            if (searchParams.containsKey("method")) {
                sql.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                sql.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            if (searchParams.containsKey("start_time")) {
                sql.append(" AND timestamp >= ?");
                parameters.add(parseTimestamp(searchParams.get("start_time")));
            }
            if (searchParams.containsKey("end_time")) {
                sql.append(" AND timestamp <= ?");
                parameters.add(parseTimestamp(searchParams.get("end_time")));
            }
            
            // Only include requests that have responses for valid HAR
            sql.append(" AND status_code IS NOT NULL");
            sql.append(" ORDER BY timestamp");
            
            // Apply limit if specified
            if (searchParams.containsKey("limit")) {
                sql.append(" LIMIT ?");
                parameters.add(Integer.parseInt(searchParams.get("limit")));
            }
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("id", rs.getLong("id"));
                    entry.put("timestamp", rs.getTimestamp("timestamp"));
                    entry.put("method", rs.getString("method"));
                    entry.put("url", rs.getString("url"));
                    entry.put("host", rs.getString("host"));
                    entry.put("headers", rs.getString("headers"));
                    entry.put("body", rs.getString("body"));
                    entry.put("status_code", rs.getInt("status_code"));
                    entry.put("response_headers", rs.getString("response_headers"));
                    entry.put("response_body", rs.getString("response_body"));
                    harEntries.add(entry);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic for HAR export", e);
        }
        
        return harEntries;
    }
    
    /**
     * Imports existing proxy history from the current Burp project into the database.
     * This method extracts all proxy history items and stores them with IMPORTED source.
     * 
     * @param api The MontoyaApi instance to access proxy history
     * @param sessionTag Session tag to use for imported data
     * @return Number of records imported (not including duplicates)
     */
    public int importExistingProxyHistory(burp.api.montoya.MontoyaApi api, String sessionTag) {
        if (shutdown.get() || connection == null) {
            logger.warn("Cannot import proxy history - database not available");
            return 0;
        }

        logger.info("Starting COMPREHENSIVE MULTI-PASS import of existing proxy history...");
        
        // OPTIMIZED STRATEGY: Faster startup with smarter import
        // Reduced passes and shorter delays for better performance on large datasets
        
        java.util.Set<String> seenContentHashes = new java.util.HashSet<>();
        int totalImported = 0;
        int totalErrors = 0;
        int pass = 1;
        
        try {
            // OPTIMIZED MULTI-PASS IMPORT (reduced for faster startup)
            while (pass <= 3) { // Reduced from 5 to 3 passes
                logger.info("📋 IMPORT PASS {}/3: Calling api.proxy().history()...", pass);
                
                java.util.List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                logger.info("📋 Pass {} returned {} proxy history items", pass, proxyHistory.size());
                
                if (proxyHistory.isEmpty()) {
                    if (pass == 1) {
                        logger.error("NO PROXY HISTORY ACCESSIBLE on first pass - This indicates:");
                        logger.error("   1. Burp API buffer limitations (older history not accessible)");
                        logger.error("   2. Scope filtering excluding all historical data");
                        logger.error("   3. Project state issue preventing API access");
                        logger.error("   4. Extension loaded before proxy history populated API buffer");
                        logger.error("RECOMMENDATION: Check Burp's Proxy > HTTP History tab to verify data exists");
                        return 0;
                    } else {
                        logger.info("Pass {} returned no new data - import may be complete", pass);
                        break;
                    }
                }
                
                // Process this pass's data with batching for better performance
                int passImported = 0;
                int passDuplicates = 0;
                int passErrors = 0;
                
                // Batch processing for large datasets
                List<Map<String, Object>> batchBuffer = new ArrayList<>();
                final int BATCH_SIZE = 100; // Process in batches of 100
                
                // Check for oldest and newest timestamps in this batch
                long oldestTimestamp = Long.MAX_VALUE;
                long newestTimestamp = 0;
                
                for (burp.api.montoya.proxy.ProxyHttpRequestResponse item : proxyHistory) {
                    try {
                        // Extract request data for deduplication
                        burp.api.montoya.http.message.requests.HttpRequest request = item.finalRequest();
                        burp.api.montoya.http.message.responses.HttpResponse response = item.originalResponse();
                        
                        String method = request.method();
                        String url = request.url();
                        String host = request.httpService().host();
                        String requestHeaders = request.headers().toString();
                        String requestBody = request.bodyToString();
                        
                        // Extract response data (if available)
                        String responseHeaders = null;
                        String responseBody = null;
                        Integer statusCode = null;
                        
                        if (response != null) {
                            statusCode = (int) response.statusCode();
                            responseHeaders = response.headers().toString();
                            responseBody = response.bodyToString();
                        }
                        
                        // Generate content hash for deduplication across passes
                        String contentHash = generateContentHash(method, url, requestHeaders, requestBody, responseHeaders, responseBody);
                        
                        if (seenContentHashes.contains(contentHash)) {
                            passDuplicates++;
                            continue; // Skip duplicate from previous pass
                        }
                        seenContentHashes.add(contentHash);
                        
                        // Track timestamp range for this pass
                        // Note: Burp doesn't expose request timestamp directly, so we use current time
                        // This is a limitation of Burp's API
                        long currentTime = System.currentTimeMillis();
                        oldestTimestamp = Math.min(oldestTimestamp, currentTime);
                        newestTimestamp = Math.max(newestTimestamp, currentTime);
                        
                        // Add to batch buffer instead of immediate storage
                        Map<String, Object> record = new HashMap<>();
                        record.put("method", method);
                        record.put("url", url);
                        record.put("host", host);
                        record.put("requestHeaders", requestHeaders);
                        record.put("requestBody", requestBody);
                        record.put("responseHeaders", responseHeaders);
                        record.put("responseBody", responseBody);
                        record.put("statusCode", statusCode);
                        record.put("sessionTag", sessionTag + "_imported_pass" + pass);
                        
                        batchBuffer.add(record);
                        
                        // Process batch when full
                        if (batchBuffer.size() >= BATCH_SIZE) {
                            int batchImported = processBatch(batchBuffer, TrafficSource.IMPORTED);
                            passImported += batchImported;
                            totalImported += batchImported;
                            batchBuffer.clear();
                            
                            if (totalImported % 500 == 0) {
                                logger.info("📥 Imported {} total records across {} passes...", totalImported, pass);
                            }
                        }
                        
                    } catch (Exception e) {
                        passErrors++;
                        totalErrors++;
                        if (totalErrors <= 10) {
                            logger.warn("Error importing proxy history item in pass {}: {}", pass, e.getMessage());
                        }
                    }
                }
                
                // Process remaining batch records
                if (!batchBuffer.isEmpty()) {
                    int finalBatchImported = processBatch(batchBuffer, TrafficSource.IMPORTED);
                    passImported += finalBatchImported;
                    totalImported += finalBatchImported;
                    batchBuffer.clear();
                }
                
                logger.info("📋 Pass {} completed: {} new records, {} duplicates, {} errors", 
                           pass, passImported, passDuplicates, passErrors);
                
                // If we got very few new records on this pass, the API buffer may be exhausted
                if (passImported < 10 && pass > 1) {
                    logger.info("Low new record count on pass {} - API buffer likely exhausted", pass);
                    break;
                }
                
                // Optimized delays for faster startup (reduced from progressive 10s, 20s, 30s)
                if (pass < 3) {
                    int delaySeconds = pass == 1 ? 3 : 5; // Fast delays: 3s, 5s
                    logger.info("Waiting {} seconds before pass {}...", delaySeconds, pass + 1);
                    Thread.sleep(delaySeconds * 1000);
                }
                
                pass++;
            }
            
            // Final assessment
            logger.info("MULTI-PASS IMPORT SUMMARY:");
            logger.info("   Total passes attempted: {}", pass - 1);
            logger.info("   📥 Total records imported: {}", totalImported);
            logger.info("   Total duplicates skipped: {}", seenContentHashes.size() - totalImported);
            logger.info("   Total errors: {}", totalErrors);
            
            if (totalImported < 1000) {
                logger.warn("LOW TOTAL IMPORT COUNT: {} - This suggests Burp API limitations", totalImported);
                logger.warn("   Older data you see in Burp's UI may not be accessible via api.proxy().history()");
                logger.warn("   This is a known limitation of Burp's proxy history API buffer");
            } else {
                logger.info("Successfully imported substantial proxy history: {} records", totalImported);
            }
            
            // Log the import operation
            try {
                String logSql = "INSERT INTO deduplication_log " +
                              "(operation_type, records_processed, duplicates_found, duplicates_removed, session_tag) " +
                              "VALUES (?, ?, ?, ?, ?)";
                
                // Isolate the INSERT on a leased write connection (see storeRequest / #37).
                try (WriteLease lease = new WriteLease();
                     PreparedStatement logStmt = lease.conn.prepareStatement(logSql)) {
                    logStmt.setString(1, "PROXY_HISTORY_MULTIPASS_IMPORT");
                    logStmt.setInt(2, seenContentHashes.size());
                    logStmt.setInt(3, seenContentHashes.size() - totalImported);
                    logStmt.setInt(4, 0); // We skip duplicates, don't remove them
                    logStmt.setString(5, sessionTag + "_imported_multipass");
                    logStmt.executeUpdate();
                }
            } catch (SQLException e) {
                logger.debug("Failed to log import operation", e);
            }
            
            return totalImported;
            
        } catch (Exception e) {
            logger.error("Failed to import existing proxy history", e);
            return 0;
        }
    }
    
    /**
     * Processes a batch of proxy records for efficient database insertion.
     * 
     * @param batch List of proxy records to process
     * @param source Traffic source for the records
     * @return Number of records successfully imported
     */
    private int processBatch(List<Map<String, Object>> batch, TrafficSource source) {
        if (batch.isEmpty()) {
            return 0;
        }
        
        int imported = 0;
        // Isolate the batch INSERT on a leased write connection. The lease closes
        // (returning a pooled connection, or releasing the degraded-mode lock)
        // without ever physically closing the shared connection. (#37)
        try (WriteLease lease = new WriteLease()) {
            Connection conn = lease.conn;
            // Use prepared statement for batch insert
            String sql = "INSERT INTO proxy_traffic (method, url, host, headers, body, " +
                        "response_headers, response_body, status_code, session_tag, traffic_source, " +
                        "timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                for (Map<String, Object> record : batch) {
                    stmt.setString(1, (String) record.get("method"));
                    stmt.setString(2, (String) record.get("url"));
                    stmt.setString(3, (String) record.get("host"));
                    stmt.setString(4, (String) record.get("requestHeaders"));
                    stmt.setString(5, (String) record.get("requestBody"));
                    stmt.setString(6, (String) record.get("responseHeaders"));
                    stmt.setString(7, (String) record.get("responseBody"));
                    stmt.setObject(8, record.get("statusCode"));
                    stmt.setString(9, (String) record.get("sessionTag"));
                    stmt.setString(10, source.toString());
                    stmt.setTimestamp(11, new Timestamp(System.currentTimeMillis()));
                    
                    stmt.addBatch();
                }
                
                int[] results = stmt.executeBatch();
                for (int result : results) {
                    if (result > 0) {
                        imported++;
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Error processing batch of {} records", batch.size(), e);
        }

        return imported;
    }
    
    /**
     * Gets orphaned requests (requests without responses) for debugging.
     * 
     * @param limit Maximum number of orphaned requests to return
     * @return List of orphaned request records
     */
    public List<Map<String, Object>> getOrphanedRequests(int limit) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> orphanedRequests = new ArrayList<>();
        
        String sql = "SELECT id, timestamp, method, url, host, session_tag " +
                    "FROM proxy_traffic " +
                    "WHERE status_code IS NULL " +
                    "ORDER BY timestamp DESC " +
                    "LIMIT ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, limit);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    orphanedRequests.add(record);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get orphaned requests", e);
        }
        
        return orphanedRequests;
    }
    
    /**
     * Cache for scope checking results to avoid repeated API calls.
     * Key: URL, Value: {inScope: boolean, lastChecked: timestamp}
     */
    public void cacheScopeResult(String url, boolean inScope) {
        String sql = "INSERT OR REPLACE INTO scope_cache (url, in_scope, last_checked) VALUES (?, ?, ?)";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, url);
            stmt.setBoolean(2, inScope);
            stmt.setTimestamp(3, Timestamp.valueOf(LocalDateTime.now()));
            stmt.executeUpdate();
            
            logger.debug("Cached scope result for {}: {}", url, inScope);
            
        } catch (SQLException e) {
            logger.error("Failed to cache scope result", e);
        }
    }
    
    /**
     * Gets cached scope result if available and not stale (within 5 minutes).
     * 
     * @param url The URL to check
     * @return Map with "inScope" boolean and "cached" boolean, or null if not cached/stale
     */
    public Map<String, Object> getCachedScopeResult(String url) {
        String sql = "SELECT in_scope, last_checked FROM scope_cache WHERE url = ? AND last_checked > ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, url);
            // Cache valid for 5 minutes
            stmt.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now().minusMinutes(5)));
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("inScope", rs.getBoolean("in_scope"));
                    result.put("cached", true);
                    result.put("lastChecked", rs.getTimestamp("last_checked"));
                    return result;
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get cached scope result", e);
        }
        
        return null;
    }
    
    /**
     * Bulk scope checking optimized for database queries.
     * Returns URLs with their scope status from cache or fresh API calls.
     */
    public Map<String, Boolean> bulkScopeCheck(List<String> urls, burp.api.montoya.MontoyaApi api) {
        Map<String, Boolean> results = new HashMap<>();
        List<String> uncachedUrls = new ArrayList<>();
        
        // First, check cache for all URLs
        for (String url : urls) {
            Map<String, Object> cached = getCachedScopeResult(url);
            if (cached != null) {
                results.put(url, (Boolean) cached.get("inScope"));
            } else {
                uncachedUrls.add(url);
            }
        }
        
        // Check uncached URLs via API and cache results
        for (String url : uncachedUrls) {
            try {
                boolean inScope = api.scope().isInScope(url);
                results.put(url, inScope);
                cacheScopeResult(url, inScope);
            } catch (Exception e) {
                logger.warn("Failed to check scope for URL {}: {}", url, e.getMessage());
                results.put(url, false); // Default to false on error
            }
        }
        
        logger.debug("Bulk scope check: {} cached, {} API calls", results.size() - uncachedUrls.size(), uncachedUrls.size());
        return results;
    }
    
    /**
     * Generate a query plan analysis for performance optimization
     */
    public Map<String, Object> analyzeQueryPerformance(String query, Map<String, Object> params) {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> analysis = new HashMap<>();
        
        try {
            // Get EXPLAIN QUERY PLAN
            String explainQuery = "EXPLAIN QUERY PLAN " + query;
            
            try (PreparedStatement stmt = getConnection().prepareStatement(explainQuery)) {
                // Set parameters if provided
                if (params != null) {
                    int paramIndex = 1;
                    for (Object param : params.values()) {
                        stmt.setObject(paramIndex++, param);
                    }
                }
                
                List<Map<String, Object>> queryPlan = new ArrayList<>();
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> planStep = new HashMap<>();
                        planStep.put("selectid", rs.getInt("selectid"));
                        planStep.put("order", rs.getInt("order"));
                        planStep.put("from", rs.getInt("from"));
                        planStep.put("detail", rs.getString("detail"));
                        queryPlan.add(planStep);
                    }
                }
                
                analysis.put("query_plan", queryPlan);
                
                // Analyze for potential performance issues
                List<String> recommendations = new ArrayList<>();
                for (Map<String, Object> step : queryPlan) {
                    String detail = (String) step.get("detail");
                    if (detail.contains("SCAN TABLE")) {
                        recommendations.add("Consider adding an index to avoid table scan: " + detail);
                    }
                    if (detail.contains("TEMP B-TREE")) {
                        recommendations.add("Query requires temporary sorting, consider index optimization: " + detail);
                    }
                    if (detail.contains("USING INDEX")) {
                        recommendations.add("Using index efficiently: " + detail);
                    }
                }
                
                analysis.put("recommendations", recommendations);
                analysis.put("timestamp", System.currentTimeMillis());
                
            }
            
        } catch (SQLException e) {
            logger.error("Failed to analyze query performance", e);
            analysis.put("error", e.getMessage());
        }
        
        return analysis;
    }
    
    /**
     * Get comprehensive database performance metrics
     */
    public Map<String, Object> getDatabasePerformanceMetrics() {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> metrics = new HashMap<>();
        
        try (Statement stmt = getConnection().createStatement()) {
            // Basic database info
            Map<String, Object> dbInfo = new HashMap<>();
            
            try (ResultSet rs = stmt.executeQuery("PRAGMA database_list")) {
                while (rs.next()) {
                    dbInfo.put("name", rs.getString("name"));
                    dbInfo.put("file", rs.getString("file"));
                }
            }
            
            // Page and cache statistics
            Map<String, Object> cacheStats = new HashMap<>();
            cacheStats.put("page_count", getPragmaValue(stmt, "PRAGMA page_count"));
            cacheStats.put("freelist_count", getPragmaValue(stmt, "PRAGMA freelist_count"));
            cacheStats.put("cache_size", getPragmaValue(stmt, "PRAGMA cache_size"));
            cacheStats.put("cache_spill", getPragmaValue(stmt, "PRAGMA cache_spill"));
            
            // Index usage
            Map<String, Object> indexStats = new HashMap<>();
            try (ResultSet rs = stmt.executeQuery("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")) {
                List<Map<String, Object>> indexes = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> index = new HashMap<>();
                    index.put("name", rs.getString("name"));
                    index.put("sql", rs.getString("sql"));
                    indexes.add(index);
                }
                indexStats.put("indexes", indexes);
                indexStats.put("count", indexes.size());
            }
            
            // Table statistics
            Map<String, Object> tableStats = new HashMap<>();
            String[] tables = {"traffic_meta", "traffic_requests", "traffic_responses", "proxy_traffic"};
            for (String table : tables) {
                try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + table)) {
                    if (rs.next()) {
                        tableStats.put(table + "_count", rs.getInt(1));
                    }
                } catch (SQLException e) {
                    tableStats.put(table + "_count", "N/A");
                }
            }
            
            metrics.put("database_info", dbInfo);
            metrics.put("cache_statistics", cacheStats);
            metrics.put("index_statistics", indexStats);
            metrics.put("table_statistics", tableStats);
            metrics.put("schema_version", schemaManager.getSchemaVersion(connection));
            metrics.put("normalized_schema_available", schemaManager.isNormalizedSchemaAvailable(connection));
            metrics.put("fts5_available", schemaManager.isFTS5SearchAvailable(connection));
            metrics.put("collected_at", System.currentTimeMillis());
            
        } catch (SQLException e) {
            logger.error("Failed to collect database performance metrics", e);
            metrics.put("error", e.getMessage());
        }
        
        return metrics;
    }
    
    private String getPragmaValue(Statement stmt, String pragma) {
        try (ResultSet rs = stmt.executeQuery(pragma)) {
            if (rs.next()) {
                return rs.getString(1);
            }
        } catch (SQLException e) {
            logger.debug("Failed to get pragma value for: {}", pragma);
        }
        return "unknown";
    }
    
    //=================================================================================
    // Enhanced Metadata and Tagging Methods
    //=================================================================================
    
    /**
     * Update tags for a specific traffic record.
     * 
     * @param requestId The traffic_meta.id to update
     * @param tags Comma-separated tags or JSON array
     * @return true if update was successful
     */
    /**
     * Attach analyst tags to the request a {@code proxy_traffic.id} names.
     *
     * <p>Keyed on {@code traffic_meta.proxy_traffic_id}, the exact link to the
     * public id space (schema v14), not on {@code traffic_meta.id} — those are
     * independent counters written by different loggers, so keying on the raw id
     * labelled whichever request the normalized path happened to assign it (#21).
     * Call {@link #ensureTrafficMetaForProxyId(long)} first so a linked row
     * exists.
     *
     * @param requestId The proxy_traffic.id supplied by the client
     * @param tags Comma-joined analyst labels
     * @return true if a linked metadata row was updated
     */
    public boolean updateTrafficTags(long requestId, String tags) {
        String sql = "UPDATE traffic_meta SET tags = ? WHERE proxy_traffic_id = ?";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, tags);
            stmt.setLong(2, requestId);

            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Updated tags for request ID {}: {}", requestId, tags);
                return true;
            } else {
                logger.warn("No linked metadata row for proxy_traffic id: {}", requestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to update tags for request ID {}: {}", requestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Update comment for a specific traffic record.
     * 
     * @param requestId The traffic_meta.id to update
     * @param comment Analyst comment/note
     * @return true if update was successful
     */
    /** Whether the public id space holds a {@code proxy_traffic} row with this id. */
    public boolean proxyTrafficExists(long requestId) {
        String sql = "SELECT 1 FROM proxy_traffic WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, requestId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            logger.error("Error checking if proxy_traffic row exists: {}", e.getMessage());
            return false;
        }
    }

    /**
     * The {@code traffic_meta.id} linked to {@code proxyTrafficId}, or {@code -1}
     * if no metadata row carries that link yet.
     */
    private long findTrafficMetaIdByProxyId(long proxyTrafficId) throws SQLException {
        String sql = "SELECT id FROM traffic_meta WHERE proxy_traffic_id = ? ORDER BY id LIMIT 1";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, proxyTrafficId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? rs.getLong(1) : -1L;
            }
        }
    }

    /**
     * Guarantee a {@code traffic_meta} row linked to {@code proxyTrafficId} exists,
     * so an annotation keyed on {@code proxy_traffic_id} has a row to land on.
     *
     * <p>The normalized logger records the exact {@code proxy_traffic.id} it
     * captured against (schema v14, #28); when that path skipped the request
     * (proxy-only capture, content-hash dedup, or a pre-v14 row the backfill left
     * unlinked) no linked row exists, so this copies the {@code proxy_traffic} row
     * into a fresh, linked metadata row. The id autoincrements rather than being
     * forced to equal {@code proxyTrafficId} — copying the id is exactly what
     * collided with the normalized counter and mislabeled evidence (#21).
     *
     * @param proxyTrafficId The proxy_traffic.id supplied by the client
     * @return the linked {@code traffic_meta.id}, or {@code -1} if no
     *     {@code proxy_traffic} row holds this id (nothing to copy)
     */
    public long ensureTrafficMetaForProxyId(long proxyTrafficId) {
        try {
            long existing = findTrafficMetaIdByProxyId(proxyTrafficId);
            if (existing > 0) {
                return existing;
            }

            String insertSql =
                "INSERT INTO traffic_meta (timestamp, method, url, host, session_tag, tool_source, content_hash, proxy_traffic_id) "
              + "SELECT timestamp, method, url, host, COALESCE(session_tag, ''), 'IMPORTED', '', id "
              + "FROM proxy_traffic WHERE id = ?";
            // Isolate the INSERT on a leased write connection (see storeRequest / #37).
            try (WriteLease lease = new WriteLease();
                 PreparedStatement stmt = lease.conn.prepareStatement(insertSql)) {
                stmt.setLong(1, proxyTrafficId);
                if (stmt.executeUpdate() == 0) {
                    return -1L; // No proxy_traffic row to copy.
                }
            }
            logger.info("Linked traffic_meta row created for proxy_traffic id {}", proxyTrafficId);
            return findTrafficMetaIdByProxyId(proxyTrafficId);
        } catch (SQLException e) {
            logger.error("Failed to ensure traffic_meta row for proxy_traffic id {}: {}",
                         proxyTrafficId, e.getMessage());
            return -1L;
        }
    }

    /**
     * Attach an analyst comment to the request a {@code proxy_traffic.id} names.
     * Keyed on {@code proxy_traffic_id} for the same reason as
     * {@link #updateTrafficTags(long, String)} (#21).
     *
     * @param requestId The proxy_traffic.id supplied by the client
     * @param comment Analyst comment/note
     * @return true if a linked metadata row was updated
     */
    public boolean updateTrafficComment(long requestId, String comment) {
        String sql = "UPDATE traffic_meta SET comment = ? WHERE proxy_traffic_id = ?";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, comment);
            stmt.setLong(2, requestId);

            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Updated comment for request ID {}: {}", requestId, comment);
                return true;
            } else {
                logger.warn("No linked metadata row for proxy_traffic id: {}", requestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to update comment for request ID {}: {}", requestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Set replay lineage for a traffic record.
     * 
     * @param replayedRequestId The ID of the replayed request
     * @param originalRequestId The ID of the original request it was replayed from
     * @return true if update was successful
     */
    public boolean setReplayLineage(long replayedRequestId, long originalRequestId) {
        String sql = "UPDATE traffic_meta SET replayed_from = ? WHERE id = ?";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setLong(1, originalRequestId);
            stmt.setLong(2, replayedRequestId);
            
            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Set replay lineage: {} replayed from {}", replayedRequestId, originalRequestId);
                return true;
            } else {
                logger.warn("No record found for replayed request ID: {}", replayedRequestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to set replay lineage for request ID {}: {}", replayedRequestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Get all traffic records that were replayed from a specific original request.
     * 
     * @param originalRequestId The original request ID
     * @return List of replayed traffic records
     */
    public List<Map<String, Object>> getReplayedFrom(long originalRequestId) {
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tm.replayed_from = ? " +
                    "ORDER BY tm.timestamp DESC";

        List<Map<String, Object>> results = new ArrayList<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, originalRequestId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    // `id` carries the public proxy_traffic.id when the row is linked,
                    // matching every other read endpoint; the internal id stays visible
                    // as traffic_meta_id (#21).
                    long resolvedId = rs.getLong("proxy_traffic_id");
                    boolean replayable = !rs.wasNull();
                    record.put("id", replayable ? resolvedId : null);
                    record.put("traffic_meta_id", rs.getLong("id"));
                    record.put("replayable", replayable);
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get replayed requests for original ID {}: {}", originalRequestId, e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Search request bodies using FTS5 if available.
     * 
     * @param searchQuery The search query
     * @param limit Maximum results to return
     * @param offset Results to skip for pagination
     * @return List of matching traffic records
     */
    public List<Map<String, Object>> searchRequestBodies(String searchQuery, int limit, int offset) {
        // Check if request FTS is available
        try {
            if (!schemaManager.isRequestFTS5SearchAvailable(connection)) {
                logger.warn("Request FTS5 not available, falling back to LIKE search");
                return searchRequestBodiesLike(searchQuery, limit, offset);
            }
        } catch (SQLException e) {
            logger.warn("Error checking request FTS5 availability, falling back to LIKE search: {}", e.getMessage());
            return searchRequestBodiesLike(searchQuery, limit, offset);
        }
        
        // Resolve each hit back to the public proxy_traffic.id space (#28) via the
        // exact link recorded at capture time (schema v14). A NULL means the hit
        // has no replayable counterpart (Repeater traffic, or a pre-v14 row whose
        // content_hash mapping was ambiguous and left unlinked by the backfill).
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body, " +
                    "tm.proxy_traffic_id AS proxy_traffic_id " +
                    "FROM request_index ri " +
                    "JOIN traffic_meta tm ON ri.traffic_meta_id = tm.id " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE request_index MATCH ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, searchQuery);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    // `id` carries the public proxy_traffic.id so a hit can be
                    // handed straight to /proxy/replay; `traffic_meta_id` keeps the
                    // internal id visible, and `replayable` flags a hit that has no
                    // proxy_traffic counterpart (reconstruct via /proxy/send) (#28).
                    long resolvedId = rs.getLong("proxy_traffic_id");
                    boolean replayable = !rs.wasNull();
                    record.put("id", replayable ? resolvedId : null);
                    record.put("traffic_meta_id", rs.getLong("id"));
                    record.put("replayable", replayable);
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search request bodies with FTS5: {}", e.getMessage());
            return searchRequestBodiesLike(searchQuery, limit, offset);
        }
        
        return results;
    }
    
    /**
     * Fallback search for request bodies using LIKE.
     */
    private List<Map<String, Object>> searchRequestBodiesLike(String searchQuery, int limit, int offset) {
        // Same public-id resolution as the FTS path (#28).
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body, " +
                    "tm.proxy_traffic_id AS proxy_traffic_id " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tr.body LIKE ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, "%" + searchQuery + "%");
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    // Same public-id resolution as the FTS path (#28).
                    long resolvedId = rs.getLong("proxy_traffic_id");
                    boolean replayable = !rs.wasNull();
                    record.put("id", replayable ? resolvedId : null);
                    record.put("traffic_meta_id", rs.getLong("id"));
                    record.put("replayable", replayable);
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search request bodies with LIKE: {}", e.getMessage());
        }

        return results;
    }

    /**
     * Search response bodies (and response headers) using FTS5 if available.
     *
     * <p>Mirrors {@link #searchRequestBodies} but matches the {@code response_index}
     * FTS5 table. This is the read side the trigger-maintained {@code response_index}
     * had been missing a consumer for (#12): the index was populated for every
     * normalized capture but no endpoint queried it, so response-body search
     * silently returned nothing. Hits resolve back to the public
     * {@code proxy_traffic.id} space the same way the request-body search does (#28).
     *
     * @param searchQuery FTS5 MATCH expression (e.g. a resource id)
     * @param limit Maximum results to return
     * @param offset Results to skip for pagination
     * @return List of matching traffic records
     */
    public List<Map<String, Object>> searchResponseBodies(String searchQuery, int limit, int offset) {
        // Check if response FTS is available (response_index).
        try {
            if (!schemaManager.isFTS5SearchAvailable(connection)) {
                logger.warn("Response FTS5 not available, falling back to LIKE search");
                return searchResponseBodiesLike(searchQuery, limit, offset);
            }
        } catch (SQLException e) {
            logger.warn("Error checking response FTS5 availability, falling back to LIKE search: {}", e.getMessage());
            return searchResponseBodiesLike(searchQuery, limit, offset);
        }

        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body, " +
                    "tm.proxy_traffic_id AS proxy_traffic_id " +
                    "FROM response_index ridx " +
                    "JOIN traffic_meta tm ON ridx.traffic_meta_id = tm.id " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE response_index MATCH ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";

        List<Map<String, Object>> results = new ArrayList<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, searchQuery);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    results.add(mapBodySearchRow(rs));
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search response bodies with FTS5: {}", e.getMessage());
            return searchResponseBodiesLike(searchQuery, limit, offset);
        }

        return results;
    }

    /**
     * Fallback search for response bodies using LIKE.
     */
    private List<Map<String, Object>> searchResponseBodiesLike(String searchQuery, int limit, int offset) {
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body, " +
                    "tm.proxy_traffic_id AS proxy_traffic_id " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tres.body LIKE ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";

        List<Map<String, Object>> results = new ArrayList<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, "%" + searchQuery + "%");
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    results.add(mapBodySearchRow(rs));
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search response bodies with LIKE: {}", e.getMessage());
        }

        return results;
    }

    /**
     * Build the result record shared by the request/response body search paths,
     * resolving each hit back to the public {@code proxy_traffic.id} space (#28).
     * A NULL {@code proxy_traffic_id} means the hit has no replayable counterpart
     * (Repeater traffic, or a pre-v14 row the backfill left unlinked); {@code id}
     * is then null and callers reconstruct via {@code /proxy/send}.
     */
    private Map<String, Object> mapBodySearchRow(ResultSet rs) throws SQLException {
        Map<String, Object> record = new HashMap<>();
        long resolvedId = rs.getLong("proxy_traffic_id");
        boolean replayable = !rs.wasNull();
        record.put("id", replayable ? resolvedId : null);
        record.put("traffic_meta_id", rs.getLong("id"));
        record.put("replayable", replayable);
        record.put("timestamp", rs.getTimestamp("timestamp"));
        record.put("method", rs.getString("method"));
        record.put("url", rs.getString("url"));
        record.put("host", rs.getString("host"));
        record.put("session_tag", rs.getString("session_tag"));
        record.put("tool_source", rs.getString("tool_source"));
        record.put("tags", rs.getString("tags"));
        record.put("comment", rs.getString("comment"));
        record.put("replayed_from", rs.getLong("replayed_from"));
        record.put("request_headers", rs.getString("request_headers"));
        record.put("request_body", rs.getString("request_body"));
        record.put("status_code", rs.getObject("status_code"));
        record.put("response_headers", rs.getString("response_headers"));
        record.put("response_body", rs.getString("response_body"));
        return record;
    }

    /**
     * Save a query preset for later reuse.
     * 
     * @param name Unique name for the query
     * @param description Optional description
     * @param queryParamsJson JSON string containing query parameters
     * @param sessionTag Session tag for organization
     * @return The ID of the saved query, or -1 if failed
     */
    public long saveQuery(String name, String description, String queryParamsJson, String sessionTag) {
        logger.info("Attempting to save query: name='{}', description='{}', sessionTag='{}'", name, description, sessionTag);
        
        // Add timestamp to make name unique for test queries
        if (name.startsWith("test_")) {
            name = name + "_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
        }
        
        // Check schema availability like listSavedQueries does
        try {
            boolean available = schemaManager.isSavedQueriesAvailable(connection);
            logger.info("Schema check result: saved_queries available = {}", available);
            if (!available) {
                logger.error("Saved queries feature not available - but table exists!");
                // Continue anyway since we know table exists
            }
        } catch (SQLException e) {
            logger.error("Schema availability check failed: {}", e.getMessage(), e);
            // Continue anyway
        }
        
        String sql = "INSERT INTO saved_queries (name, description, query_params, session_tag) VALUES (?, ?, ?, ?)";
        
        logger.info("About to execute SQL: {} with name='{}', description='{}', queryParamsJson='{}', sessionTag='{}'", 
                   sql, name, description, queryParamsJson, sessionTag);
        
        // Isolate INSERT + last_insert_rowid() on a leased write connection so the
        // id read is this insert's own and no shared autocommit state is mutated
        // (see storeRequest / #37). A pooled write connection is already in
        // autocommit mode; the explicit set keeps the degraded-fallback path
        // (shared connection) in the same mode this method has always assumed.
        try {
            try (WriteLease lease = new WriteLease()) {
                Connection conn = lease.conn;
                conn.setAutoCommit(true);

                // First insert the record
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setString(1, name);
                    stmt.setString(2, description);
                    stmt.setString(3, queryParamsJson);
                    stmt.setString(4, sessionTag);

                    logger.info("Executing prepared statement...");

                    int rowsInserted = stmt.executeUpdate();
                    logger.info("Rows inserted: {}", rowsInserted);

                    if (rowsInserted > 0) {
                        // Get the last inserted row ID using SQLite specific function
                        try (PreparedStatement idStmt = conn.prepareStatement("SELECT last_insert_rowid()")) {
                            try (ResultSet rs = idStmt.executeQuery()) {
                                if (rs.next()) {
                                    long queryId = rs.getLong(1);
                                    logger.info("Saved query '{}' with ID: {}", name, queryId);
                                    return queryId;
                                }
                            }
                        }
                    } else {
                        logger.warn("No rows inserted for query '{}'", name);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to save query '{}': {} (SQL State: {}, Error Code: {})", 
                        name, e.getMessage(), e.getSQLState(), e.getErrorCode());
            logger.error("Full SQL Exception:", e);
            // Check if it's a unique constraint violation
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.info("Query name '{}' already exists, trying with new timestamp", name);
                // Try again with a more unique name
                String newName = name + "_retry_" + System.currentTimeMillis();
                return saveQuery(newName, description, queryParamsJson, sessionTag);
            }
        } catch (Exception e) {
            logger.error("Unexpected error saving query '{}': {}", name, e.getMessage(), e);
        }
        
        return -1;
    }
    
    /**
     * Load a saved query by name.
     * 
     * @param name The name of the saved query
     * @return Map containing query details, or null if not found
     */
    public Map<String, Object> loadQuery(String name) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return null;
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return null;
        }
        
        String sql = "SELECT * FROM saved_queries WHERE name = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, name);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> query = new HashMap<>();
                    query.put("id", rs.getLong("id"));
                    query.put("name", rs.getString("name"));
                    query.put("description", rs.getString("description"));
                    query.put("query_params", rs.getString("query_params"));
                    query.put("created_at", rs.getTimestamp("created_at"));
                    query.put("updated_at", rs.getTimestamp("updated_at"));
                    query.put("session_tag", rs.getString("session_tag"));
                    return query;
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to load query '{}': {}", name, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * List all saved queries, optionally filtered by session tag.
     * 
     * @param sessionTag Optional session tag filter (null for all)
     * @return List of saved queries
     */
    public List<Map<String, Object>> listSavedQueries(String sessionTag) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return new ArrayList<>();
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return new ArrayList<>();
        }
        
        String sql = "SELECT * FROM saved_queries";
        if (sessionTag != null) {
            sql += " WHERE session_tag = ?";
        }
        sql += " ORDER BY updated_at DESC";
        
        List<Map<String, Object>> queries = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            if (sessionTag != null) {
                stmt.setString(1, sessionTag);
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> query = new HashMap<>();
                    query.put("id", rs.getLong("id"));
                    query.put("name", rs.getString("name"));
                    query.put("description", rs.getString("description"));
                    query.put("query_params", rs.getString("query_params"));
                    query.put("created_at", rs.getTimestamp("created_at"));
                    query.put("updated_at", rs.getTimestamp("updated_at"));
                    query.put("session_tag", rs.getString("session_tag"));
                    queries.add(query);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to list saved queries: {}", e.getMessage());
        }
        
        return queries;
    }
    
    /**
     * Delete a saved query by name.
     * 
     * @param name The name of the query to delete
     * @return true if deletion was successful
     */
    public boolean deleteSavedQuery(String name) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return false;
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return false;
        }
        
        String sql = "DELETE FROM saved_queries WHERE name = ?";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, name);

            int rowsDeleted = stmt.executeUpdate();
            if (rowsDeleted > 0) {
                logger.info("Deleted saved query: {}", name);
                return true;
            } else {
                logger.warn("No saved query found with name: {}", name);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to delete saved query '{}': {}", name, e.getMessage());
            return false;
        }
    }
    
    /**
     * Get traffic records by IDs for replay functionality.
     * 
     * @param requestIds List of traffic_meta IDs to retrieve
     * @return List of traffic records with full request/response data
     */
    public List<Map<String, Object>> getTrafficByIds(List<Long> requestIds) {
        if (requestIds == null || requestIds.isEmpty()) {
            return new ArrayList<>();
        }
        
        // Build IN clause for the query
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < requestIds.size(); i++) {
            if (i > 0) placeholders.append(",");
            placeholders.append("?");
        }
        
        String sql = "SELECT id, timestamp, method, url, host, status_code, headers, body, response_headers, response_body, session_tag, content_hash, traffic_source, request_http_version, response_http_version, dns_resolution_time, connection_time, tls_negotiation_time, request_time, response_time, total_time FROM proxy_traffic WHERE id IN (" + placeholders + ") ORDER BY timestamp DESC";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            // Set parameters
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 1, requestIds.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("content_hash", rs.getString("content_hash"));
                    record.put("traffic_source", rs.getString("traffic_source"));
                    record.put("request_http_version", rs.getString("request_http_version"));
                    record.put("response_http_version", rs.getString("response_http_version"));
                    
                    // Add timing data
                    record.put("dns_resolution_time", rs.getObject("dns_resolution_time"));
                    record.put("connection_time", rs.getObject("connection_time"));
                    record.put("tls_negotiation_time", rs.getObject("tls_negotiation_time"));
                    record.put("request_time", rs.getObject("request_time"));
                    record.put("response_time", rs.getObject("response_time"));
                    record.put("total_time", rs.getObject("total_time"));
                    
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get traffic records by IDs: {}", e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Get full request metadata by ID for curl generation.
     *
     * <p>Resolves {@code proxy_traffic}, which is the id space every read
     * endpoint hands to clients ({@code /proxy/search}, {@code /proxy/history},
     * {@code /proxy/har-export}). {@code traffic_meta} carries an independent
     * AUTOINCREMENT counter — it is filled by a different logger — so the two
     * have drifted apart, and resolving that table made this endpoint answer
     * about a different captured request, or 404 on rows the legacy table alone
     * holds (#20).
     *
     * @param requestId The proxy_traffic ID to retrieve
     * @return Map containing full request data, or null if not found
     */
    public Map<String, Object> getFullRequestDataForCurl(long requestId) {
        // Resolve against the public proxy_traffic.id space first — the id
        // /proxy/search returns. Only when that misses do we treat the value as
        // an internal traffic_meta.id (surfaced as `traffic_meta_id` by
        // request-body search and annotation contexts) and follow its
        // proxy_traffic_id link. The fallback fires ONLY on a public miss, so an
        // id valid in the public space is never re-pointed at a different
        // request — the ambiguity #21/#28 guarded against (#22).
        Map<String, Object> record = readCurlRow(requestId);
        if (record != null) {
            record.put("resolved_id", requestId);
            record.put("resolved_via", "id");
            return record;
        }

        long linkedId = linkedProxyTrafficId(requestId);
        if (linkedId >= 0) {
            record = readCurlRow(linkedId);
            if (record != null) {
                record.put("resolved_id", linkedId);
                record.put("resolved_via", "traffic_meta_id");
                logger.debug("Curl id {} resolved via traffic_meta.proxy_traffic_id -> {}",
                             requestId, linkedId);
                return record;
            }
        }

        logger.warn("No request found with ID: {}", requestId);
        return null;
    }

    /**
     * Reads one proxy_traffic row into the shape {@link #generateBasicCurl}
     * expects, or null when the id names no captured request. Used by
     * {@link #getFullRequestDataForCurl} for both the public-id lookup and the
     * traffic_meta fallback (#22).
     */
    private Map<String, Object> readCurlRow(long proxyTrafficId) {
        String sql = "SELECT id, timestamp, method, url, host, session_tag, traffic_source, " +
                    "headers AS request_headers, body AS request_body " +
                    "FROM proxy_traffic WHERE id = ?";

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, proxyTrafficId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("traffic_source"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));

                    // Extract content type from headers for better curl generation
                    String headers = rs.getString("request_headers");
                    String contentType = extractContentType(headers);
                    record.put("content_type", contentType);

                    return record;
                }
                return null;
            }
        } catch (SQLException e) {
            logger.error("Failed to get full request data for ID {}: {}", proxyTrafficId, e.getMessage());
            return null;
        }
    }

    /**
     * The public proxy_traffic.id an internal traffic_meta.id links to, or -1
     * when the id names no traffic_meta row, the row is unlinked
     * (proxy_traffic_id NULL — e.g. Repeater traffic or an ambiguous pre-v14
     * backfill), or the schema predates the traffic_meta link. Never throws:
     * a missing traffic_meta table or column just means no fallback (#22).
     */
    private long linkedProxyTrafficId(long trafficMetaId) {
        String sql = "SELECT proxy_traffic_id FROM traffic_meta " +
                    "WHERE id = ? AND proxy_traffic_id IS NOT NULL";

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, trafficMetaId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    long linked = rs.getLong("proxy_traffic_id");
                    if (!rs.wasNull()) {
                        return linked;
                    }
                }
            }
        } catch (SQLException e) {
            // traffic_meta / proxy_traffic_id absent on this schema: no fallback.
            logger.debug("No traffic_meta link available for id {}: {}", trafficMetaId, e.getMessage());
        }
        return -1;
    }
    
    /**
     * Get top hosts or URLs by frequency.
     * 
     * @param limit Number of results to return
     * @param by Either "host" or "url"
     * @param sessionTag Optional session tag filter
     * @param startTime Optional start time filter
     * @param endTime Optional end time filter
     * @return List of top hosts/URLs with counts
     */
    public List<Map<String, Object>> getTopHosts(int limit, String by, String sessionTag, String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        String column = "host".equals(by) ? "host" : "url";
        
        try {
            String sql = "SELECT " + column + " AS value, COUNT(*) AS count FROM proxy_traffic " +
                        "GROUP BY " + column + " ORDER BY count DESC LIMIT " + limit;
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("value", rs.getString("value"));
                        result.put("count", rs.getLong("count"));
                        results.add(result);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get top hosts: {}", e.getMessage(), e);
        }
        
        return results;
    }
    
    /**
     * Get histogram of request counts over time.
     * 
     * @param interval Time interval: "minute", "hour", or "day"
     * @param sessionTag Optional session tag filter
     * @param method Optional HTTP method filter
     * @param statusCode Optional status code filter
     * @param startTime Optional start time filter
     * @param endTime Optional end time filter
     * @return List of histogram buckets with counts
     */
    public List<Map<String, Object>> getHistogram(String interval, String sessionTag, String method, 
                                                  String statusCode, String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try {
            // Determine SQL date format based on interval
            String dateFormat;
            switch (interval.toLowerCase()) {
                case "minute":
                    dateFormat = "%Y-%m-%dT%H:%M:00Z";
                    break;
                case "hour":
                    dateFormat = "%Y-%m-%dT%H:00:00Z";
                    break;
                case "day":
                    dateFormat = "%Y-%m-%dT00:00:00Z";
                    break;
                default:
                    dateFormat = "%Y-%m-%dT%H:00:00Z"; // Default to hour
                    break;
            }
            
            String sql = "SELECT strftime('" + dateFormat + "', timestamp/1000, 'unixepoch') AS bucket, " +
                        "COUNT(*) AS count FROM proxy_traffic " +
                        "GROUP BY bucket ORDER BY bucket ASC";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("bucket", rs.getString("bucket"));
                        result.put("count", rs.getLong("count"));
                        results.add(result);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get histogram: {}", e.getMessage(), e);
        }
        
        return results;
    }
    
    /**
     * Enhanced search with regex support.
     * 
     * @param searchParams Search parameters including regex patterns
     * @return List of matching traffic records
     */
    public List<Map<String, Object>> searchTrafficWithRegex(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Use enhanced search if regex parameters are present
        boolean useRegex = Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
        if (!useRegex && !hasRegexParams(searchParams)) {
            // Fallback to standard search
            return searchTraffic(searchParams);
        }
        
        StringBuilder sql = new StringBuilder("SELECT * FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        
        // Add regex filters
        if (searchParams.containsKey("url_regex")) {
            sql.append(" AND url REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("url_regex") : searchParams.get("url_regex"));
        }
        
        if (searchParams.containsKey("method_regex")) {
            sql.append(" AND method REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("method_regex") : searchParams.get("method_regex"));
        }
        
        if (searchParams.containsKey("host_regex")) {
            sql.append(" AND host REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("host_regex") : searchParams.get("host_regex"));
        }
        
        if (searchParams.containsKey("headers_regex")) {
            sql.append(" AND headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("headers_regex") : searchParams.get("headers_regex"));
        }
        
        if (searchParams.containsKey("body_regex")) {
            sql.append(" AND body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("body_regex") : searchParams.get("body_regex"));
        }
        
        if (searchParams.containsKey("response_headers_regex")) {
            sql.append(" AND response_headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_headers_regex") : searchParams.get("response_headers_regex"));
        }
        
        if (searchParams.containsKey("response_body_regex")) {
            sql.append(" AND response_body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_body_regex") : searchParams.get("response_body_regex"));
        }
        
        if (searchParams.containsKey("session_tag_regex")) {
            sql.append(" AND session_tag REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("session_tag_regex") : searchParams.get("session_tag_regex"));
        }
        
        // Add standard filters (still supported alongside regex)
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        // Add ordering and limits
        sql.append(" ORDER BY timestamp DESC");
        
        if (searchParams.containsKey("limit")) {
            sql.append(" LIMIT ?");
            params.add(Integer.parseInt(searchParams.get("limit")));
        }
        
        if (searchParams.containsKey("offset")) {
            sql.append(" OFFSET ?");
            params.add(Integer.parseInt(searchParams.get("offset")));
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search traffic with regex: {}", e.getMessage(), e);
            // Fallback to standard search on regex error
            logger.info("Falling back to standard search due to regex error");
            return searchTraffic(searchParams);
        }
        
        return results;
    }
    
    /**
     * Check if search parameters contain regex patterns.
     */
    private boolean hasRegexParams(Map<String, String> searchParams) {
        return searchParams.containsKey("url_regex") || 
               searchParams.containsKey("method_regex") ||
               searchParams.containsKey("host_regex") ||
               searchParams.containsKey("headers_regex") ||
               searchParams.containsKey("body_regex") ||
               searchParams.containsKey("response_headers_regex") ||
               searchParams.containsKey("response_body_regex") ||
               searchParams.containsKey("session_tag_regex");
    }
    
    /**
     * Get count for regex search queries.
     */
    public long getRegexSearchCount(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        // Use standard count if no regex
        boolean useRegex = Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
        if (!useRegex && !hasRegexParams(searchParams)) {
            return getSearchCount(searchParams);
        }
        
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        
        // Add same regex filters as main search
        if (searchParams.containsKey("url_regex")) {
            sql.append(" AND url REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("url_regex") : searchParams.get("url_regex"));
        }
        
        if (searchParams.containsKey("method_regex")) {
            sql.append(" AND method REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("method_regex") : searchParams.get("method_regex"));
        }
        
        if (searchParams.containsKey("host_regex")) {
            sql.append(" AND host REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("host_regex") : searchParams.get("host_regex"));
        }
        
        if (searchParams.containsKey("headers_regex")) {
            sql.append(" AND headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("headers_regex") : searchParams.get("headers_regex"));
        }
        
        if (searchParams.containsKey("body_regex")) {
            sql.append(" AND body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("body_regex") : searchParams.get("body_regex"));
        }
        
        if (searchParams.containsKey("response_headers_regex")) {
            sql.append(" AND response_headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_headers_regex") : searchParams.get("response_headers_regex"));
        }
        
        if (searchParams.containsKey("response_body_regex")) {
            sql.append(" AND response_body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_body_regex") : searchParams.get("response_body_regex"));
        }
        
        if (searchParams.containsKey("session_tag_regex")) {
            sql.append(" AND session_tag REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("session_tag_regex") : searchParams.get("session_tag_regex"));
        }
        
        // Add standard filters
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get regex search count: {}", e.getMessage(), e);
            return getSearchCount(searchParams);
        }
        
        return 0;
    }
    
    /**
     * Bulk tagging operation.
     * 
     * @param requestIds List of request IDs to tag
     * @param tags Comma-separated tags to add
     * @return Number of records updated
     */
    public int bulkAddTags(List<Long> requestIds, String tags) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET tags = CASE " +
                    "WHEN tags IS NULL OR tags = '' THEN ? " +
                    "ELSE tags || ',' || ? " +
                    "END WHERE id IN (" + placeholders + ")";
        
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, tags);
            stmt.setString(2, tags);

            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 3, requestIds.get(i));
            }

            int updated = stmt.executeUpdate();
            logger.info("Bulk tagged {} records with tags: {}", updated, tags);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk add tags: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Bulk commenting operation.
     * 
     * @param requestIds List of request IDs to comment
     * @param comment Comment to add
     * @return Number of records updated
     */
    public int bulkAddComments(List<Long> requestIds, String comment) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET comment = CASE " +
                    "WHEN comment IS NULL OR comment = '' THEN ? " +
                    "ELSE comment || '\\n---\\n' || ? " +
                    "END WHERE id IN (" + placeholders + ")";
        
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            stmt.setString(1, comment);
            stmt.setString(2, comment);

            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 3, requestIds.get(i));
            }

            int updated = stmt.executeUpdate();
            logger.info("Bulk commented {} records with comment: {}", updated, comment);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk add comments: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Remove tags from multiple records.
     * 
     * @param requestIds List of request IDs to update
     * @param tagsToRemove Comma-separated tags to remove
     * @return Number of records updated
     */
    public int bulkRemoveTags(List<Long> requestIds, String tagsToRemove) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String[] tagsArray = tagsToRemove.split(",");
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        
        StringBuilder sql = new StringBuilder("UPDATE proxy_traffic SET tags = ");
        
        // Build REPLACE chain for each tag to remove
        sql.append("REPLACE(");
        for (int i = 0; i < tagsArray.length; i++) {
            if (i > 0) {
                sql.append("REPLACE(");
            }
            sql.append("COALESCE(tags, '')");
        }
        
        // Add the REPLACE operations
        for (int i = 0; i < tagsArray.length; i++) {
            sql.append(", ?, '')");
            if (i < tagsArray.length - 1) {
                sql.append(")");
            }
        }
        
        sql.append(" WHERE id IN (").append(placeholders).append(")");
        
        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql.toString())) {
            int paramIndex = 1;

            // Set tag parameters
            for (String tag : tagsArray) {
                stmt.setString(paramIndex++, tag.trim());
            }
            
            // Set ID parameters
            for (Long requestId : requestIds) {
                stmt.setLong(paramIndex++, requestId);
            }
            
            int updated = stmt.executeUpdate();
            logger.info("Bulk removed tags '{}' from {} records", tagsToRemove, updated);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk remove tags: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Clear comments from multiple records.
     * 
     * @param requestIds List of request IDs to update
     * @return Number of records updated
     */
    public int bulkClearComments(List<Long> requestIds) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET comment = NULL WHERE id IN (" + placeholders + ")";

        try (WriteLease lease = new WriteLease();
             PreparedStatement stmt = lease.conn.prepareStatement(sql)) {
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 1, requestIds.get(i));
            }

            int updated = stmt.executeUpdate();
            logger.info("Bulk cleared comments from {} records", updated);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk clear comments: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Helper method to add host filtering to SQL queries.
     * Supports both single host and multiple hosts filtering.
     * 
     * @param sql The StringBuilder to append to
     * @param params The parameter list to add to
     * @param searchParams The search parameters map
     * @param caseInsensitive Whether to use case-insensitive comparison
     */
    private void addHostFiltering(StringBuilder sql, List<Object> params, 
                                 Map<String, String> searchParams, boolean caseInsensitive) {
        addHostFiltering(sql, params, searchParams, caseInsensitive, "host");
    }
    
    /**
     * Overloaded helper method to add host filtering with custom column name.
     * 
     * @param sql The StringBuilder to append to
     * @param params The parameter list to add to
     * @param searchParams The search parameters map
     * @param caseInsensitive Whether to use case-insensitive comparison
     * @param columnName The host column name (e.g., "host" or "tm.host")
     */
    private void addHostFiltering(StringBuilder sql, List<Object> params, 
                                 Map<String, String> searchParams, boolean caseInsensitive, String columnName) {
        if (searchParams.containsKey("host")) {
            String hostLikeOperator = caseInsensitive ? 
                " AND LOWER(" + columnName + ") LIKE LOWER(?)" : 
                " AND " + columnName + " LIKE ?";
            sql.append(hostLikeOperator);
            params.add("%" + searchParams.get("host") + "%");
        } else if (searchParams.containsKey("hosts")) {
            String[] hostList = searchParams.get("hosts").split(",");
            if (hostList.length > 0) {
                sql.append(" AND (");
                for (int i = 0; i < hostList.length; i++) {
                    if (i > 0) sql.append(" OR ");
                    String hostClause = caseInsensitive ? 
                        "LOWER(" + columnName + ") LIKE LOWER(?)" : 
                        columnName + " LIKE ?";
                    sql.append(hostClause);
                    params.add("%" + hostList[i].trim() + "%");
                }
                sql.append(")");
            }
        }
    }
    
    /**
     * Helper method for Map<String, Object> parameter type.
     */
    private void addHostFilteringFromObjectMap(StringBuilder sql, List<Object> params, 
                                              Map<String, Object> searchParams, boolean caseInsensitive, String columnName) {
        if (searchParams.containsKey("host")) {
            String hostLikeOperator = caseInsensitive ? 
                " AND LOWER(" + columnName + ") LIKE LOWER(?)" : 
                " AND " + columnName + " LIKE ?";
            sql.append(hostLikeOperator);
            params.add("%" + searchParams.get("host").toString() + "%");
        } else if (searchParams.containsKey("hosts")) {
            String[] hostList = searchParams.get("hosts").toString().split(",");
            if (hostList.length > 0) {
                sql.append(" AND (");
                for (int i = 0; i < hostList.length; i++) {
                    if (i > 0) sql.append(" OR ");
                    String hostClause = caseInsensitive ? 
                        "LOWER(" + columnName + ") LIKE LOWER(?)" : 
                        columnName + " LIKE ?";
                    sql.append(hostClause);
                    params.add("%" + hostList[i].trim() + "%");
                }
                sql.append(")");
            }
        }
    }
    
    /**
     * Helper method to add timestamp filtering for incremental updates.
     * 
     * @param sql The StringBuilder to append to
     * @param params The parameter list to add to
     * @param searchParams The search parameters map
     */
    private void addTimestampFiltering(StringBuilder sql, List<Object> params, Map<String, String> searchParams) {
        if (searchParams.containsKey("since")) {
            Long sinceMs = parseWindowBound("since", searchParams.get("since"));
            if (sinceMs != null) {
                // Exclusive lower bound: incremental sync must not refetch the
                // last seen row (#54 window semantics pinned in tests).
                sql.append(" AND timestamp > ?");
                params.add(sinceMs);
            }
        }
        if (searchParams.containsKey("until")) {
            Long untilMs = parseWindowBound("until", searchParams.get("until"));
            if (untilMs != null) {
                sql.append(" AND timestamp <= ?");
                params.add(untilMs);
            }
        }
    }

    /**
     * Parses a since/until window bound to epoch milliseconds. Accepts epoch-ms
     * digits or ISO 8601; anything else is ignored with a warning so a malformed
     * bound never silently empties the result set (#54).
     */
    private Long parseWindowBound(String name, String value) {
        try {
            if (value.matches("\\d+")) {
                return Long.parseLong(value);
            }
            // ISO 8601 (e.g., 2024-01-15T10:30:00) or date-only. Parsed here rather
            // than via parseTimestamp, whose silent now() fallback must not apply:
            // an unparseable bound is ignored, never turned into a filter (#54).
            LocalDateTime localDateTime;
            if (value.endsWith("Z")) {
                localDateTime = LocalDateTime.parse(value.substring(0, value.length() - 1));
            } else if (value.contains("T")) {
                localDateTime = LocalDateTime.parse(value);
            } else {
                localDateTime = LocalDateTime.parse(value + "T00:00:00");
            }
            return Timestamp.valueOf(localDateTime).getTime();
        } catch (RuntimeException e) {
            logger.warn("Invalid timestamp format for '{}' parameter: {}", name, value);
            return null;
        }
    }
    
    /**
     * Helper method for Map<String, Object> parameter type.
     */
    private void addTimestampFilteringFromObjectMap(StringBuilder sql, List<Object> params, Map<String, Object> searchParams) {
        if (searchParams.containsKey("since")) {
            Long sinceMs = parseWindowBound("since", searchParams.get("since").toString());
            if (sinceMs != null) {
                sql.append(" AND timestamp > ?");
                params.add(sinceMs);
            }
        }
        if (searchParams.containsKey("until")) {
            Long untilMs = parseWindowBound("until", searchParams.get("until").toString());
            if (untilMs != null) {
                sql.append(" AND timestamp <= ?");
                params.add(untilMs);
            }
        }
    }
} 
