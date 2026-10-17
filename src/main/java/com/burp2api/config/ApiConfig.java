package com.burp2api.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.io.File;

/**
 * Configuration class for the burp2api - Burp Suite REST API Extension.
 * Manages all configuration settings including port, database path,
 * and other runtime parameters.
 * 
 * @version 1.0.1
 */
public class ApiConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(ApiConfig.class);
    
    // Default configuration values
    private static final int DEFAULT_PORT = 7850;
    private static final String DEFAULT_DB_PATH = "burp2api.db";
    private static final boolean DEFAULT_VERBOSE_LOGGING = false;
    private static final String DEFAULT_SESSION_TAG = ""; // Will be auto-generated if empty
    private static final String DEFAULT_BIND_HOST = "127.0.0.1"; // Loopback only by default
    private static final String DEFAULT_AUTH_TOKEN = "";          // Empty = auth disabled
    private static final String DEFAULT_REST_URL = "http://127.0.0.1:1337"; // Burp built-in REST API
    private static final String DEFAULT_REST_KEY = "";           // Empty = keyless (loopback only)
    // Ticket #14: REST-first, throttled scanning. backend=auto prefers the built-in
    // REST API with this named audit config + resource pool, falling back to a
    // Montoya audit only when REST is unreachable. "Default resource pool" is
    // Burp's built-in pool name, preset to 1 concurrent request / 1000ms throttle
    // by config/project-options.template.json (import it via POST /scope/project-config);
    // that same project pool also throttles the Montoya fallback path.
    private static final String DEFAULT_RESOURCE_POOL = "Default resource pool";
    // Default audit configuration applied to auto/REST scans. b2a-light-fuzz is a
    // custom library config (JS analysis off, insertion points trimmed) that DOES
    // include the extension-registered checks (param-fuzzer), unlike Burp's built-in
    // "Audit checks - light/medium active" presets which exclude them.
    // #15: this value may be a library NAME (resolved against Burp's configuration
    // library) or a PATH to a config JSON exported once from the Burp UI. A path is
    // shipped inline as a CustomConfiguration, so backend=auto works on a fresh
    // install with an EMPTY library. As a bare name it must exist in the library or
    // the REST scan fails and burp2api falls back to a Montoya audit. See
    // burp/config/b2a-light-fuzz-build.md.
    private static final String DEFAULT_SCAN_CONFIG = "b2a-light-fuzz";

    // #20: captured headers and bodies are stored verbatim; this is only a
    // sanity ceiling on a single column, not a body-size policy. 10 MiB keeps
    // any realistic captured response whole.
    private static final int DEFAULT_MAX_STORED_CONTENT_CHARS = 10 * 1024 * 1024;

    // #24: byte-exact raw request/response capture. Raw wire bytes are stored in
    // a BLOB alongside the flattened columns. A message larger than this cap is
    // stored NULL and flagged omitted rather than truncated — a partial raw
    // message is worse than none for evidence. 50 MiB keeps any realistic pair.
    private static final int DEFAULT_MAX_RAW_BYTES = 50 * 1024 * 1024;

    // Configuration keys
    private static final String CONFIG_FILE = "/config/application.properties";
    private static final String PORT_KEY = "api.port";
    private static final String DB_PATH_KEY = "database.path";
    private static final String VERBOSE_LOGGING_KEY = "logging.verbose";
    private static final String SESSION_TAG_KEY = "session.tag";
    private static final String BIND_HOST_KEY = "api.bind";
    private static final String AUTH_TOKEN_KEY = "api.token";
    private static final String REST_URL_KEY = "scanner.rest.url";
    private static final String REST_KEY_KEY = "scanner.rest.key";
    private static final String RESOURCE_POOL_KEY = "scanner.rest.resource_pool";
    private static final String SCAN_CONFIG_KEY = "scanner.rest.scan_config";
    private static final String MAX_STORED_CONTENT_CHARS_KEY = "storage.max_content_chars";
    private static final String MAX_RAW_BYTES_KEY = "storage.max_raw_bytes";

    // Configuration values
    private int port;
    private String databasePath;
    private boolean verboseLogging;
    private String sessionTag;
    private String bindHost = DEFAULT_BIND_HOST;
    private String authToken = DEFAULT_AUTH_TOKEN;
    private String restUrl = DEFAULT_REST_URL;
    private String restKey = DEFAULT_REST_KEY;
    private String resourcePool = DEFAULT_RESOURCE_POOL;
    private String scanConfig = DEFAULT_SCAN_CONFIG;
    private int maxStoredContentChars = DEFAULT_MAX_STORED_CONTENT_CHARS;
    private int maxRawBytes = DEFAULT_MAX_RAW_BYTES;

    /**
     * Constructor that loads configuration from properties file
     * with fallback to environment variables and defaults.
     */
    public ApiConfig() {
        // First, try to load from UI saved configuration
        loadFromUiConfiguration();
        
        // Then load from properties file (can override UI config)
        Properties properties = loadProperties();
        
        // Load configuration with fallbacks to environment variables and defaults
        this.port = getIntProperty(properties, PORT_KEY, "BURP2API_PORT", this.port != 0 ? this.port : DEFAULT_PORT);
        String configuredDbPath = getStringProperty(properties, DB_PATH_KEY, "BURP2API_DB_PATH", this.databasePath != null ? this.databasePath : DEFAULT_DB_PATH);
        
        // Apply path conversion logic for database path
        if (!configuredDbPath.startsWith("/") && !configuredDbPath.contains(":")) {
            String defaultDbDir = System.getProperty("user.home") + File.separator + ".burp2api";
            File dbDir = new File(defaultDbDir);
            if (!dbDir.exists()) {
                dbDir.mkdirs();
                logger.info("Created database directory: {}", defaultDbDir);
            }
            this.databasePath = defaultDbDir + File.separator + configuredDbPath;
            logger.info("Converted relative database path to absolute: {}", this.databasePath);
        } else {
            this.databasePath = configuredDbPath;
        }
        
        this.verboseLogging = getBooleanProperty(properties, VERBOSE_LOGGING_KEY, "BURP2API_VERBOSE", this.verboseLogging);

        this.maxStoredContentChars = getIntProperty(properties, MAX_STORED_CONTENT_CHARS_KEY,
                "BURP2API_MAX_STORED_CONTENT_CHARS", DEFAULT_MAX_STORED_CONTENT_CHARS);

        this.maxRawBytes = getIntProperty(properties, MAX_RAW_BYTES_KEY,
                "BURP2API_MAX_RAW_BYTES", DEFAULT_MAX_RAW_BYTES);

        // Network binding and optional bearer-token auth (agent access controls)
        this.bindHost = getStringProperty(properties, BIND_HOST_KEY, "BURP2API_BIND", DEFAULT_BIND_HOST);
        this.authToken = getStringProperty(properties, AUTH_TOKEN_KEY, "BURP2API_TOKEN", DEFAULT_AUTH_TOKEN);
        if (!"127.0.0.1".equals(this.bindHost) && !"localhost".equals(this.bindHost)) {
            logger.warn("API is bound to non-loopback host '{}' - it may be reachable from other machines. "
                + "Set BURP2API_TOKEN to require bearer-token authentication.", this.bindHost);
        }

        // Burp built-in REST API backend for URL/crawl+audit scans (ticket #13).
        // The key, if set, is authentication material and must never be logged.
        this.restUrl = getStringProperty(properties, REST_URL_KEY, "BURP2API_REST_URL", DEFAULT_REST_URL);
        this.restKey = getStringProperty(properties, REST_KEY_KEY, "BURP2API_REST_KEY", DEFAULT_REST_KEY);
        this.resourcePool = getStringProperty(properties, RESOURCE_POOL_KEY, "BURP2API_RESOURCE_POOL", DEFAULT_RESOURCE_POOL);
        this.scanConfig = getStringProperty(properties, SCAN_CONFIG_KEY, "BURP2API_SCAN_CONFIG", DEFAULT_SCAN_CONFIG);
        
        // Handle session tag with auto-generation if empty/null
        String configuredSessionTag = getStringProperty(properties, SESSION_TAG_KEY, "BURP2API_SESSION_TAG", this.sessionTag != null ? this.sessionTag : DEFAULT_SESSION_TAG);
        this.sessionTag = generateSessionTagIfNeeded(configuredSessionTag);
        
        logger.info("Configuration loaded - Port: {}, Database: {}, Verbose: {}, Session Tag: '{}'", 
                   port, databasePath, verboseLogging, sessionTag);
        logger.debug("Config DB path: configured='{}', default='{}', final='{}'",
                   configuredDbPath, DEFAULT_DB_PATH, this.databasePath);
                   
        // Apply initial verbose logging setting
        com.burp2api.logging.ApiLogger.setVerbose(verboseLogging);
    }
    
    /**
     * Loads configuration from the UI configuration file if it exists.
     */
    private void loadFromUiConfiguration() {
        try {
            // Import ConfigurationPanel statically to avoid circular dependency
            String configDir = System.getProperty("user.home") + File.separator + ".burp2api";
            String configFile = configDir + File.separator + "extension.properties";
            
            File uiConfigFile = new File(configFile);
            if (!uiConfigFile.exists()) {
                // Initialize with smart defaults
                this.port = DEFAULT_PORT;
                this.verboseLogging = DEFAULT_VERBOSE_LOGGING;
                this.sessionTag = generateSessionTagIfNeeded(DEFAULT_SESSION_TAG);
                
                // Create default database directory and path
                String defaultDbDir = System.getProperty("user.home") + File.separator + ".burp2api";
                File dbDir = new File(defaultDbDir);
                if (!dbDir.exists()) {
                    dbDir.mkdirs();
                    logger.info("Created default database directory: {}", defaultDbDir);
                }
                this.databasePath = defaultDbDir + File.separator + "burp2api.db";
                logger.info("Using default database path: {}", this.databasePath);
                return;
            }
            
            Properties uiProps = new Properties();
            try (InputStream fis = new java.io.FileInputStream(uiConfigFile)) {
                uiProps.load(fis);
            }
            
            // Load UI configuration
            this.port = Integer.parseInt(uiProps.getProperty("api.port", String.valueOf(DEFAULT_PORT)));
            String configuredDbPath = uiProps.getProperty("database.path", DEFAULT_DB_PATH);
            
            // If the configured path is relative, make it absolute in the user's home
            if (!configuredDbPath.startsWith("/") && !configuredDbPath.contains(":")) {
                String defaultDbDir = System.getProperty("user.home") + File.separator + ".burp2api";
                File dbDir = new File(defaultDbDir);
                if (!dbDir.exists()) {
                    dbDir.mkdirs();
                    logger.info("Created database directory: {}", defaultDbDir);
                }
                this.databasePath = defaultDbDir + File.separator + configuredDbPath;
                logger.info("Converted relative database path to absolute: {}", this.databasePath);
            } else {
                this.databasePath = configuredDbPath;
            }
            
            this.verboseLogging = Boolean.parseBoolean(uiProps.getProperty("logging.verbose", String.valueOf(DEFAULT_VERBOSE_LOGGING)));
            this.sessionTag = generateSessionTagIfNeeded(uiProps.getProperty("session.tag", DEFAULT_SESSION_TAG));
            
            logger.debug("Loaded configuration from UI config file: {}", configFile);
            
        } catch (Exception e) {
            logger.debug("No UI configuration found or failed to load, using defaults: {}", e.getMessage());
            // Initialize with smart defaults
            this.port = DEFAULT_PORT;
            this.verboseLogging = DEFAULT_VERBOSE_LOGGING;
            this.sessionTag = generateSessionTagIfNeeded(DEFAULT_SESSION_TAG);
            
            // Create default database directory and path
            String defaultDbDir = System.getProperty("user.home") + File.separator + ".burp2api";
            File dbDir = new File(defaultDbDir);
            if (!dbDir.exists()) {
                dbDir.mkdirs();
                logger.info("Created default database directory: {}", defaultDbDir);
            }
            this.databasePath = defaultDbDir + File.separator + "burp2api.db";
            logger.info("Using default database path: {}", this.databasePath);
        }
    }
    
    /**
     * Loads properties from the configuration file.
     * 
     * @return Properties object with loaded configuration
     */
    private Properties loadProperties() {
        Properties properties = new Properties();
        
        try (InputStream inputStream = getClass().getResourceAsStream(CONFIG_FILE)) {
            if (inputStream != null) {
                properties.load(inputStream);
                logger.debug("Configuration file loaded successfully");
            } else {
                logger.warn("Configuration file not found: {}, using defaults", CONFIG_FILE);
            }
        } catch (IOException e) {
            logger.warn("Failed to load configuration file: {}, using defaults", CONFIG_FILE, e);
        }
        
        return properties;
    }
    
    /**
     * Gets an integer property with environment variable and default fallback.
     */
    private int getIntProperty(Properties properties, String propertyKey, String envKey, int defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        if (value != null) {
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                logger.warn("Invalid integer value for {}: {}, using default: {}", propertyKey, value, defaultValue);
            }
        }
        
        return defaultValue;
    }
    
    /**
     * Gets a string property with environment variable and default fallback.
     */
    private String getStringProperty(Properties properties, String propertyKey, String envKey, String defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        return value != null ? value.trim() : defaultValue;
    }
    
    /**
     * Gets a boolean property with environment variable and default fallback.
     */
    private boolean getBooleanProperty(Properties properties, String propertyKey, String envKey, boolean defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        if (value != null) {
            return Boolean.parseBoolean(value.trim());
        }
        
        return defaultValue;
    }
    
    /**
     * Generates a session tag if the provided one is null or empty.
     * Creates a meaningful default using timestamp and session info.
     * 
     * @param configuredTag The configured session tag (may be null/empty)
     * @return A valid session tag (auto-generated if needed)
     */
    private String generateSessionTagIfNeeded(String configuredTag) {
        if (configuredTag != null && !configuredTag.trim().isEmpty()) {
            return configuredTag.trim();
        }
        
        // Auto-generate a meaningful session tag
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String timestamp = now.format(formatter);
        
        // Include some context about the session
        String autoTag = String.format("session_%s", timestamp);
        
        logger.info("🏷️ Auto-generated session tag: '{}' (no session tag was configured)", autoTag);
        return autoTag;
    }
    
    /**
     * Updates the session tag with auto-generation logic.
     * This can be called from the UI or API to set a new session tag.
     * 
     * @param sessionTag The new session tag (will be auto-generated if null/empty)
     */
    public void updateSessionTag(String sessionTag) {
        this.sessionTag = generateSessionTagIfNeeded(sessionTag);
        logger.info("Session tag updated to: '{}'", this.sessionTag);
    }
    
    /**
     * Generates a new auto session tag for starting a new session.
     * Useful for creating new testing sessions programmatically.
     * 
     * @param prefix Optional prefix for the session tag (e.g., "test", "scan", "manual")
     * @return A new auto-generated session tag
     */
    public String generateNewSessionTag(String prefix) {
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String timestamp = now.format(formatter);
        
        if (prefix != null && !prefix.trim().isEmpty()) {
            String newTag = String.format("%s_%s", prefix.trim(), timestamp);
            logger.info("🏷️ Generated new session tag with prefix: '{}'", newTag);
            return newTag;
        } else {
            String newTag = String.format("session_%s", timestamp);
            logger.info("🏷️ Generated new session tag: '{}'", newTag);
            return newTag;
        }
    }
    
    // Getters
    
    public int getPort() {
        return port;
    }
    
    public String getDatabasePath() {
        return databasePath;
    }
    
    public boolean isVerboseLogging() {
        return verboseLogging;
    }
    
    public String getSessionTag() {
        return sessionTag;
    }

    public String getBindHost() {
        return bindHost;
    }

    /** Base URL of the Burp built-in REST API (default {@code http://127.0.0.1:1337}). */
    public String getRestUrl() {
        return restUrl;
    }

    /** API key for the Burp built-in REST API, or empty for keyless (loopback) access. Never log this. */
    public String getRestKey() {
        return restKey;
    }

    /**
     * Default Burp resource pool name applied to auto/REST scans that do not name a
     * pool (ticket #14). Defaults to Burp's built-in {@code "Default resource pool"},
     * which the project-options template presets to 1 concurrent request / 1000ms
     * throttle. Empty disables the default (REST scan runs with no named pool).
     */
    public String getResourcePool() {
        return resourcePool;
    }

    /**
     * Default audit configuration applied to auto/REST scans that do not name one
     * (ticket #14). Defaults to {@code "b2a-light-fuzz"}, a custom config that keeps
     * param-fuzzer's extension checks (unlike the built-in light/medium presets).
     * The value is either a library <b>name</b> or a <b>path</b> to a config JSON
     * exported from the Burp UI; a path is shipped inline as a
     * {@code CustomConfiguration} so scans work with an empty library (ticket #15,
     * resolved by {@link com.burp2api.services.ScanConfigResolver}). Empty disables
     * the default (REST scan runs with Burp's default config). See
     * burp/config/b2a-light-fuzz-build.md.
     */
    public String getScanConfig() {
        return scanConfig;
    }

    /**
     * Ceiling, in characters, on a single stored header or body column (#20).
     * Content below it is stored verbatim; a longer value is trimmed to exactly
     * this length, logged, and flagged as truncated on the record.
     */
    public int getMaxStoredContentChars() {
        return maxStoredContentChars;
    }

    /**
     * Ceiling, in bytes, on a single stored raw request or response message
     * ({@code request_raw} / {@code response_raw}, #24). A message at or below it
     * is stored verbatim; a larger one is stored as NULL and flagged omitted on
     * the record rather than truncated.
     */
    public int getMaxRawBytes() {
        return maxRawBytes;
    }

    /**
     * Returns the configured bearer token, or empty string if authentication is disabled.
     */
    public String getAuthToken() {
        return authToken;
    }

    /**
     * Whether bearer-token authentication is enabled (a non-empty token is configured).
     */
    public boolean isAuthEnabled() {
        return authToken != null && !authToken.isEmpty();
    }

    // Setters (for standalone mode configuration override)
    
    public void setPort(int port) {
        this.port = port;
    }
    
    public void setDatabasePath(String databasePath) {
        this.databasePath = databasePath;
    }
    
    public void setVerboseLogging(boolean verboseLogging) {
        this.verboseLogging = verboseLogging;
        // Apply the verbose logging setting to the logger
        com.burp2api.logging.ApiLogger.setVerbose(verboseLogging);
    }
    
    public void setSessionTag(String sessionTag) {
        this.sessionTag = sessionTag;
    }
    
    
    @Override
    public String toString() {
        return "ApiConfig{" +
                "port=" + port +
                ", databasePath='" + databasePath + '\'' +
                ", verboseLogging=" + verboseLogging +
                ", sessionTag='" + sessionTag + '\'' +
                '}';
    }
} 