package com.burp2api.database;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import com.burp2api.config.ApiConfig;
import com.burp2api.logging.TrafficSource;
import com.burp2api.websocket.EventBroadcaster;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Asynchronous traffic queue system to handle high-volume proxy traffic
 * without impacting Burp's performance. Uses background processing and
 * batch operations for optimal database performance.
 * 
 * @version 1.0.0
 */
public class TrafficQueue {
    
    private static final Logger logger = LoggerFactory.getLogger(TrafficQueue.class);
    
    // HIGH-PERFORMANCE Queue configuration optimized for WAL mode + large datasets
    private static final int DEFAULT_QUEUE_SIZE = 100000; // Large buffer for high-volume bursts
    private static final int MIN_BATCH_SIZE = 50;         // Small batches for low-latency
    private static final int MAX_BATCH_SIZE = 500;        // Large batches for high-throughput  
    private static final int ADAPTIVE_BATCH_SIZE = 250;   // Default adaptive batch size
    private static final int PROCESSING_INTERVAL_MS = 1;  // Ultra-low latency WebSocket streaming
    private static final int MAX_PROCESSING_TIME_MS = 1000; // More time for WAL mode batch commits
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    
    // WebSocket event broadcasting
    private EventBroadcaster eventBroadcaster;
    
    // Queue for storing traffic items
    private final BlockingQueue<TrafficItem> trafficQueue;
    
    // Background processing
    private final ExecutorService processingExecutor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Performance metrics
    private final AtomicLong totalQueued = new AtomicLong(0);
    private final AtomicLong totalProcessed = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);
    private final AtomicLong totalErrors = new AtomicLong(0);
    private volatile long lastProcessingTime = 0;
    private volatile int currentQueueSize = 0;
    
    // Project change detection
    private volatile long lastProjectCheckTime = 0;
    private static final long PROJECT_CHECK_INTERVAL_MS = 10000; // Check every 10 seconds
    
    private final Lock queueLock = new ReentrantLock();
    
    /**
     * Represents a traffic item to be processed.
     */
    public static class TrafficItem {
        public enum Type { REQUEST, RESPONSE, RAW_TRAFFIC }
        
        public final Type type;
        public final long timestamp;
        public final String sessionTag;
        public final TrafficSource source;
        
        // For requests
        public final InterceptedRequest request;
        
        // For responses
        public final InterceptedResponse response;
        
        // For raw traffic (imports, etc.)
        public final String method;
        public final String url;
        public final String host;
        public final String headers;
        public final String body;
        public final String responseHeaders;
        public final String responseBody;
        public final Integer statusCode;
        public final String requestHttpVersion;
        public final String responseHttpVersion;

        // The exact proxy_traffic.id this capture also wrote, when the caller
        // knows it (AllToolsLogger/RepeaterLogger), so storeTrafficNormalized can
        // record an exact traffic_meta -> proxy_traffic link instead of leaving
        // the two id spaces to be bridged heuristically (#28). <= 0 means unknown.
        public long proxyTrafficId = -1L;

        // Request constructor
        public TrafficItem(InterceptedRequest request, String sessionTag) {
            this.type = Type.REQUEST;
            this.timestamp = System.currentTimeMillis();
            this.request = request;
            this.response = null;
            this.sessionTag = sessionTag;
            this.source = TrafficSource.PROXY;
            this.method = null;
            this.url = null;
            this.host = null;
            this.headers = null;
            this.body = null;
            this.responseHeaders = null;
            this.responseBody = null;
            this.statusCode = null;
            this.requestHttpVersion = null;
            this.responseHttpVersion = null;
        }
        
        // Response constructor
        public TrafficItem(InterceptedResponse response, String sessionTag) {
            this.type = Type.RESPONSE;
            this.timestamp = System.currentTimeMillis();
            this.request = null;
            this.response = response;
            this.sessionTag = sessionTag;
            this.source = TrafficSource.PROXY;
            this.method = null;
            this.url = null;
            this.host = null;
            this.headers = null;
            this.body = null;
            this.responseHeaders = null;
            this.responseBody = null;
            this.statusCode = null;
            this.requestHttpVersion = null;
            this.responseHttpVersion = null;
        }
        
        // Raw traffic constructor
        public TrafficItem(String method, String url, String host, String headers, String body,
                          String responseHeaders, String responseBody, Integer statusCode, 
                          String sessionTag, TrafficSource source, String requestHttpVersion, String responseHttpVersion) {
            this.type = Type.RAW_TRAFFIC;
            this.timestamp = System.currentTimeMillis();
            this.request = null;
            this.response = null;
            this.sessionTag = sessionTag;
            this.source = source;
            this.method = method;
            this.url = url;
            this.host = host;
            this.headers = headers;
            this.body = body;
            this.responseHeaders = responseHeaders;
            this.responseBody = responseBody;
            this.statusCode = statusCode;
            this.requestHttpVersion = requestHttpVersion;
            this.responseHttpVersion = responseHttpVersion;
        }
        
        // Overloaded constructor for backward compatibility
        public TrafficItem(String method, String url, String host, String headers, String body,
                          String responseHeaders, String responseBody, Integer statusCode, 
                          String sessionTag, TrafficSource source) {
            this(method, url, host, headers, body, responseHeaders, responseBody, statusCode, 
                 sessionTag, source, null, null);
        }
    }
    
    /**
     * Constructor for TrafficQueue.
     * 
     * @param databaseService The database service for persistence
     * @param config The API configuration
     */
    public TrafficQueue(DatabaseService databaseService, ApiConfig config) {
        this.databaseService = databaseService;
        this.config = config;
        this.trafficQueue = new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE);
        this.processingExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "TrafficQueue-Processor");
            t.setDaemon(true); // Don't prevent JVM shutdown
            t.setPriority(Thread.NORM_PRIORITY - 1); // Lower priority than main threads
            return t;
        });
    }
    
    /**
     * Starts the traffic queue processing.
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("TrafficQueue already running");
            return;
        }
        
        logger.info("Starting TrafficQueue with capacity: {}, adaptive batch size: {}-{}", 
                   DEFAULT_QUEUE_SIZE, MIN_BATCH_SIZE, MAX_BATCH_SIZE);
        
        // Start background processing thread
        processingExecutor.submit(this::processQueue);
        
        logger.info("TrafficQueue started successfully");
    }
    
    /**
     * Set the event broadcaster for real-time WebSocket updates.
     */
    public void setEventBroadcaster(EventBroadcaster eventBroadcaster) {
        this.eventBroadcaster = eventBroadcaster;
        logger.info("[*] TrafficQueue WebSocket broadcasting enabled");
    }
    
    /**
     * Stops the traffic queue and processes remaining items.
     */
    public void stop() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("Stopping TrafficQueue...");
        running.set(false);
        
        // Process remaining items
        processRemainingItems();
        
        // Shutdown executor
        processingExecutor.shutdown();
        try {
            if (!processingExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("TrafficQueue processing did not terminate within 5 seconds, forcing shutdown");
                processingExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            processingExecutor.shutdownNow();
        }
        
        logger.info("TrafficQueue stopped. Final stats: queued={}, processed={}, dropped={}, errors={}", 
                   totalQueued.get(), totalProcessed.get(), totalDropped.get(), totalErrors.get());
    }
    
    /**
     * Queues a request for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param request The intercepted request
     */
    public void queueRequest(InterceptedRequest request) {
        if (shutdown.get()) {
            return;
        }
        
        TrafficItem item = new TrafficItem(request, config.getSessionTag());
        queueItem(item);
    }
    
    /**
     * Queues a response for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param response The intercepted response
     */
    public void queueResponse(InterceptedResponse response) {
        if (shutdown.get()) {
            return;
        }
        
        TrafficItem item = new TrafficItem(response, config.getSessionTag());
        queueItem(item);
    }
    
    /**
     * Queues raw traffic data for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers
     * @param responseBody Response body
     * @param statusCode Status code
     * @param sessionTag Session tag
     * @param source Traffic source
     */
    public void queueRawTraffic(String method, String url, String host, String headers, String body,
                               String responseHeaders, String responseBody, Integer statusCode,
                               String sessionTag, TrafficSource source) {
        queueRawTraffic(method, url, host, headers, body, responseHeaders, responseBody,
                        statusCode, sessionTag, source, -1L);
    }

    /**
     * As {@link #queueRawTraffic(String, String, String, String, String, String, String, Integer, String, TrafficSource)},
     * but records the {@code proxy_traffic.id} the same capture already wrote so
     * the normalized row can carry an exact link to the public id space (#28).
     */
    public void queueRawTraffic(String method, String url, String host, String headers, String body,
                               String responseHeaders, String responseBody, Integer statusCode,
                               String sessionTag, TrafficSource source, long proxyTrafficId) {
        if (shutdown.get()) {
            return;
        }

        TrafficItem item = new TrafficItem(method, url, host, headers, body,
                                         responseHeaders, responseBody, statusCode, sessionTag, source);
        item.proxyTrafficId = proxyTrafficId;
        queueItem(item);
    }
    
    /**
     * Internal method to queue an item with backpressure handling.
     */
    private void queueItem(TrafficItem item) {
        totalQueued.incrementAndGet();
        
        // Non-blocking offer - if queue is full, drop the item to prevent blocking Burp
        boolean queued = trafficQueue.offer(item);
        
        if (!queued) {
            totalDropped.incrementAndGet();
            
            // Log warning occasionally (not for every drop to avoid log spam)
            if (totalDropped.get() % 1000 == 1) {
                logger.warn("TrafficQueue full - dropping items. Total dropped: {}. " +
                           "Consider increasing queue size or database performance.", totalDropped.get());
            }
        }
        
        currentQueueSize = trafficQueue.size();
    }
    
    /**
     * Main processing loop that handles the traffic queue.
     */
    private void processQueue() {
        logger.info("Traffic queue processing started");
        
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                long processingStartTime = System.currentTimeMillis();
                
                // Check for project changes periodically
                checkForProjectChange();
                
                // Process batches with adaptive sizing for optimal performance
                List<TrafficItem> batch = new ArrayList<>();
                
                // ADAPTIVE BATCHING: Adjust batch size based on queue load
                int currentBatchSize = calculateOptimalBatchSize();
                
                // Collect items for batch processing (non-blocking)
                TrafficItem item;
                while (batch.size() < currentBatchSize && 
                       (item = trafficQueue.poll()) != null) {
                    batch.add(item);
                }
                
                if (!batch.isEmpty()) {
                    processBatch(batch);
                }
                
                // Update metrics
                lastProcessingTime = System.currentTimeMillis() - processingStartTime;
                currentQueueSize = trafficQueue.size();
                
                // Control processing rate
                if (lastProcessingTime < PROCESSING_INTERVAL_MS) {
                    Thread.sleep(PROCESSING_INTERVAL_MS - lastProcessingTime);
                }
                
            } catch (InterruptedException e) {
                logger.info("Traffic queue processing interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error in traffic queue processing", e);
                totalErrors.incrementAndGet();
                
                try {
                    Thread.sleep(1000); // Brief pause on error
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        logger.info("Traffic queue processing stopped");
    }
    
    /**
     * Checks for project changes and reinitializes database if needed.
     */
    private void checkForProjectChange() {
        long currentTime = System.currentTimeMillis();
        
        // Only check periodically to avoid overhead
        if (currentTime - lastProjectCheckTime < PROJECT_CHECK_INTERVAL_MS) {
            return;
        }
        
        lastProjectCheckTime = currentTime;
        
        // REMOVED: Project change checking was causing database instability
    }
    
    /**
     * Processes a batch of traffic items efficiently with optimized database operations.
     * Uses the new normalized schema when available for better performance.
     */
    private void processBatch(List<TrafficItem> batch) {
        if (batch.isEmpty() || shutdown.get() || databaseService == null || !databaseService.isInitialized()) {
            return;
        }
        
        long startTime = System.currentTimeMillis();
        int processed = 0;
        int errors = 0;
        int duplicates = 0;
        
        try {
            // Persist the whole batch in a SINGLE write transaction (one commit,
            // one connection lease) instead of one transaction per item, which is
            // the fix for the multi-second batch stalls. Results are positionally
            // aligned with `batch`.
            long[] results = databaseService.storeQueuedBatch(batch);

            for (int i = 0; i < batch.size(); i++) {
                TrafficItem item = batch.get(i);
                long result = results[i];

                if (result == -2) {
                    duplicates++; // Duplicate content hash, not an error
                    continue;
                }
                if (result < 0) {
                    errors++;
                    continue;
                }

                processed++;

                // Only RAW_TRAFFIC carries a broadcastable traffic_meta id; for
                // REQUEST/RESPONSE `result` is just a success sentinel.
                if (item.type == TrafficItem.Type.RAW_TRAFFIC && eventBroadcaster != null) {
                    // Broadcast new traffic event to WebSocket clients.
                    // `id` carries the public proxy_traffic.id so WS clients
                    // address traffic in the same id space the REST read
                    // endpoints hand out; `result` is the internal
                    // traffic_meta.id, kept as traffic_meta_id (#21).
                    Map<String, Object> trafficData = new HashMap<>();
                    boolean replayable = item.proxyTrafficId > 0;
                    trafficData.put("id", replayable ? item.proxyTrafficId : null);
                    trafficData.put("traffic_meta_id", result);
                    trafficData.put("replayable", replayable);
                    trafficData.put("method", item.method);
                    trafficData.put("url", item.url);
                    trafficData.put("host", item.host);
                    trafficData.put("status_code", item.statusCode);
                    trafficData.put("timestamp", item.timestamp);
                    trafficData.put("tool_source", item.source.toString());
                    trafficData.put("body_size", item.body != null ? item.body.length() : 0);

                    eventBroadcaster.broadcastTrafficCapture(trafficData, item.sessionTag);
                }
            }

            // Update performance metrics
            totalProcessed.addAndGet(processed);
            if (errors > 0) {
                totalErrors.addAndGet(errors);
            }
            
            long processingTime = System.currentTimeMillis() - startTime;
            
            // Enhanced logging with duplicate tracking
            if (totalProcessed.get() % 1000 == 0) {
                logger.debug("TrafficQueue stats: processed={}, queue_size={}, processing_time={}ms, errors={}, duplicates_skipped={}", 
                           processed, currentQueueSize, processingTime, errors, duplicates);
            }
            
            // Log performance warnings
            if (processingTime > MAX_PROCESSING_TIME_MS) {
                logger.warn("Batch processing exceeded time limit: {}ms (target: {}ms)", 
                           processingTime, MAX_PROCESSING_TIME_MS);
            }
            
            // Log efficiency metrics
            if (processed > 0) {
                double itemsPerSecond = (processed * 1000.0) / processingTime;
                if (itemsPerSecond < 50) { // Less than 50 items/second is slow
                    // SLF4J uses {} placeholders, not Python-style {:.1f}; format first.
                    logger.warn("Slow batch processing: {} items/second", String.format("%.1f", itemsPerSecond));
                }
            }
            
        } catch (Exception e) {
            logger.error("Error processing traffic batch", e);
            totalErrors.incrementAndGet();
        }
    }
    
    /**
     * Processes remaining items during shutdown.
     */
    private void processRemainingItems() {
        if (trafficQueue.isEmpty()) {
            return;
        }
        
        logger.info("Processing {} remaining traffic items...", trafficQueue.size());
        
        int processed = 0;
        long startTime = System.currentTimeMillis();
        
        // Process items in batches
        while (!trafficQueue.isEmpty() && System.currentTimeMillis() - startTime < 5000) {
            List<TrafficItem> batch = new ArrayList<>();
            
            // Collect batch
            int emergencyBatchSize = calculateOptimalBatchSize();
            for (int i = 0; i < emergencyBatchSize && !trafficQueue.isEmpty(); i++) {
                TrafficItem item = trafficQueue.poll();
                if (item != null) {
                    batch.add(item);
                }
            }
            
            if (!batch.isEmpty()) {
                processBatch(batch);
                processed += batch.size();
            }
        }
        
        logger.info("📋 Processed {} remaining items in {}ms", processed, System.currentTimeMillis() - startTime);
        
        if (!trafficQueue.isEmpty()) {
            logger.warn("{} traffic items were not processed during shutdown (timeout)", trafficQueue.size());
        }
    }
    
    /**
     * Gets current queue performance metrics.
     * 
     * @return Map with performance metrics
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        metrics.put("running", running.get());
        metrics.put("total_queued", totalQueued.get());
        metrics.put("total_processed", totalProcessed.get());
        metrics.put("total_dropped", totalDropped.get());
        metrics.put("total_errors", totalErrors.get());
        metrics.put("current_queue_size", currentQueueSize);
        metrics.put("queue_capacity", DEFAULT_QUEUE_SIZE);
        metrics.put("queue_utilization_percent", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE);
        metrics.put("last_processing_time_ms", lastProcessingTime);
        metrics.put("adaptive_batch_size_range", MIN_BATCH_SIZE + "-" + MAX_BATCH_SIZE);
        metrics.put("current_batch_size", calculateOptimalBatchSize());
        metrics.put("processing_interval_ms", PROCESSING_INTERVAL_MS);
        
        // Calculate processing rate
        long processed = totalProcessed.get();
        long queued = totalQueued.get();
        if (queued > 0) {
            metrics.put("processing_success_rate_percent", (processed * 100.0) / queued);
        } else {
            metrics.put("processing_success_rate_percent", 100.0);
        }
        
        return metrics;
    }
    
    /**
     * ADAPTIVE BATCHING: Calculate optimal batch size based on current load.
     * Optimizes for WAL mode performance characteristics.
     * 
     * @return optimal batch size between MIN_BATCH_SIZE and MAX_BATCH_SIZE
     */
    private int calculateOptimalBatchSize() {
        int queueSize = trafficQueue.size();
        
        // LOW LOAD: Use small batches for low latency (real-time feeling)
        if (queueSize < 10) {
            return MIN_BATCH_SIZE;  // 50 items - fast processing
        }
        
        // MEDIUM LOAD: Use adaptive batching for balanced performance  
        if (queueSize < 1000) {
            // Scale linearly: 50 + (queueSize * 0.25)
            return Math.min(MAX_BATCH_SIZE, MIN_BATCH_SIZE + (queueSize / 4));
        }
        
        // HIGH LOAD: Use large batches for maximum throughput
        return MAX_BATCH_SIZE;  // 500 items - bulk processing efficiency
    }
    
    /**
     * Checks if the queue is healthy (not dropping too many items).
     * 
     * @return true if queue is healthy, false if experiencing issues
     */
    public boolean isHealthy() {
        long queued = totalQueued.get();
        long dropped = totalDropped.get();
        
        if (queued == 0) {
            return true; // No traffic yet
        }
        
        double dropRate = (dropped * 100.0) / queued;
        return dropRate < 5.0; // Healthy if dropping less than 5% of items
    }
    
    /**
     * Gets queue health status with details.
     * 
     * @return Map with health status and details
     */
    public Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        
        boolean healthy = isHealthy();
        health.put("healthy", healthy);
        health.put("running", running.get());
        health.put("queue_utilization_percent", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE);
        
        if (!healthy) {
            health.put("issues", List.of(
                "High drop rate detected - queue may be overloaded",
                "Consider optimizing database performance or increasing queue capacity"
            ));
        }
        
        if (currentQueueSize > DEFAULT_QUEUE_SIZE * 0.8) {
            health.put("warnings", List.of(
                "Queue utilization high (" + String.format("%.1f", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE) + "%)",
                "Monitor for potential dropping of traffic items"
            ));
        }
        
        return health;
    }
} 