package com.burp2api.services;

/**
 * Pure mapping from a live Montoya scan task's observable signals
 * ({@code statusMessage()} + {@code requestCount()}) to a normalized,
 * caller-facing state. Extracted as a dependency-free class so ticket #13's
 * status derivation is unit-testable without Montoya, a database, or a live
 * Burp scanner.
 *
 * <p>The status message wording is Burp/version dependent, so
 * {@code requestCount() > 0} is treated as the robust "audit traffic started"
 * signal for RUNNING; the message only refines terminal/paused states.
 */
public final class ScanStatusMapper {

    public static final String PENDING = "PENDING";
    public static final String RUNNING = "RUNNING";
    public static final String DONE = "DONE";
    public static final String PAUSED = "PAUSED";
    public static final String CANCELLED = "CANCELLED";
    public static final String ERRORED = "ERRORED";

    private ScanStatusMapper() {
    }

    /**
     * Derive the normalized state. Terminal/paused messages win over request
     * count; otherwise any observed request means the audit is RUNNING.
     */
    public static String deriveState(String statusMessage, int requestCount) {
        String msg = statusMessage == null ? "" : statusMessage.trim().toLowerCase();

        if (msg.contains("cancel")) {
            return CANCELLED;
        }
        if (msg.contains("fail")) {
            return ERRORED;
        }
        if (msg.contains("paus")) {
            return PAUSED;
        }
        if (msg.contains("finish") || msg.contains("complete") || msg.contains("succeed")) {
            return DONE;
        }
        if (requestCount > 0) {
            return RUNNING;
        }
        return PENDING;
    }

    /** Whether any audit request has been sent yet. */
    public static boolean auditTrafficStarted(int requestCount) {
        return requestCount > 0;
    }

    /**
     * A task is "stalled" when it is still PENDING with zero audit traffic after
     * the threshold has elapsed — the tell that it is queued behind other work
     * (e.g. a prior large scan on a memory-starved JVM) rather than merely slow.
     */
    public static boolean isStalled(String state, int requestCount, long elapsedMs, long thresholdMs) {
        return PENDING.equals(state) && requestCount <= 0 && elapsedMs > thresholdMs;
    }
}
