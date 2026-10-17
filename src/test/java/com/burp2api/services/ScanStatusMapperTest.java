package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Ticket #13: {@code /scanner/tasks/{id}} must report Burp's real state instead
 * of a frozen literal {@code PENDING}. The mapping from a live audit's
 * {@code statusMessage()} + {@code requestCount()} to a normalized state is the
 * load-bearing logic and is unit-tested here with no Montoya or DB dependency.
 */
class ScanStatusMapperTest {

    @Test
    void pendingWhenNoTrafficAndNoTerminalMessage() {
        // Burp's early "Waiting to start" (or empty) message, zero requests.
        assertThat(ScanStatusMapper.deriveState("Waiting to start", 0))
            .isEqualTo(ScanStatusMapper.PENDING);
        assertThat(ScanStatusMapper.deriveState(null, 0))
            .isEqualTo(ScanStatusMapper.PENDING);
        assertThat(ScanStatusMapper.deriveState("", 0))
            .isEqualTo(ScanStatusMapper.PENDING);
    }

    @Test
    void runningOnceAuditTrafficHasStarted() {
        // requestCount > 0 is the robust "audit traffic started" signal, even if
        // the status message wording is unknown on this Burp build.
        assertThat(ScanStatusMapper.deriveState("Auditing", 42))
            .isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(ScanStatusMapper.deriveState("", 1))
            .isEqualTo(ScanStatusMapper.RUNNING);
    }

    @Test
    void doneWhenMessageIndicatesCompletion() {
        // Terminal message wins even though requestCount stays > 0.
        assertThat(ScanStatusMapper.deriveState("Audit finished.", 644))
            .isEqualTo(ScanStatusMapper.DONE);
        assertThat(ScanStatusMapper.deriveState("Completed", 10))
            .isEqualTo(ScanStatusMapper.DONE);
        assertThat(ScanStatusMapper.deriveState("Audit succeeded", 10))
            .isEqualTo(ScanStatusMapper.DONE);
    }

    @Test
    void cancelledAndPausedAndErroredMessagesMapToTerminalOrPausedStates() {
        assertThat(ScanStatusMapper.deriveState("Cancelled", 5))
            .isEqualTo(ScanStatusMapper.CANCELLED);
        assertThat(ScanStatusMapper.deriveState("Paused", 5))
            .isEqualTo(ScanStatusMapper.PAUSED);
        assertThat(ScanStatusMapper.deriveState("Audit failed", 5))
            .isEqualTo(ScanStatusMapper.ERRORED);
    }

    @Test
    void mappingIsCaseInsensitiveAndTrimmed() {
        assertThat(ScanStatusMapper.deriveState("  AUDIT FINISHED.  ", 1))
            .isEqualTo(ScanStatusMapper.DONE);
    }

    @Test
    void stalledOnlyWhenPendingWithNoTrafficPastThreshold() {
        long threshold = 60_000L;
        // Pending, no traffic, past threshold -> stalled (queued behind other work).
        assertThat(ScanStatusMapper.isStalled(
            ScanStatusMapper.PENDING, 0, 61_000L, threshold)).isTrue();
        // Not yet past threshold.
        assertThat(ScanStatusMapper.isStalled(
            ScanStatusMapper.PENDING, 0, 59_000L, threshold)).isFalse();
        // Traffic started -> not stalled, it is progressing.
        assertThat(ScanStatusMapper.isStalled(
            ScanStatusMapper.PENDING, 3, 120_000L, threshold)).isFalse();
        // Running is never "stalled".
        assertThat(ScanStatusMapper.isStalled(
            ScanStatusMapper.RUNNING, 0, 120_000L, threshold)).isFalse();
    }

    @Test
    void auditTrafficStartedTracksRequestCount() {
        assertThat(ScanStatusMapper.auditTrafficStarted(0)).isFalse();
        assertThat(ScanStatusMapper.auditTrafficStarted(1)).isTrue();
    }
}
