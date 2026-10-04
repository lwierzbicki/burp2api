package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.api.montoya.scanner.audit.Audit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Ticket #13: the live-progress snapshot built from a Montoya {@code Audit}
 * handle must derive real state, surface the stall/traffic signals, and never
 * blow up when an accessor throws {@code UnsupportedOperationException}. Cancel
 * must use the real {@code delete()} primitive.
 */
class ScanTaskProgressTest {

    @Test
    void pendingAuditWithNoTrafficIsStalledPastThreshold() {
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenReturn("Waiting to start");
        when(audit.requestCount()).thenReturn(0);
        when(audit.errorCount()).thenReturn(0);
        when(audit.insertionPointCount()).thenReturn(0);
        when(audit.issues()).thenReturn(List.of());

        Map<String, Object> p = ScanTaskManager.auditProgress(audit, 200_000L);

        assertThat(p.get("state")).isEqualTo(ScanStatusMapper.PENDING);
        assertThat(p.get("audit_traffic_started")).isEqualTo(false);
        assertThat(p.get("stalled")).isEqualTo(true);
        assertThat(p.get("request_count")).isEqualTo(0);
    }

    @Test
    void runningAuditReportsTrafficStartedAndNotStalled() {
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenReturn("Auditing");
        when(audit.requestCount()).thenReturn(644);
        when(audit.errorCount()).thenReturn(2);
        when(audit.insertionPointCount()).thenReturn(12);
        when(audit.issues()).thenReturn(List.of());

        Map<String, Object> p = ScanTaskManager.auditProgress(audit, 300_000L);

        assertThat(p.get("state")).isEqualTo(ScanStatusMapper.RUNNING);
        assertThat(p.get("audit_traffic_started")).isEqualTo(true);
        assertThat(p.get("stalled")).isEqualTo(false);
        assertThat(p.get("request_count")).isEqualTo(644);
        assertThat(p.get("error_count")).isEqualTo(2);
        assertThat(p.get("insertion_points")).isEqualTo(12);
    }

    @Test
    void finishedAuditIsDone() {
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenReturn("Audit finished.");
        when(audit.requestCount()).thenReturn(644);
        when(audit.errorCount()).thenReturn(0);
        when(audit.insertionPointCount()).thenReturn(12);
        when(audit.issues()).thenReturn(List.of());

        Map<String, Object> p = ScanTaskManager.auditProgress(audit, 500_000L);

        assertThat(p.get("state")).isEqualTo(ScanStatusMapper.DONE);
    }

    @Test
    void guardedAccessorsNeverThrow() {
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenThrow(new UnsupportedOperationException());
        when(audit.requestCount()).thenThrow(new UnsupportedOperationException());
        when(audit.errorCount()).thenThrow(new UnsupportedOperationException());
        when(audit.insertionPointCount()).thenThrow(new UnsupportedOperationException());
        when(audit.issues()).thenThrow(new UnsupportedOperationException());

        Map<String, Object> p = ScanTaskManager.auditProgress(audit, 10_000L);

        // Falls back to defaults and stays PENDING rather than propagating.
        assertThat(p.get("state")).isEqualTo(ScanStatusMapper.PENDING);
        assertThat(p.get("request_count")).isEqualTo(0);
        assertThat(p.get("error_count")).isEqualTo(0);
        assertThat(p.get("issues_found")).isEqualTo(0);
    }

    @Test
    void deleteLiveTaskCancelsViaMontoyaDelete() {
        Audit audit = mock(Audit.class);

        ScanTaskManager.deleteLiveTask(audit, null);

        verify(audit).delete();
    }

    @Test
    void deleteLiveTaskSwallowsDeleteFailure() {
        Audit audit = mock(Audit.class);
        doThrow(new UnsupportedOperationException()).when(audit).delete();

        // Must not propagate.
        ScanTaskManager.deleteLiveTask(audit, null);

        verify(audit).delete();
    }
}
