package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.api.montoya.scope.Scope;
import org.junit.jupiter.api.Test;

/**
 * Ticket #13: before starting an active scan, burp2api must ensure the target is
 * in Burp's scope. With an empty/excluding scope, {@code startAudit()} is
 * silently accepted but sends zero payload variations (confirmed live during
 * T-026). The preflight either confirms scope, adds it, or blocks the scan.
 */
class ScopePreflightTest {

    @Test
    void alreadyInScopeDoesNotModifyScope() {
        Scope scope = mock(Scope.class);
        when(scope.isInScope("https://t/")).thenReturn(true);

        ScopePreflight.Decision decision = ScopePreflight.decide(scope, "https://t/", true);

        assertThat(decision).isEqualTo(ScopePreflight.Decision.ALREADY_IN_SCOPE);
        verify(scope, never()).includeInScope("https://t/");
    }

    @Test
    void outOfScopeWithAutoScopeAddsTarget() {
        Scope scope = mock(Scope.class);
        when(scope.isInScope("https://t/")).thenReturn(false);

        ScopePreflight.Decision decision = ScopePreflight.decide(scope, "https://t/", true);

        assertThat(decision).isEqualTo(ScopePreflight.Decision.ADDED);
        verify(scope).includeInScope("https://t/");
    }

    @Test
    void outOfScopeWithoutAutoScopeBlocksAndLeavesScopeUnchanged() {
        Scope scope = mock(Scope.class);
        when(scope.isInScope("https://t/")).thenReturn(false);

        ScopePreflight.Decision decision = ScopePreflight.decide(scope, "https://t/", false);

        assertThat(decision).isEqualTo(ScopePreflight.Decision.BLOCKED);
        verify(scope, never()).includeInScope("https://t/");
    }
}
