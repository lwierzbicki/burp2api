package com.burp2api.services;

import burp.api.montoya.scope.Scope;

/**
 * Ticket #13: scope preflight for active scans. An audit started via the Montoya
 * API against an out-of-scope target is silently accepted (it even appears on
 * the Dashboard) but sends <em>zero</em> payload variations — no error, no
 * warning. This decides whether to confirm existing scope, add the target, or
 * block the scan so the caller is never left waiting on a scan that does
 * nothing. Kept pure (only the injected {@link Scope}) so it is unit-testable.
 */
public final class ScopePreflight {

    public enum Decision {
        /** Target was already in scope; scope left unchanged. */
        ALREADY_IN_SCOPE,
        /** Target was out of scope and has been added (auto_scope). */
        ADDED,
        /** Target is out of scope and auto_scope is off; do not start the scan. */
        BLOCKED
    }

    private ScopePreflight() {
    }

    public static Decision decide(Scope scope, String url, boolean autoScope) {
        if (scope.isInScope(url)) {
            return Decision.ALREADY_IN_SCOPE;
        }
        if (autoScope) {
            scope.includeInScope(url);
            return Decision.ADDED;
        }
        return Decision.BLOCKED;
    }
}
