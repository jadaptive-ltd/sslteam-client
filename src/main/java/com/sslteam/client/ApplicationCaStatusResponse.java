package com.sslteam.client;

import java.time.Instant;

public record ApplicationCaStatusResponse(
        Scope scope,
        String familyStatus,
        String setupState,
        boolean applicationCaReady,
        boolean leafIssuanceReady,
        int leafMaxValidityDays,
        long familyVersion,
        Instant rootNotBefore,
        Instant rootNotAfter) {

    public record Scope(String team, String environment) {
    }
}