package com.sslteam.client;

/**
 * OAuth token response returned by the SSLTeam server.
 *
 * <p>Token values are credentials. Callers must keep them in ephemeral protected storage and
 * must never log or persist this record without an explicit secure storage policy.</p>
 */
public record AuthTokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        String refreshToken,
        long refreshExpiresIn,
        boolean passwordChangeRequired) {
}