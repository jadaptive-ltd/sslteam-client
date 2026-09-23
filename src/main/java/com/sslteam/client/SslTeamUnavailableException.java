package com.sslteam.client;

/**
 * Indicates that a retryable SSLTeam request could not reach the server.
 */
public final class SslTeamUnavailableException extends SslTeamClientException {

    private final int permittedAttempts;

    public SslTeamUnavailableException(int permittedAttempts, Throwable cause) {
        super("Could not connect to the SSLTeam server after " + permittedAttempts + " attempt"
                + (permittedAttempts == 1 ? "" : "s") + ".", cause);
        this.permittedAttempts = permittedAttempts;
    }

    public int permittedAttempts() {
        return permittedAttempts;
    }
}