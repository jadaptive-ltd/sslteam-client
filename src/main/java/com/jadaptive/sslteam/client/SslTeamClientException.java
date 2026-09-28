package com.jadaptive.sslteam.client;

/**
 * Base unchecked failure for the portable SSLTeam client API.
 *
 * <p>Messages are bounded and must not contain tokens, passwords, private keys, certificate or
 * CSR bodies, raw request bodies, raw response bodies, or stack traces.</p>
 */
public class SslTeamClientException extends RuntimeException {

    public SslTeamClientException(String message) {
        super(message);
    }

    public SslTeamClientException(String message, Throwable cause) {
        super(message, cause);
    }
}