package com.sslteam.client.tls.transport;

/**
 * Represents a TLS policy or handshake failure at the CLI transport boundary.
 *
 * <p>The bounded message is suitable for operator output and intentionally excludes exception
 * details, certificate bodies, credentials, and request/response data. The original throwable is
 * retained for diagnostic logging by the boundary. Certificate, hostname, and trust failures are
 * non-retryable and never trigger a weaker trust mode or an authenticated retry.</p>
 */
public final class TlsTransportException extends IllegalStateException {

    /**
     * Creates a bounded non-retryable TLS transport failure.
     *
     * @param message operator-safe explanation without sensitive material
     * @param cause original JSSE failure retained for diagnostics
     */
    public TlsTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
