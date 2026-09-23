package com.sslteam.client.tls.discovery;

/**
 * Reports a bounded failure while discovering a server certificate over a TLS-only connection.
 * The cause is retained for diagnostic logging; certificate bodies, credentials, and raw transport
 * data are never included in the message.
 */
public final class TlsDiscoveryException extends IllegalStateException {

    /**
     * Creates an operator-safe discovery failure.
     *
     * @param message bounded explanation without certificate or transport contents
     */
    public TlsDiscoveryException(String message) {
        super(message);
    }

    /**
     * Creates an operator-safe discovery failure while retaining diagnostics.
     *
     * @param message bounded explanation without certificate or transport contents
     * @param cause underlying TLS or socket failure
     */
    public TlsDiscoveryException(String message, Throwable cause) {
        super(message, cause);
    }

}
