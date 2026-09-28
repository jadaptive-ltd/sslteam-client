package com.jadaptive.sslteam.client.tls.origin;

/**
 * Reports an invalid or ambiguous server origin before TLS or HTTP transport begins.
 * No network, credential, trust-store, or persistence operation is performed when this
 * exception is created.
 */
public final class TlsOriginException extends IllegalArgumentException {

    /**
     * Creates an origin-policy failure with a bounded operator-safe explanation.
     *
     * @param message explanation that must not contain certificate or credential material
     */
    public TlsOriginException(String message) {
        super(message);
    }

    /**
     * Creates an origin parsing failure while retaining the parser cause for diagnostics.
     *
     * @param message bounded operator-safe explanation
     * @param cause original URI parsing failure
     */
    public TlsOriginException(String message, Throwable cause) {
        super(message, cause);
    }

}
