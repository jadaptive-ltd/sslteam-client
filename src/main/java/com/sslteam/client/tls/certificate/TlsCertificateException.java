package com.sslteam.client.tls.certificate;

/**
 * Reports unsafe, malformed, or unavailable public certificate material before trust configuration
 * or transport begins. Messages are bounded and must not contain certificate bodies, private keys,
 * credentials, or raw file contents; the cause is retained for diagnostic logging at the boundary.
 */
public final class TlsCertificateException extends IllegalArgumentException {

    /**
     * Creates an operator-safe certificate-material failure.
     *
     * @param message bounded explanation that excludes certificate and secret material
     */
    public TlsCertificateException(String message) {
        super(message);
    }

    /**
     * Creates an operator-safe failure while retaining the implementation cause for diagnostics.
     *
     * @param message bounded explanation that excludes certificate and secret material
     * @param cause original parsing or file-system failure
     */
    public TlsCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

}
