package com.jadaptive.sslteam.client.tls.profile;

/**
 * Reports a conflicting or incomplete origin-scoped trust profile before TLS transport begins.
 * The exception intentionally contains no certificate body, private key, credential, or file
 * contents.
 */
public final class TlsTrustProfileException extends IllegalArgumentException {

    /**
     * Creates a bounded configuration failure.
     *
     * @param message operator-safe explanation of the invalid profile
     */
    public TlsTrustProfileException(String message) {
        super(message);
    }

}
