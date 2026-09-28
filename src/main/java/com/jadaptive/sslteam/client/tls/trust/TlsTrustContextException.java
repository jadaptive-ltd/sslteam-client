package com.jadaptive.sslteam.client.tls.trust;

/**
 * Reports failure to construct a scoped TLS trust context before an HTTP request is sent. The
 * message is operator-safe; the cause is retained for throwable-aware diagnostic logging and may
 * contain provider details that must not be returned directly to a user.
 */
public final class TlsTrustContextException extends IllegalStateException {

    /**
     * Creates a bounded trust-context failure.
     *
     * @param message operator-safe explanation without certificate bodies or secrets
     */
    public TlsTrustContextException(String message) {
        super(message);
    }

    /**
     * Creates a bounded trust-context failure while retaining the provider cause.
     *
     * @param message operator-safe explanation without certificate bodies or secrets
     * @param cause original JSSE or trust-store failure
     */
    public TlsTrustContextException(String message, Throwable cause) {
        super(message, cause);
    }

}
