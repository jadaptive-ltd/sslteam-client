package com.jadaptive.sslteam.client.tls.profile;

/**
 * Mutually exclusive trust selection for one complete server origin.
 *
 * <p>The mode selects a future TLS trust context; it does not itself perform a handshake,
 * load a file, or authorize an HTTP request.</p>
 */
public enum TlsTrustMode {
    /** Use the normal JVM/system trust configuration. */
    SYSTEM,
    /** Trust only the operator-approved public certificate for the origin. */
    TOFU,
    /** Trust public certificates loaded from the explicitly configured PEM path. */
    TRUST_STORE
}
