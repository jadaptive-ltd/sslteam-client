package com.sslteam.client.tls.discovery;

import com.sslteam.client.tls.certificate.CertificateFingerprint;
import com.sslteam.client.tls.origin.TlsOrigin;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Ephemeral public result of TLS certificate discovery for one normalized origin.
 *
 * <p>The certificate is retained only in memory so the operator can approve its DER fingerprint.
 * This result is not persisted, contains no credentials, and cannot perform HTTP I/O.</p>
 *
 * @param origin normalized HTTPS origin contacted during discovery
 * @param leafCertificate public leaf certificate returned by the TLS peer
 */
public record TlsDiscoveryResult(TlsOrigin origin, X509Certificate leafCertificate) {

    /**
     * Validates the discovery result and rejects absent public certificate material.
     *
     * @param origin normalized origin associated with the handshake
     * @param leafCertificate public leaf certificate
     */
    public TlsDiscoveryResult {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(leafCertificate, "leafCertificate");
    }

    /**
     * Returns the canonical SHA-256 fingerprint of the discovered DER certificate.
     *
     * @return upper-case hexadecimal fingerprint suitable for explicit approval
     */
    public String sha256Fingerprint() {
        return CertificateFingerprint.sha256(leafCertificate);
    }

    /**
     * Returns bounded public subject metadata for operator display.
     *
     * @return subject distinguished name, bounded to avoid unbounded terminal output
     */
    public String subject() {
        String value = leafCertificate.getSubjectX500Principal().getName();
        return value.length() > 256 ? value.substring(0, 256) + "…" : value;
    }
}
