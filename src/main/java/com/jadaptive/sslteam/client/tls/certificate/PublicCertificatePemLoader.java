package com.jadaptive.sslteam.client.tls.certificate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Loads bounded public X.509 certificates from an explicitly selected PEM file.
 *
 * <p>This is the trust-store input boundary for the CLI. It accepts one or more public
 * {@code CERTIFICATE} PEM blocks, rejects private-key markers and non-X.509 material, and never
 * reads a password or sends a request. The returned certificates are later used as trust anchors
 * by a standard {@code TrustManagerFactory}; this loader does not approve a server, disable
 * hostname verification, or mutate persisted configuration.</p>
 */
public final class PublicCertificatePemLoader {

    private static final long MAX_FILE_BYTES = 1_048_576L;

    /**
     * Reads and validates all public X.509 certificates in a bounded PEM file.
     *
     * @param path explicit local PEM trust-store path
     * @return immutable list of parsed public certificates in file order
     * @throws TlsCertificateException if the path is missing, oversized, secret-bearing, malformed,
     *                                 or does not contain a public X.509 certificate
     */
    public List<X509Certificate> load(Path path) {
        if (path == null || path.toString().isBlank()) {
            throw new TlsCertificateException("A public PEM trust-store path is required.");
        }
        Path normalized = path.toAbsolutePath().normalize();
        try {
            if (!Files.isRegularFile(normalized)) {
                throw new TlsCertificateException("The configured PEM trust store is not a regular file.");
            }
            if (Files.size(normalized) > MAX_FILE_BYTES) {
                throw new TlsCertificateException("The configured PEM trust store exceeds the supported size limit.");
            }
            String pem = Files.readString(normalized);
            rejectSecretMaterial(pem);
            List<X509Certificate> certificates = parseCertificates(pem);
            if (certificates.isEmpty()) {
                throw new TlsCertificateException("The PEM trust store contains no public X.509 certificates.");
            }
            return List.copyOf(certificates);
        } catch (IOException exception) {
            throw new TlsCertificateException("Unable to read the configured PEM trust store.", exception);
        }
    }

    private static List<X509Certificate> parseCertificates(String pem) {
        try (InputStream input = new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> parsed = factory.generateCertificates(input);
            List<X509Certificate> certificates = new ArrayList<>(parsed.size());
            for (Certificate certificate : parsed) {
                if (!(certificate instanceof X509Certificate x509)) {
                    throw new TlsCertificateException("The PEM trust store contains a non-X.509 certificate.");
                }
                certificates.add(x509);
            }
            return certificates;
        } catch (CertificateException | IOException exception) {
            throw new TlsCertificateException("The PEM trust store is malformed or unsupported.", exception);
        }
    }

    private static void rejectSecretMaterial(String pem) {
        String upper = pem.toUpperCase(java.util.Locale.ROOT);
        if (upper.contains("PRIVATE KEY") || upper.contains("BEGIN ENCRYPTED")
                || upper.contains("BEGIN RSA ") || upper.contains("BEGIN EC ")) {
            throw new TlsCertificateException("The PEM trust store must contain public certificates only.");
        }
    }
}
