package com.jadaptive.sslteam.client.tls.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jadaptive.sslteam.client.tls.certificate.CertificateFingerprint;
import com.jadaptive.sslteam.client.tls.certificate.PublicCertificatePemLoader;
import com.jadaptive.sslteam.client.tls.certificate.TlsCertificateException;
import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import com.jadaptive.sslteam.client.tls.profile.TlsTrustProfile;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.net.ssl.SSLParameters;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies client trust-context policy before any authenticated CLI request. Fixtures are public,
 * locally generated X.509 certificates: PEM loading proves public-material and secret rejection,
 * the trust manager proves exact trust selection, and SSL parameters prove hostname policy remains
 * enabled. These are deterministic unit tests; they do not open a socket or claim a live TLS
 * handshake, certificate capture, or server hostname verification result.
 */
class TlsTrustContextFactoryTest {

    @TempDir
    Path tempDir;

    @Test
    void systemContextEnablesHttpsEndpointIdentification() {
        // Given an exact HTTPS origin with the JVM/system trust mode.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");

        // When a per-profile context is created.
        TlsTrustContext context = new TlsTrustContextFactory().create(TlsTrustProfile.system(origin));

        // Then standard system trust is selected and hostname/SAN verification is explicitly enabled.
        SSLParameters parameters = context.sslParameters();
        assertEquals("HTTPS", parameters.getEndpointIdentificationAlgorithm());
        assertEquals("TLS", context.sslContext().getProtocol());
    }

    @Test
    void trustStoreContextLoadsOnlyPublicCertificatesAndUsesThemAsAnchors() throws Exception {
        // Given two public X.509 certificates in one explicit PEM trust store.
        GeneratedCertificate first = certificate("first-root", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        GeneratedCertificate second = certificate("second-root", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        Path trustStore = tempDir.resolve("public-roots.pem");
        Files.writeString(trustStore, pem(first.certificate()) + pem(second.certificate()));
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");

        // When the explicit public trust store is converted into a scoped TLS context.
        TlsTrustContext context = new TlsTrustContextFactory().create(TlsTrustProfile.trustStore(origin, trustStore));

        // Then both configured public anchors are accepted by the standard trust-manager path.
        context.trustManager().checkServerTrusted(new X509Certificate[]{first.certificate()}, "ECDHE_ECDSA");
        context.trustManager().checkServerTrusted(new X509Certificate[]{second.certificate()}, "ECDHE_ECDSA");
        assertEquals("HTTPS", context.sslParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    void tofuContextAcceptsOnlyTheApprovedCertificateFingerprint() throws Exception {
        // Given an approved public certificate fingerprint and a different presented certificate.
        GeneratedCertificate approved = certificate("approved", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        GeneratedCertificate different = certificate("different", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");
        TlsTrustProfile profile = TlsTrustProfile.tofu(origin, CertificateFingerprint.sha256(approved.certificate()));

        // When the scoped TOFU trust manager evaluates each presented chain.
        TlsTrustContext context = new TlsTrustContextFactory().create(profile);

        // Then only the exact approved leaf identity is accepted, without a fallback trust mode.
        context.trustManager().checkServerTrusted(new X509Certificate[]{approved.certificate()}, "ECDHE_ECDSA");
        assertThrows(CertificateException.class,
                () -> context.trustManager().checkServerTrusted(new X509Certificate[]{different.certificate()}, "ECDHE_ECDSA"));
        assertThrows(CertificateException.class,
                () -> context.trustManager().checkServerTrusted(new X509Certificate[0], "ECDHE_ECDSA"));
    }

    @Test
    void pemLoaderRejectsMalformedAndSecretBearingTrustStores() throws Exception {
        // Given files that do not contain only public X.509 certificate PEM blocks.
        Path malformed = tempDir.resolve("malformed.pem");
        Files.writeString(malformed, "not a certificate");
        Path privateKey = tempDir.resolve("private-key.pem");
        Files.writeString(privateKey, "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n");
        PublicCertificatePemLoader loader = new PublicCertificatePemLoader();

        // Then the input boundary fails closed without parsing or exposing secret material.
        assertThrows(TlsCertificateException.class, () -> loader.load(malformed));
        assertThrows(TlsCertificateException.class, () -> loader.load(privateKey));
    }

    @Test
    void tofuContextRejectsExpiredApprovedCertificate() throws Exception {
        // Given an expired certificate whose fingerprint is otherwise the configured TOFU pin.
        GeneratedCertificate expired = certificate("expired", Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");
        TlsTrustContext context = new TlsTrustContextFactory().create(
                TlsTrustProfile.tofu(origin, CertificateFingerprint.sha256(expired.certificate())));

        // Then certificate validity remains enforced instead of allowing an expired pinned identity.
        assertThrows(CertificateException.class,
                () -> context.trustManager().checkServerTrusted(new X509Certificate[]{expired.certificate()}, "ECDHE_ECDSA"));
    }

    private static GeneratedCertificate certificate(String commonName, Instant notBefore, Instant notAfter) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=" + commonName);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(Math.abs(new SecureRandom().nextLong()) + 1),
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        certificate.verify(keyPair.getPublic());
        return new GeneratedCertificate(keyPair, certificate);
    }

    private static String pem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }

    private record GeneratedCertificate(KeyPair keyPair, X509Certificate certificate) {
    }
}
