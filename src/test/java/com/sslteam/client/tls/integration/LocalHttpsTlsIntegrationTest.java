package com.sslteam.client.tls.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sslteam.client.tls.certificate.CertificateFingerprint;
import com.sslteam.client.tls.discovery.CertificateDiscovery;
import com.sslteam.client.tls.discovery.TlsDiscoveryResult;
import com.sslteam.client.tls.discovery.TlsDiscoveryException;
import com.sslteam.client.tls.enrollment.TofuEnrollmentService;
import com.sslteam.client.tls.origin.TlsOrigin;
import com.sslteam.client.tls.persistence.TlsTrustProfileStore;
import com.sslteam.client.tls.profile.TlsTrustProfile;
import com.sslteam.client.tls.trust.TlsTrustContext;
import com.sslteam.client.tls.trust.TlsTrustContextFactory;
import com.sslteam.client.tls.validation.TlsServerValidator;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpExchange;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the TLS workflow against real local HTTPS sockets rather than only inspecting JSSE
 * objects. Certificates are locally generated self-signed EC certificates with intentional DNS or
 * IPv4 SANs. Discovery sends a TLS ClientHello and stops in the rejecting trust callback, so the
 * HTTP handler must not run and no authorization header can be observed. Authenticated HTTP is
 * attempted only after the selected public trust decision and hostname identity both succeed.
 */
class LocalHttpsTlsIntegrationTest {

    private static final char[] KEY_PASSWORD = "test-only-key-password".toCharArray();

    @TempDir
    Path temporaryDirectory;

    @Test
    void discoveryCapturesDnsCertificateWithoutSendingHttpOrCredentials() throws Exception {
        // Given a local HTTPS server whose certificate identifies localhost with a DNS SAN.
        CertificateMaterial material = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        try (RunningHttpsServer server = startServer(material, 0)) {
            TlsOrigin origin = TlsOrigin.normalize("https://localhost:" + server.port());
            CertificateDiscovery discovery = new CertificateDiscovery(Duration.ofSeconds(3));

            // When TLS-only discovery runs without an HTTP request or authorization header.
            TlsDiscoveryResult result = discovery.discover(origin);

            // Then the public leaf is captured and the server's HTTP handler remains untouched.
            assertEquals(CertificateFingerprint.sha256(material.certificate()), result.sha256Fingerprint());
            assertEquals(0, server.requestCount());
            assertFalse(server.authorizationSeen());
        }
    }

    @Test
    void explicitPemTrustAcceptsDnsIdentityAndRejectsIpHostnameMismatch() throws Exception {
        // Given a self-signed certificate trusted through a public PEM file and containing only a DNS SAN.
        CertificateMaterial material = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        Path trustStore = temporaryDirectory.resolve("localhost.pem");
        Files.writeString(trustStore, pem(material.certificate()));
        try (RunningHttpsServer server = startServer(material, 0)) {
            TlsTrustContextFactory factory = new TlsTrustContextFactory();
            TlsTrustContext context = factory.create(TlsTrustProfile.trustStore(
                    TlsOrigin.normalize("https://localhost:" + server.port()), trustStore));

            // When the URL hostname matches the DNS SAN, the real HTTPS request is allowed.
            HttpResponse<String> response = send(context, URI.create("https://localhost:" + server.port() + "/health"));

            // Then the request succeeds, while the same certificate cannot authenticate an IPv4 identity.
            assertEquals(200, response.statusCode());
            assertEquals("ok", response.body());
            assertEquals(1, server.requestCount());
            assertThrows(SSLHandshakeException.class, () -> send(context,
                    URI.create("https://127.0.0.1:" + server.port() + "/health")));
            assertEquals(1, server.requestCount());
        }
    }

    @Test
    void explicitPemTrustAcceptsIpv4IdentityOnlyWithIpSan() throws Exception {
        // Given a certificate whose identity is intentionally an IPv4 IP SAN, not a DNS SAN string.
        CertificateMaterial material = certificate("127.0.0.1", new GeneralName(GeneralName.iPAddress, "127.0.0.1"));
        Path trustStore = temporaryDirectory.resolve("loopback.pem");
        Files.writeString(trustStore, pem(material.certificate()));
        try (RunningHttpsServer server = startServer(material, 0)) {
            TlsTrustContext context = new TlsTrustContextFactory().create(TlsTrustProfile.trustStore(
                    TlsOrigin.normalize("https://127.0.0.1:" + server.port()), trustStore));

            // When the URL uses the matching IPv4 identity, hostname verification and trust both succeed.
            HttpResponse<String> response = send(context, URI.create("https://127.0.0.1:" + server.port() + "/health"));

            // Then the real server receives exactly one ordinary HTTP request.
            assertEquals(200, response.statusCode());
            assertEquals(1, server.requestCount());
        }
    }

    @Test
    void trustStoreValidationChecksHostnameWithoutSendingHttp() throws Exception {
        // Given a trusted DNS certificate and a validator configured for the matching HTTPS origin.
        CertificateMaterial material = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        Path trustStore = temporaryDirectory.resolve("validator.pem");
        Files.writeString(trustStore, pem(material.certificate()));
        try (RunningHttpsServer server = startServer(material, 0)) {
            TlsOrigin origin = TlsOrigin.normalize("https://localhost:" + server.port());
            TlsTrustContext context = new TlsTrustContextFactory().create(
                    TlsTrustProfile.trustStore(origin, trustStore));

            // When trust and hostname validation runs as a TLS-only operation.
            new TlsServerValidator(Duration.ofSeconds(3)).validate(origin, context);

            // Then the server sees no application HTTP request.
            assertEquals(0, server.requestCount());
        }
    }

    @Test
    void tofuPinFailsClosedAfterRotationUntilExplicitReplacement() throws Exception {
        // Given an origin enrolled against the first certificate through TLS-only discovery and explicit approval.
        CertificateMaterial first = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        CertificateMaterial replacement = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        InMemoryTlsTrustProfileStore connectionStore = new InMemoryTlsTrustProfileStore();
        CertificateDiscovery discovery = new CertificateDiscovery(Duration.ofSeconds(3));
        TofuEnrollmentService enrollment = new TofuEnrollmentService(discovery, connectionStore);
        int port;
        TlsOrigin origin;
        try (RunningHttpsServer server = startServer(first, 0)) {
            port = server.port();
            origin = TlsOrigin.normalize("https://localhost:" + port);
            TlsDiscoveryResult firstDiscovery = discovery.discover(origin);
            enrollment.enroll(firstDiscovery, firstDiscovery.sha256Fingerprint());
            assertEquals(0, server.requestCount());
        }

        // When the server rotates its leaf certificate on the same origin, the old pin is used once.
        try (RunningHttpsServer rotatedServer = startServer(replacement, port)) {
            TlsTrustProfile oldProfile = connectionStore.findTlsProfile(origin).orElseThrow();
            TlsTrustContext oldContext = new TlsTrustContextFactory().create(oldProfile);

            // Then the changed certificate fails at TLS and never reaches the HTTP handler.
            assertThrows(SSLHandshakeException.class, () -> send(oldContext,
                    URI.create(origin + "/health")));
            assertEquals(0, rotatedServer.requestCount());

            // And only a fresh discovery followed by explicit replacement changes the persisted pin.
            TlsDiscoveryResult replacementDiscovery = discovery.discover(origin);
            enrollment.replace(replacementDiscovery, replacementDiscovery.sha256Fingerprint());
            TlsTrustContext newContext = new TlsTrustContextFactory().create(connectionStore.findTlsProfile(origin).orElseThrow());
            HttpResponse<String> response = send(newContext, URI.create(origin + "/health"));
            assertEquals(200, response.statusCode());
            assertEquals(1, rotatedServer.requestCount());
        }
    }

    @Test
    void tofuRejectsIncorrectFingerprintWithoutPersistingOrSendingHttp() throws Exception {
        // Given a freshly discovered certificate and an operator fingerprint that does not match it.
        CertificateMaterial material = certificate("localhost", new GeneralName(GeneralName.dNSName, "localhost"));
        InMemoryTlsTrustProfileStore connectionStore = new InMemoryTlsTrustProfileStore();
        CertificateDiscovery discovery = new CertificateDiscovery(Duration.ofSeconds(3));
        TofuEnrollmentService enrollment = new TofuEnrollmentService(discovery, connectionStore);
        try (RunningHttpsServer server = startServer(material, 0)) {
            TlsOrigin origin = TlsOrigin.normalize("https://localhost:" + server.port());
            TlsDiscoveryResult discovered = discovery.discover(origin);

            // When approval supplies a complete but incorrect SHA-256 fingerprint.
            assertThrows(TlsDiscoveryException.class, () -> enrollment.enroll(discovered, "00".repeat(32)));

            // Then no trust profile is persisted and discovery still has not sent HTTP.
            assertFalse(connectionStore.findTlsProfile(origin).isPresent());
            assertEquals(0, server.requestCount());
        }
    }

    private static HttpResponse<String> send(TlsTrustContext context, URI uri) throws Exception {
        HttpClient client = context.httpClientBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(3)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static RunningHttpsServer startServer(CertificateMaterial material, int port) throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        SSLContext sslContext = serverSslContext(material);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters parameters) {
                parameters.setSSLParameters(getSSLContext().getDefaultSSLParameters());
            }
        });
        AtomicInteger requestCount = new AtomicInteger();
        AtomicInteger authorizationCount = new AtomicInteger();
        server.createContext("/", exchange -> handle(exchange, requestCount, authorizationCount));
        server.start();
        return new RunningHttpsServer(server, requestCount, authorizationCount);
    }

    private static void handle(HttpExchange exchange, AtomicInteger requestCount, AtomicInteger authorizationCount)
            throws java.io.IOException {
        requestCount.incrementAndGet();
        if (exchange.getRequestHeaders().containsKey("Authorization")) {
            authorizationCount.incrementAndGet();
        }
        byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    private static SSLContext serverSslContext(CertificateMaterial material) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, KEY_PASSWORD);
        keyStore.setKeyEntry("server", material.keyPair().getPrivate(), KEY_PASSWORD,
                new X509Certificate[]{material.certificate()});
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, KEY_PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        return context;
    }

    private static CertificateMaterial certificate(String commonName, GeneralName san) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=" + commonName);
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(Math.abs(new SecureRandom().nextLong()) + 1),
                Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)),
                subject,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        certificate.verify(keyPair.getPublic());
        return new CertificateMaterial(keyPair, certificate);
    }

    private static String pem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }

    private record CertificateMaterial(KeyPair keyPair, X509Certificate certificate) {
    }

    private static final class InMemoryTlsTrustProfileStore implements TlsTrustProfileStore {
        private final ConcurrentMap<TlsOrigin, TlsTrustProfile> profiles = new ConcurrentHashMap<>();

        @Override
        public Optional<TlsTrustProfile> findTlsProfile(TlsOrigin origin) {
            return Optional.ofNullable(profiles.get(origin));
        }

        @Override
        public List<TlsTrustProfile> listTlsProfiles() {
            return List.copyOf(profiles.values());
        }

        @Override
        public void putTlsProfile(TlsTrustProfile profile) {
            profiles.put(profile.origin(), profile);
        }

        @Override
        public boolean removeTlsProfile(TlsOrigin origin) {
            return profiles.remove(origin) != null;
        }
    }

    private static final class RunningHttpsServer implements AutoCloseable {
        private final HttpsServer server;
        private final AtomicInteger requestCount;
        private final AtomicInteger authorizationCount;

        private RunningHttpsServer(HttpsServer server, AtomicInteger requestCount, AtomicInteger authorizationCount) {
            this.server = server;
            this.requestCount = requestCount;
            this.authorizationCount = authorizationCount;
        }

        private int port() {
            return server.getAddress().getPort();
        }

        private int requestCount() {
            return requestCount.get();
        }

        private boolean authorizationSeen() {
            return authorizationCount.get() > 0;
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
