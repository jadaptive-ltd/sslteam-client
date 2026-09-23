package com.sslteam.client.tls.origin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Verifies deterministic origin identity policy without claiming a live TLS handshake.
 * The fixture values represent profile-key confusion and unsafe endpoint input; no test opens
 * a socket, sends HTTP bytes, reads credentials, or inspects a server certificate.
 */
class TlsOriginTest {

    @Test
    void normalizesSchemeHostAndDefaultPortIntoCompleteOriginIdentity() {
        // Given a case-variant HTTPS URL with an optional root path.
        TlsOrigin origin = TlsOrigin.normalize(" HTTPS://Example.COM/ ");

        // Then the profile identity is canonical and includes HTTPS's effective port.
        assertEquals("https", origin.scheme());
        assertEquals("example.com", origin.host());
        assertEquals(443, origin.port());
        assertEquals("https://example.com:443", origin.toString());
    }

    @Test
    void preservesPortIsolationAndIPv6LiteralIdentity() {
        // Given two listeners on the same host and an IPv6 loopback URL.
        TlsOrigin defaultPort = TlsOrigin.normalize("https://server.example.test");
        TlsOrigin alternatePort = TlsOrigin.normalize("https://server.example.test:15080");
        TlsOrigin ipv6 = TlsOrigin.normalize("https://[::1]");

        // Then pins cannot cross ports, and IPv6 is rendered as an IP literal rather than DNS.
        assertNotEquals(defaultPort, alternatePort);
        assertEquals("::1", ipv6.host());
        assertEquals("https://[::1]:443", ipv6.toString());
    }

    @Test
    void permitsPlainHttpOnlyForTheExistingLocalDevelopmentBoundary() {
        // Given local loopback development endpoints.
        TlsOrigin localhost = TlsOrigin.normalize("http://localhost");
        TlsOrigin ipv4Loopback = TlsOrigin.normalize("http://127.0.0.1:15080");
        TlsOrigin ipv6Loopback = TlsOrigin.normalize("http://[::1]:15080");

        // Then the local exception remains explicit and normalized.
        assertEquals("http://localhost:80", localhost.toString());
        assertEquals("http://127.0.0.1:15080", ipv4Loopback.toString());
        assertEquals("http://[::1]:15080", ipv6Loopback.toString());
    }

    @Test
    void rejectsAmbiguousOriginsBeforeTransport() {
        // Given malformed, credential-bearing, scoped, or remote-HTTP endpoint values.
        String[] unsafeOrigins = {
                null,
                "",
                "ftp://server.example.test",
                "https://user:password@server.example.test",
                "https://server.example.test/path",
                "https://server.example.test?query=value",
                "https://server.example.test#fragment",
                "http://server.example.test",
                "https://*.example.test",
                "https://server.example.test:0",
                "https://server.example.test:65536",
                "https:///missing-host"
        };

        // Then each value is rejected without a weaker transport fallback.
        for (String unsafeOrigin : unsafeOrigins) {
            assertThrows(TlsOriginException.class, () -> TlsOrigin.normalize(unsafeOrigin), unsafeOrigin);
        }
    }
}
