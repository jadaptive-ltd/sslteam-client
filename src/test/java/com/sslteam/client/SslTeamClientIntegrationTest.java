package com.sslteam.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.sslteam.cert.api.contract.intermediate.IntermediateCurrentResponse;
import com.sslteam.cert.api.contract.root.RootCertificateResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;

/**
 * Calls the configured SSLTeam server with test-resource credentials.
 *
 * <p>The transport deliberately trusts the configured test server's self-signed certificate and
 * disables hostname identification only for this test. Production callers must use normal
 * certificate and hostname verification or an explicit trust profile.</p>
 */
class SslTeamClientIntegrationTest {

    @Test
    void logsInToConfiguredServerAndCallsPing() throws Exception {
        Properties configuration = loadConfiguration();
        String baseUrl = required(configuration, "url");
        SslTeamClient client = new SslTeamClient(new TestTrustingTransport());

        AuthTokenResponse tokens = client.login(
                baseUrl,
                required(configuration, "username"),
                required(configuration, "password"));
        PingResponse response = client.ping(baseUrl, tokens.accessToken());
        RootCertificateResponse root = client.applicationRoot(
            baseUrl,
            tokens.accessToken(),
            required(configuration, "teamCode"),
            required(configuration, "environment"));
        IntermediateCurrentResponse intermediate = client.currentIntermediate(
            baseUrl,
            tokens.accessToken(),
            required(configuration, "teamCode"),
            required(configuration, "environment"));

        assertNotNull(tokens.accessToken());
        assertFalse(tokens.accessToken().isBlank());
        assertNotNull(response);
        assertNotNull(response.message());
        assertNotNull(root);
        assertNotNull(intermediate);
    }

    private static Properties loadConfiguration() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = SslTeamClientIntegrationTest.class
                .getResourceAsStream("/client-test.properties")) {
            if (input == null) {
                throw new IOException("client-test.properties is missing");
            }
            properties.load(input);
        }
        return properties;
    }

    private static String required(Properties properties, String name) {
        String value = properties.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing client test property: " + name);
        }
        return value;
    }

    private static final class TestTrustingTransport implements SslTeamHttpTransport {

        private final HttpClient client;

        private TestTrustingTransport() throws NoSuchAlgorithmException, KeyManagementException {
            TrustManager[] trustManagers = {new TrustAllManager()};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            SSLParameters sslParameters = new SSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm(null);
            client = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .sslParameters(sslParameters)
                    .version(HttpClient.Version.HTTP_1_1)
                    .build();
        }

        @Override
        public <T> HttpResponse<T> send(
                HttpRequest request,
                HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
            return client.send(request, responseBodyHandler);
        }
    }

    private static final class TrustAllManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
