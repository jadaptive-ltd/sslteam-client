package com.sslteam.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;

class SslTeamClientTest {

    @Test
    void tokenRequestUsesServerChannelProperty() throws Exception {
        String json = new ObjectMapper().writeValueAsString(
                new AuthTokenRequest("operator", "password", "CLI"));

        assertEquals("{\"username\":\"operator\",\"password\":\"password\",\"channel\":\"CLI\"}", json);
    }

    @Test
    void pingBuildsAuthenticatedVersionedEndpointAndCorrelationHeader() {
        RecordingTransport transport = new RecordingTransport(
                response(200, "{\"message\":\"pong\"}", Map.of("X-SSL-Teams-Correlation-Id", List.of("corr-1"))));
        SslTeamClient client = new SslTeamClient(transport);

        PingResponse response = client.ping("http://localhost:15080/", "access-token");

        assertEquals("pong", response.message());
        assertEquals("GET", transport.request.method());
        assertEquals("http://localhost:15080/api/v1/auth/ping", transport.request.uri().toString());
        assertEquals("Bearer access-token", transport.request.headers().firstValue("Authorization").orElseThrow());
        assertTrue(transport.request.headers().firstValue("X-SSL-Teams-Correlation-Id").isPresent());
    }

    @Test
    void refreshUsesOneNonIdempotentAttemptAndDoesNotLogOrExposeToken() {
        RecordingTransport transport = new RecordingTransport(
                response(200, "{\"accessToken\":\"new-atk\",\"tokenType\":\"Bearer\","
                        + "\"expiresIn\":300,\"refreshToken\":\"new-rtk\",\"refreshExpiresIn\":86400,"
                        + "\"passwordChangeRequired\":false}", Map.of()));
        SslTeamClient client = new SslTeamClient(transport);

        AuthTokenResponse response = client.refresh("http://localhost:15080", "refresh-secret");

        assertEquals("new-atk", response.accessToken());
        assertEquals("POST", transport.request.method());
        assertEquals(1, transport.sendCount.get());
        assertTrue(transport.request.headers().firstValue("Authorization").isEmpty());
    }

    @Test
    void rejectsNonLocalHttpOriginBeforeSendingAnyRequest() {
        RecordingTransport transport = new RecordingTransport(response(200, "{}", Map.of()));
        SslTeamClient client = new SslTeamClient(transport);

        assertThrows(IllegalArgumentException.class, () -> client.ping("http://example.test", "access-token"));
        assertEquals(0, transport.sendCount.get());
    }

    @Test
    void mapsServerRejectionToBoundedTypedFailure() {
        RecordingTransport transport = new RecordingTransport(response(401, "{\"token\":\"secret\"}", Map.of()));
        SslTeamClient client = new SslTeamClient(transport);

        SslTeamHttpException exception = assertThrows(
                SslTeamHttpException.class,
                () -> client.ping("https://sslteam.example", "access-token"));

        assertEquals(401, exception.statusCode());
        assertTrue(exception.getMessage().contains("401"));
        assertTrue(!exception.getMessage().contains("secret"));
    }

    private static HttpResponse<String> response(int status, String body, Map<String, List<String>> headers) {
        return new FakeHttpResponse<>(status, body, headers);
    }

    private static final class RecordingTransport implements SslTeamHttpTransport {

        private final HttpResponse<String> response;
        private final AtomicInteger sendCount = new AtomicInteger();
        private HttpRequest request;

        private RecordingTransport(HttpResponse<String> response) {
            this.response = response;
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
                throws IOException {
            this.request = request;
            sendCount.incrementAndGet();
            return (HttpResponse<T>) response;
        }
    }

    private static final class FakeHttpResponse<T> implements HttpResponse<T> {

        private final int statusCode;
        private final T body;
        private final HttpHeaders headers;

        private FakeHttpResponse(int statusCode, T body, Map<String, List<String>> headers) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = HttpHeaders.of(headers, (name, value) -> true);
        }

        @Override
        public int statusCode() {
            return statusCode;
        }

        @Override
        public HttpRequest request() {
            return HttpRequest.newBuilder(URI.create("https://sslteam.example")).build();
        }

        @Override
        public Optional<HttpResponse<T>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return headers;
        }

        @Override
        public T body() {
            return body;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return URI.create("https://sslteam.example");
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }
}
