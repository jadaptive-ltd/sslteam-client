package com.sslteam.client;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Portable JDK transport using the platform trust store and HTTPS hostname verification.
 *
 * <p>This transport is appropriate for consumers that use normal system trust. Consumers with
 * origin-scoped TOFU or explicit trust-store policy should provide their own transport instead
 * of changing global JVM TLS settings.</p>
 */
public final class SslTeamTransport implements SslTeamHttpTransport {

    private final HttpClient httpClient;

    /**
     * Creates a system-trust transport with bounded connection establishment.
     *
     * @param connectTimeout maximum time to establish a connection
     */
    public SslTeamTransport(Duration connectTimeout) {
        if (connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()) {
            throw new IllegalArgumentException("connectTimeout must be positive");
        }
        this.httpClient = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
    }

    /**
     * Creates a transport with a caller-owned JDK client.
     *
     * @param httpClient configured client; its TLS policy remains caller-owned
     */
    public SslTeamTransport(HttpClient httpClient) {
        this.httpClient = java.util.Objects.requireNonNull(httpClient, "httpClient");
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        return httpClient.send(request, responseBodyHandler);
    }
}
