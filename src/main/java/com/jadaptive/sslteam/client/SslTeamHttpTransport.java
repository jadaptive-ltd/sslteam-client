package com.jadaptive.sslteam.client;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Sends an already constructed SSLTeam HTTP request using the caller's transport policy.
 *
 * <p>The client API owns endpoint and payload semantics, while this SPI lets an embedding
 * application provide origin-scoped TLS, proxy, connection, and observability policy. The
 * transport must not weaken hostname verification or trust checks and must not log request
 * bodies, credentials, tokens, or certificate material.</p>
 */
@FunctionalInterface
public interface SslTeamHttpTransport {

    /**
     * Sends one request and decodes its response with the supplied JDK body handler.
     *
     * @param request request prepared by the SSLTeam client
     * @param responseBodyHandler response decoder
     * @param <T> decoded response body type
     * @return the HTTP response
     * @throws IOException when the transport cannot complete the request
     * @throws InterruptedException when the calling thread is interrupted
     */
    <T> HttpResponse<T> send(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException;
}
