package com.jadaptive.sslteam.client;

/*-
 * #%L
 * SSLTeam Java Client
 * %%
 * Copyright (C) 2026 Jadaptive Limited
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

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
