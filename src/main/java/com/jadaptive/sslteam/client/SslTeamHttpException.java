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

/**
 * Indicates that the server returned an HTTP error for an SSLTeam request.
 *
 * <p>The response body is intentionally not retained. Consumers can use the status and
 * correlation ID for safe classification while the transport logs full throwable diagnostics
 * at its own exception boundary.</p>
 */
public final class SslTeamHttpException extends SslTeamClientException {

    private final String method;
    private final String uri;
    private final int statusCode;
    private final String correlationId;
    private final String errorCode;
    private final String serverMessage;

    public SslTeamHttpException(String method, String uri, int statusCode, String correlationId) {
        this(method, uri, statusCode, correlationId, null, null);
    }

    public SslTeamHttpException(
            String method,
            String uri,
            int statusCode,
            String correlationId,
            String errorCode,
            String serverMessage) {
        super("SSLTeam server rejected the request with HTTP status " + statusCode);
        this.method = method;
        this.uri = uri;
        this.statusCode = statusCode;
        this.correlationId = correlationId;
        this.errorCode = errorCode;
        this.serverMessage = serverMessage;
    }

    public String method() {
        return method;
    }

    public String uri() {
        return uri;
    }

    public int statusCode() {
        return statusCode;
    }

    public String correlationId() {
        return correlationId;
    }

    public String errorCode() {
        return errorCode;
    }

    public String serverMessage() {
        return serverMessage;
    }
}
