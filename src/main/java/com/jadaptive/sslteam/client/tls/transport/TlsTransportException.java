package com.jadaptive.sslteam.client.tls.transport;

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
 * Represents a TLS policy or handshake failure at the CLI transport boundary.
 *
 * <p>The bounded message is suitable for operator output and intentionally excludes exception
 * details, certificate bodies, credentials, and request/response data. The original throwable is
 * retained for diagnostic logging by the boundary. Certificate, hostname, and trust failures are
 * non-retryable and never trigger a weaker trust mode or an authenticated retry.</p>
 */
public final class TlsTransportException extends IllegalStateException {

    /**
     * Creates a bounded non-retryable TLS transport failure.
     *
     * @param message operator-safe explanation without sensitive material
     * @param cause original JSSE failure retained for diagnostics
     */
    public TlsTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
