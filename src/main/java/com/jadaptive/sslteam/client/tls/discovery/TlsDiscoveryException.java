package com.jadaptive.sslteam.client.tls.discovery;

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
 * Reports a bounded failure while discovering a server certificate over a TLS-only connection.
 * The cause is retained for diagnostic logging; certificate bodies, credentials, and raw transport
 * data are never included in the message.
 */
public final class TlsDiscoveryException extends IllegalStateException {

    /**
     * Creates an operator-safe discovery failure.
     *
     * @param message bounded explanation without certificate or transport contents
     */
    public TlsDiscoveryException(String message) {
        super(message);
    }

    /**
     * Creates an operator-safe discovery failure while retaining diagnostics.
     *
     * @param message bounded explanation without certificate or transport contents
     * @param cause underlying TLS or socket failure
     */
    public TlsDiscoveryException(String message, Throwable cause) {
        super(message, cause);
    }

}
