package com.jadaptive.sslteam.client.tls.origin;

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
 * Reports an invalid or ambiguous server origin before TLS or HTTP transport begins.
 * No network, credential, trust-store, or persistence operation is performed when this
 * exception is created.
 */
public final class TlsOriginException extends IllegalArgumentException {

    /**
     * Creates an origin-policy failure with a bounded operator-safe explanation.
     *
     * @param message explanation that must not contain certificate or credential material
     */
    public TlsOriginException(String message) {
        super(message);
    }

    /**
     * Creates an origin parsing failure while retaining the parser cause for diagnostics.
     *
     * @param message bounded operator-safe explanation
     * @param cause original URI parsing failure
     */
    public TlsOriginException(String message, Throwable cause) {
        super(message, cause);
    }

}
