package com.jadaptive.sslteam.client.tls.certificate;

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
 * Reports unsafe, malformed, or unavailable public certificate material before trust configuration
 * or transport begins. Messages are bounded and must not contain certificate bodies, private keys,
 * credentials, or raw file contents; the cause is retained for diagnostic logging at the boundary.
 */
public final class TlsCertificateException extends IllegalArgumentException {

    /**
     * Creates an operator-safe certificate-material failure.
     *
     * @param message bounded explanation that excludes certificate and secret material
     */
    public TlsCertificateException(String message) {
        super(message);
    }

    /**
     * Creates an operator-safe failure while retaining the implementation cause for diagnostics.
     *
     * @param message bounded explanation that excludes certificate and secret material
     * @param cause original parsing or file-system failure
     */
    public TlsCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

}
