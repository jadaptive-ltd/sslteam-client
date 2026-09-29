package com.jadaptive.sslteam.client.tls.trust;

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
 * Reports failure to construct a scoped TLS trust context before an HTTP request is sent. The
 * message is operator-safe; the cause is retained for throwable-aware diagnostic logging and may
 * contain provider details that must not be returned directly to a user.
 */
public final class TlsTrustContextException extends IllegalStateException {

    /**
     * Creates a bounded trust-context failure.
     *
     * @param message operator-safe explanation without certificate bodies or secrets
     */
    public TlsTrustContextException(String message) {
        super(message);
    }

    /**
     * Creates a bounded trust-context failure while retaining the provider cause.
     *
     * @param message operator-safe explanation without certificate bodies or secrets
     * @param cause original JSSE or trust-store failure
     */
    public TlsTrustContextException(String message, Throwable cause) {
        super(message, cause);
    }

}
