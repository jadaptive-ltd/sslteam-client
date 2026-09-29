package com.jadaptive.sslteam.client.tls.profile;

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
 * Mutually exclusive trust selection for one complete server origin.
 *
 * <p>The mode selects a future TLS trust context; it does not itself perform a handshake,
 * load a file, or authorize an HTTP request.</p>
 */
public enum TlsTrustMode {
    /** Use the normal JVM/system trust configuration. */
    SYSTEM,
    /** Trust only the operator-approved public certificate for the origin. */
    TOFU,
    /** Trust public certificates loaded from the explicitly configured PEM path. */
    TRUST_STORE
}
