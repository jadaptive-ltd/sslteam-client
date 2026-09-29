package com.jadaptive.sslteam.client.tls.persistence;

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

import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import com.jadaptive.sslteam.client.tls.profile.TlsTrustProfile;
import java.util.List;
import java.util.Optional;

/**
 * Persistence port for origin-scoped TLS trust profiles.
 *
 * <p>The client library owns trust decisions and TLS construction, while an embedding application
 * owns where approved public trust metadata is stored. Implementations must persist only validated
 * public profile data and must not weaken hostname verification or store private credentials.</p>
 */
public interface TlsTrustProfileStore {

    /** Returns the validated profile for one exact normalized origin, if present. */
    Optional<TlsTrustProfile> findTlsProfile(TlsOrigin origin);

    /** Returns all validated persisted profiles in the store's stable iteration order. */
    List<TlsTrustProfile> listTlsProfiles();

    /** Persists one validated profile for its exact normalized origin. */
    void putTlsProfile(TlsTrustProfile profile);

    /** Removes the persisted profile for one exact normalized origin, if present. */
    boolean removeTlsProfile(TlsOrigin origin);
}
