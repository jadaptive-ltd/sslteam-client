package com.jadaptive.sslteam.client.tls.persistence;

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