package com.jadaptive.sslteam.client.tls.enrollment;

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

import com.jadaptive.sslteam.client.tls.discovery.CertificateDiscovery;
import com.jadaptive.sslteam.client.tls.discovery.TlsDiscoveryResult;
import com.jadaptive.sslteam.client.tls.discovery.TlsDiscoveryException;
import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import com.jadaptive.sslteam.client.tls.persistence.TlsTrustProfileStore;
import com.jadaptive.sslteam.client.tls.profile.TlsTrustProfile;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Orchestrates TLS-only discovery and explicit TOFU approval without combining them into transport.
 *
 * <p>Discovery always happens before approval and returns only an ephemeral public certificate
 * result. Approval requires the operator-supplied complete fingerprint to equal the freshly
 * discovered certificate. A normal enrollment refuses to replace any existing profile; replacement
 * is a separate explicit operation. Persistence occurs only after all checks succeed.</p>
 */
public final class TofuEnrollmentService {

    private static final Logger LOG = Logger.getLogger(TofuEnrollmentService.class.getName());

    private final CertificateDiscovery certificateDiscovery;
    private final TlsTrustProfileStore profileStore;

    /**
     * Creates the enrollment coordinator from independent discovery and persistence boundaries.
     *
     * @param certificateDiscovery TLS-only, no-HTTP certificate discovery
    * @param connectionStore atomic origin-scoped connection persistence
     */
    public TofuEnrollmentService(CertificateDiscovery certificateDiscovery, TlsTrustProfileStore profileStore) {
        this.certificateDiscovery = Objects.requireNonNull(certificateDiscovery, "certificateDiscovery");
        this.profileStore = Objects.requireNonNull(profileStore, "profileStore");
    }

    /**
     * Performs one TLS-only discovery for operator inspection.
     *
     * @param origin normalized HTTPS origin
     * @return ephemeral public discovery result; no profile is changed
     */
    public TlsDiscoveryResult discover(TlsOrigin origin) {
        return certificateDiscovery.discover(origin);
    }

    /**
     * Persists a first-use TOFU approval only when no profile exists for the origin.
     *
     * @param discovery result from discovery of the same origin
     * @param approvedFingerprint operator-supplied complete SHA-256 fingerprint
     * @return persisted TOFU profile
     * @throws TlsDiscoveryException if the fingerprint is invalid or a profile already exists
     */
    public TlsTrustProfile enroll(TlsDiscoveryResult discovery, String approvedFingerprint) {
        TlsTrustProfile candidate = validatedCandidate(discovery, approvedFingerprint);
        if (profileStore.findTlsProfile(discovery.origin()).isPresent()) {
            throw new TlsDiscoveryException("A TLS profile already exists for this origin; use explicit replacement.");
        }
        return persist(candidate, "enrollment");
    }

    /**
     * Replaces an existing TOFU approval only through the explicit replacement lifecycle.
     *
     * @param discovery result from discovery of the same origin
     * @param approvedFingerprint operator-supplied complete SHA-256 fingerprint
     * @return persisted replacement TOFU profile
     * @throws TlsDiscoveryException if the fingerprint is invalid or no profile exists to replace
     */
    public TlsTrustProfile replace(TlsDiscoveryResult discovery, String approvedFingerprint) {
        TlsTrustProfile candidate = validatedCandidate(discovery, approvedFingerprint);
        if (profileStore.findTlsProfile(discovery.origin()).isEmpty()) {
            throw new TlsDiscoveryException("No existing TLS profile exists for this origin to replace.");
        }
        return persist(candidate, "replacement");
    }

    private TlsTrustProfile validatedCandidate(TlsDiscoveryResult discovery, String approvedFingerprint) {
        if (discovery == null) {
            throw new TlsDiscoveryException("A TLS discovery result is required for approval.");
        }
        TlsTrustProfile candidate = TlsTrustProfile.tofu(discovery.origin(), approvedFingerprint);
        if (!candidate.pinnedCertificateSha256().equals(discovery.sha256Fingerprint())) {
            throw new TlsDiscoveryException("The supplied fingerprint does not match the freshly discovered certificate.");
        }
        return candidate;
    }

    private TlsTrustProfile persist(TlsTrustProfile candidate, String operation) {
        String operationId = UUID.randomUUID().toString();
        profileStore.putTlsProfile(candidate);
        LOG.info("TLS TOFU profile approved: operationId=" + operationId
            + " origin=" + candidate.origin() + " operation=" + operation + " mode=" + candidate.mode());
        return candidate;
    }
}
