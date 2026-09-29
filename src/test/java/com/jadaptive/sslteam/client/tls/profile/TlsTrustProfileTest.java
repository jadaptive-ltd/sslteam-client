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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import java.nio.file.Path;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * Verifies deterministic, origin-scoped trust-profile invariants without opening a socket or
 * reading a trust-store file. The fixtures represent the configuration boundary before any TLS
 * context, operator prompt, persistence mutation, credential, or HTTP request is allowed.
 */
class TlsTrustProfileTest {

    private static final String RAW_FINGERPRINT =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String COLON_FINGERPRINT =
            "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef";

    @Test
    void systemProfileHasNoLocalTrustOverride() {
        // Given an exact normalized HTTPS origin with no operator-supplied trust material.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");

        // When the system profile is created.
        TlsTrustProfile profile = TlsTrustProfile.system(origin);

        // Then only the system mode is selected and no local material is attached.
        assertEquals(origin, profile.origin());
        assertEquals(TlsTrustMode.SYSTEM, profile.mode());
        assertNull(profile.pinnedCertificateSha256());
        assertNull(profile.trustStorePath());
    }

    @Test
    void tofuProfileCanonicalizesCompleteRawAndColonSeparatedFingerprints() {
        // Given the same public SHA-256 fingerprint in two operator display formats.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");

        // When each TOFU profile is created.
        TlsTrustProfile rawProfile = TlsTrustProfile.tofu(origin, "  " + RAW_FINGERPRINT + "  ");
        TlsTrustProfile colonProfile = TlsTrustProfile.tofu(origin, COLON_FINGERPRINT);

        // Then both profiles retain one canonical upper-case fingerprint for the same origin.
        assertEquals(RAW_FINGERPRINT.toUpperCase(Locale.ROOT), rawProfile.pinnedCertificateSha256());
        assertEquals(RAW_FINGERPRINT.toUpperCase(Locale.ROOT), colonProfile.pinnedCertificateSha256());
        assertEquals(TlsTrustMode.TOFU, rawProfile.mode());
        assertNull(rawProfile.trustStorePath());
    }

    @Test
    void trustStoreProfileNormalizesPathWithoutOpeningIt() {
        // Given a relative path containing a redundant path segment and an exact origin.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");
        Path configuredPath = Path.of("trust", "..", "certs", "server.pem");

        // When an explicit trust-store profile is created.
        TlsTrustProfile profile = TlsTrustProfile.trustStore(origin, configuredPath);

        // Then the path is absolute and normalized, while file existence is not assumed here.
        assertEquals(configuredPath.toAbsolutePath().normalize(), profile.trustStorePath());
        assertEquals(TlsTrustMode.TRUST_STORE, profile.mode());
        assertNull(profile.pinnedCertificateSha256());
    }

    @Test
    void rejectsMissingOrMixedModeMaterialBeforeTransport() {
        // Given one exact origin and material belonging to incompatible trust modes.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");
        Path trustStore = Path.of("server.pem");

        // Then incomplete or mixed profiles fail closed without reading the path or creating TLS.
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.TOFU, null, null));
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.TRUST_STORE, null, null));
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.SYSTEM, RAW_FINGERPRINT, null));
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.SYSTEM, null, trustStore));
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.TOFU, RAW_FINGERPRINT, trustStore));
        assertThrows(TlsTrustProfileException.class,
                () -> new TlsTrustProfile(origin, TlsTrustMode.TRUST_STORE, RAW_FINGERPRINT, trustStore));
        assertThrows(TlsTrustProfileException.class,
                () -> TlsTrustProfile.trustStore(origin, Path.of("")));
    }

    @Test
    void rejectsIncompleteOrMalformedTofuFingerprints() {
        // Given fingerprints that are not exactly one complete SHA-256 hexadecimal value.
        TlsOrigin origin = TlsOrigin.normalize("https://server.example.test:15080");
        String[] invalidFingerprints = {
                "",
                "  ",
                "0123",
                RAW_FINGERPRINT.substring(0, RAW_FINGERPRINT.length() - 2),
                COLON_FINGERPRINT.replace(":", "-"),
                RAW_FINGERPRINT + "00",
                "not-a-fingerprint"
        };

        // Then each value is rejected before any trust material can be activated.
        for (String invalidFingerprint : invalidFingerprints) {
            assertThrows(TlsTrustProfileException.class,
                    () -> TlsTrustProfile.tofu(origin, invalidFingerprint), invalidFingerprint);
        }
    }

        @Test
        void rejectsLoopbackHttpBeforeTrustMaterialCanBeSelected() {
                // Given a loopback HTTP origin accepted by ordinary CLI transport for local development.
                TlsOrigin localHttpOrigin = TlsOrigin.normalize("http://localhost:15080");

                // Then no TLS trust decision can be created for that plaintext origin.
                assertThrows(TlsTrustProfileException.class, () -> TlsTrustProfile.system(localHttpOrigin));
        }
}
