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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * Computes the SHA-256 identity of a public X.509 certificate.
 *
 * <p>The fingerprint is calculated from the DER certificate encoding, not from a PEM wrapper or
 * mutable display text. This class performs no network, persistence, credential, or approval work;
 * callers use the result to compare a presented public certificate with an already approved
 * identity. Certificate bytes are never logged or included in the exception text.</p>
 */
public final class CertificateFingerprint {

    private CertificateFingerprint() {
    }

    /**
     * Computes a canonical upper-case, colon-free SHA-256 fingerprint for a certificate.
     *
     * @param certificate public certificate whose DER encoding is hashed
     * @return 64-character upper-case hexadecimal SHA-256 fingerprint
     * @throws IllegalArgumentException if the certificate cannot be encoded or is missing
     */
    public static String sha256(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))
                    .toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException | CertificateEncodingException exception) {
            throw new IllegalArgumentException("Unable to fingerprint the public X.509 certificate.", exception);
        }
    }
}
