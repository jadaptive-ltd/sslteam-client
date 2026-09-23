package com.sslteam.client.tls.profile;

import com.sslteam.client.tls.origin.TlsOrigin;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;

/**
 * Immutable, origin-scoped selection of one TLS trust mode and its public trust material.
 *
 * <p>{@link TlsTrustMode#SYSTEM} has no local override, {@link TlsTrustMode#TOFU} requires
 * exactly one approved SHA-256 certificate fingerprint, and {@link TlsTrustMode#TRUST_STORE}
 * requires exactly one PEM path. The path is normalized but not read here; certificate parsing,
 * trust-manager construction, persistence, operator approval, and HTTP transport belong to
 * later dedicated components. Consequently this model cannot send HTTP bytes or weaken
 * hostname verification.</p>
 */
public record TlsTrustProfile(
        TlsOrigin origin,
        TlsTrustMode mode,
        String pinnedCertificateSha256,
        Path trustStorePath) {

    /**
     * Validates the closed trust-mode vocabulary and normalizes its mode-specific public input.
     *
     * @param origin complete normalized origin that owns this decision
     * @param mode exactly one trust mode
     * @param pinnedCertificateSha256 64 hexadecimal SHA-256 fingerprint only for TOFU
     * @param trustStorePath local PEM path only for TRUST_STORE; it is not opened
     * @throws TlsTrustProfileException if mode-specific material is missing, malformed, or mixed
     */
    public TlsTrustProfile {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(mode, "mode");
        if (!"https".equals(origin.scheme())) {
            throw new TlsTrustProfileException("TLS trust profiles require an HTTPS origin.");
        }
        pinnedCertificateSha256 = normalizeFingerprint(pinnedCertificateSha256);
        trustStorePath = normalizePath(trustStorePath);
        switch (mode) {
            case SYSTEM -> requireAbsent(pinnedCertificateSha256, trustStorePath,
                    "SYSTEM trust cannot include a pinned certificate or trust-store path.");
            case TOFU -> {
                if (pinnedCertificateSha256 == null) {
                    throw new TlsTrustProfileException("TOFU trust requires an approved SHA-256 certificate fingerprint.");
                }
                if (trustStorePath != null) {
                    throw new TlsTrustProfileException("TOFU trust cannot include an explicit trust-store path.");
                }
            }
            case TRUST_STORE -> {
                if (trustStorePath == null) {
                    throw new TlsTrustProfileException("Explicit trust-store mode requires a PEM trust-store path.");
                }
                if (pinnedCertificateSha256 != null) {
                    throw new TlsTrustProfileException("Explicit trust-store mode cannot include a TOFU certificate fingerprint.");
                }
            }
        }
    }

    /**
     * Creates the system-trust profile for an exact origin.
     *
     * @param origin normalized origin to which the system decision applies
     * @return profile with no local certificate override
     */
    public static TlsTrustProfile system(TlsOrigin origin) {
        return new TlsTrustProfile(origin, TlsTrustMode.SYSTEM, null, null);
    }

    /**
     * Creates a TOFU profile from an operator-approved public certificate fingerprint.
     *
     * @param origin normalized origin to which the pin applies
     * @param fingerprint SHA-256 fingerprint, raw hexadecimal or colon-separated
     * @return profile containing the canonical upper-case raw fingerprint
     */
    public static TlsTrustProfile tofu(TlsOrigin origin, String fingerprint) {
        return new TlsTrustProfile(origin, TlsTrustMode.TOFU, fingerprint, null);
    }

    /**
     * Creates an explicit public PEM trust-store profile without reading the file.
     *
     * @param origin normalized origin to which the path applies
     * @param path local PEM trust-store path
     * @return profile containing an absolute normalized path
     */
    public static TlsTrustProfile trustStore(TlsOrigin origin, Path path) {
        return new TlsTrustProfile(origin, TlsTrustMode.TRUST_STORE, null, path);
    }

    private static String normalizeFingerprint(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String candidate = value.trim();
        boolean rawHex = candidate.matches("[0-9a-fA-F]{64}");
        boolean colonHex = candidate.matches("(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}");
        if (!rawHex && !colonHex) {
            throw new TlsTrustProfileException("TOFU fingerprint must be a complete SHA-256 hexadecimal fingerprint.");
        }
        return candidate.replace(":", "").toUpperCase(Locale.ROOT);
    }

    private static Path normalizePath(Path path) {
        if (path == null) {
            return null;
        }
        if (path.toString().isBlank()) {
            throw new TlsTrustProfileException("Explicit trust-store mode requires a non-blank PEM path.");
        }
        return path.toAbsolutePath().normalize();
    }

    private static void requireAbsent(String fingerprint, Path path, String message) {
        if (fingerprint != null || path != null) {
            throw new TlsTrustProfileException(message);
        }
    }
}
