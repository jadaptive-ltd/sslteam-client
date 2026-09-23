package com.sslteam.client.tls.origin;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Objects;
import java.util.HexFormat;

/**
 * Immutable normalized identity of a CLI server origin.
 *
 * <p>The origin contains only scheme, canonical host, and effective port. A root path is
 * accepted as input but is not part of the identity. DNS hosts are lower-cased and converted
 * to ASCII; IPv6 literals retain their literal identity without DNS resolution. Userinfo,
 * query, fragment, non-root paths, unsupported schemes, invalid ports, wildcard-like values,
 * and remote plain HTTP are rejected before any socket, credential, trust-store, or persistence
 * operation can occur. This type does not perform a TLS handshake and cannot send HTTP bytes.</p>
 */
public final class TlsOrigin {

    private final String scheme;
    private final String host;
    private final int port;

    private TlsOrigin(String scheme, String host, int port) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
    }

    /**
     * Normalizes and validates a user-supplied backend URL for use as an origin key.
     *
     * @param value URL containing an HTTPS origin, or localhost/loopback HTTP for the existing
     *              local-development boundary
     * @return normalized origin with an explicit effective port
     * @throws TlsOriginException if the value is missing, ambiguous, unsafe, or unsupported
     */
    public static TlsOrigin normalize(String value) {
        if (value == null || value.isBlank()) {
            throw new TlsOriginException("TLS origin is required.");
        }

        URI uri;
        try {
            uri = new URI(value.trim());
        } catch (URISyntaxException exception) {
            throw new TlsOriginException("TLS origin is not a valid URL.", exception);
        }

        String scheme = normalizeScheme(uri.getScheme());
        if (uri.isOpaque() || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new TlsOriginException("TLS origin must contain only a scheme, host, port, and optional root path.");
        }
        String host = normalizeHost(uri.getHost());
        int port = normalizePort(uri.getPort(), scheme);
        String rawPath = uri.getRawPath();
        if (rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath)) {
            throw new TlsOriginException("TLS origin must not contain a request path.");
        }
        if ("http".equals(scheme) && !isLocalHost(host)) {
            throw new TlsOriginException("Plain HTTP is only allowed for localhost/loopback TLS origins.");
        }
        return new TlsOrigin(scheme, host, port);
    }

    /**
     * Returns the normalized lowercase URI scheme used for transport selection.
     *
     * @return {@code https} or the explicitly permitted local-development {@code http}
     */
    public String scheme() {
        return scheme;
    }

    /**
     * Returns the canonical host identity without IPv6 brackets.
     *
     * @return lower-case DNS/IPv4 host or lower-case IPv6 literal
     */
    public String host() {
        return host;
    }

    /**
     * Returns the explicit port used to isolate this origin from other listeners.
     *
     * @return configured port, or scheme default 443/80 when omitted by the input
     */
    public int port() {
        return port;
    }

    /** Returns the stable lowercase SHA-256 namespace for this complete origin identity. */
    public String storageKey() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable for origin storage isolation", exception);
        }
    }

    /**
     * Reconstructs the normalized origin URI without a path, query, or fragment.
     *
     * @return normalized URI suitable for profile keys and request endpoint construction
     * @throws IllegalStateException only if an internal invariant is broken
     */
    public URI uri() {
        try {
            return new URI(scheme, null, host, port, null, null, null);
        } catch (URISyntaxException exception) {
            throw new IllegalStateException("Normalized TLS origin could not be represented as a URI.", exception);
        }
    }

    /**
     * Returns the normalized origin string used as the stable profile identity.
     *
     * @return explicit scheme, host, and port
     */
    @Override
    public String toString() {
        return uri().toString();
    }

    /**
     * Compares normalized scheme, host, and effective port only.
     *
     * @param other object to compare
     * @return whether both values identify the same complete origin
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof TlsOrigin origin)) {
            return false;
        }
        return port == origin.port && scheme.equals(origin.scheme) && host.equals(origin.host);
    }

    /**
     * Hashes the complete normalized origin for use as a profile-map key.
     *
     * @return stable hash of scheme, host, and port
     */
    @Override
    public int hashCode() {
        return Objects.hash(scheme, host, port);
    }

    private static String normalizeScheme(String value) {
        String scheme = value == null ? "" : value.toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            throw new TlsOriginException("TLS origin must use http or https.");
        }
        return scheme;
    }

    private static String normalizeHost(String value) {
        if (value == null || value.isBlank()) {
            throw new TlsOriginException("TLS origin must contain a host.");
        }
        String host = value;
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.isBlank() || host.indexOf('%') >= 0 || host.indexOf('*') >= 0 || containsUnsafeHostCharacter(host)) {
            throw new TlsOriginException("TLS origin host is ambiguous or unsafe.");
        }
        if (host.indexOf(':') >= 0) {
            return host.toLowerCase(Locale.ROOT);
        }
        try {
            String asciiHost = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (asciiHost.isBlank() || asciiHost.endsWith(".")) {
                throw new TlsOriginException("TLS origin host must not use a trailing dot.");
            }
            return asciiHost;
        } catch (IllegalArgumentException exception) {
            throw new TlsOriginException("TLS origin host is not a valid DNS name.", exception);
        }
    }

    private static int normalizePort(int configuredPort, String scheme) {
        int port = configuredPort >= 0 ? configuredPort : "https".equals(scheme) ? 443 : 80;
        if (port < 1 || port > 65535) {
            throw new TlsOriginException("TLS origin port must be between 1 and 65535.");
        }
        return port;
    }

    private static boolean containsUnsafeHostCharacter(String host) {
        for (int index = 0; index < host.length(); index++) {
            char character = host.charAt(index);
            if (Character.isISOControl(character) || Character.isWhitespace(character)
                    || character == '/' || character == '\\' || character == '?'
                    || character == '#') {
                return true;
            }
        }
        return false;
    }

    private static boolean isLocalHost(String host) {
        return "localhost".equals(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host);
    }
}
