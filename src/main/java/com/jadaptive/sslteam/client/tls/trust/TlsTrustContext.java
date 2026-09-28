package com.jadaptive.sslteam.client.tls.trust;

import java.net.http.HttpClient;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Per-profile TLS material for an ordinary CLI HTTPS client.
 *
 * <p>The context is created for one normalized origin and one already validated trust profile. Its
 * trust manager accepts only the selected system anchors, configured public PEM anchors, or the
 * exact approved TOFU certificate fingerprint. HTTPS endpoint identification is explicitly enabled
 * in the associated parameters, so trust does not replace hostname/SAN validation. The context
 * carries no credentials and performs no network I/O; callers should discard it with the client
 * when the effective profile changes. Use {@link #httpClientBuilder()} to create a client scoped to
 * this trust decision.</p>
 */
public final class TlsTrustContext {

    private final SSLContext sslContext;
    private final SSLParameters sslParameters;
    private final X509ExtendedTrustManager trustManager;

    TlsTrustContext(SSLContext sslContext, SSLParameters sslParameters, X509ExtendedTrustManager trustManager) {
        this.sslContext = sslContext;
        this.sslParameters = sslParameters;
        this.trustManager = trustManager;
    }

    /**
     * Returns the per-profile JSSE context used by the client builder.
     *
     * @return initialized context containing only the selected public trust decision
     */
    public SSLContext sslContext() {
        return sslContext;
    }

    /**
     * Returns HTTPS endpoint-identification parameters for the selected client.
     *
     * @return parameters with endpoint identification set to {@code HTTPS}
     */
    public SSLParameters sslParameters() {
        return sslParameters;
    }

    /**
     * Returns the selected trust manager to package-owned policy tests.
     *
     * <p>This is intentionally not public transport API. It permits deterministic tests of trust
     * acceptance and rejection without opening a socket or claiming a live handshake.</p>
     *
     * @return trust manager installed in this context
     */
    X509ExtendedTrustManager trustManager() {
        return trustManager;
    }

    /**
     * Creates a JDK client builder carrying this profile's context and hostname policy.
     *
     * @return builder that has not opened a socket or sent a request
     */
    public HttpClient.Builder httpClientBuilder() {
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(sslParameters);
    }
}
