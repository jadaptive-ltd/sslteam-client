package com.sslteam.client.tls.trust;

import com.sslteam.client.tls.certificate.CertificateFingerprint;
import com.sslteam.client.tls.certificate.PublicCertificatePemLoader;
import com.sslteam.client.tls.certificate.TlsCertificateException;
import com.sslteam.client.tls.profile.TlsTrustMode;
import com.sslteam.client.tls.profile.TlsTrustProfile;
import java.net.Socket;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Builds a disposable JSSE trust context from one validated, origin-scoped profile.
 *
 * <p>{@code SYSTEM} uses the JVM's default trust managers, {@code TRUST_STORE} loads only public
 * X.509 certificates from the configured PEM file, and {@code TOFU} accepts only the exact
 * approved leaf-certificate SHA-256 fingerprint. All modes retain HTTPS endpoint identification;
 * the TOFU manager does not trust every certificate and does not perform certificate discovery,
 * approval, persistence, or HTTP I/O. A caller must construct a new context after a profile change.
 * Certificate and provider failures are classified as bounded context errors with their causes
 * retained for diagnostic logging.</p>
 */
public final class TlsTrustContextFactory {

    private final PublicCertificatePemLoader pemLoader;

    /**
     * Creates a factory using the standard public PEM loader.
     *
     * @return factory with no opened files or initialized network resources
     */
    public TlsTrustContextFactory() {
        this(new PublicCertificatePemLoader());
    }

    TlsTrustContextFactory(PublicCertificatePemLoader pemLoader) {
        this.pemLoader = pemLoader;
    }

    /**
     * Builds a TLS context for the exact profile origin and trust mode.
     *
     * @param profile validated origin-scoped trust profile
     * @return initialized context with HTTPS endpoint identification enabled
     * @throws TlsTrustContextException if selected public trust material cannot be initialized
     */
    public TlsTrustContext create(TlsTrustProfile profile) {
        if (profile == null) {
            throw new TlsTrustContextException("A TLS trust profile is required.");
        }
        try {
            X509ExtendedTrustManager trustManager = switch (profile.mode()) {
                case SYSTEM -> systemTrustManager();
                case TOFU -> new PinnedCertificateTrustManager(profile.pinnedCertificateSha256());
                case TRUST_STORE -> trustStoreManager(profile.trustStorePath());
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            return new TlsTrustContext(sslContext, sslParameters, trustManager);
        } catch (GeneralSecurityException | TlsCertificateException exception) {
            throw new TlsTrustContextException("Unable to construct the selected TLS trust context.", exception);
        }
    }

    private X509ExtendedTrustManager trustStoreManager(Path path) throws GeneralSecurityException {
        List<X509Certificate> certificates = pemLoader.load(path);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            keyStore.load(null, null);
        } catch (java.io.IOException exception) {
            throw new GeneralSecurityException("Unable to initialize the in-memory trust store.", exception);
        }
        for (int index = 0; index < certificates.size(); index++) {
            keyStore.setCertificateEntry("certificate-" + index, certificates.get(index));
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return findX509TrustManager(trustManagerFactory.getTrustManagers());
    }

    private static X509ExtendedTrustManager systemTrustManager() throws GeneralSecurityException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        return findX509TrustManager(trustManagerFactory.getTrustManagers());
    }

    private static X509ExtendedTrustManager findX509TrustManager(TrustManager[] trustManagers) {
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509ExtendedTrustManager extended) {
                return extended;
            }
            if (trustManager instanceof X509TrustManager basic) {
                return new BasicTrustManagerAdapter(basic);
            }
        }
        throw new TlsTrustContextException("The selected TLS provider has no X.509 trust manager.");
    }

    private static final class PinnedCertificateTrustManager extends X509ExtendedTrustManager {

        private final String expectedFingerprint;

        private PinnedCertificateTrustManager(String expectedFingerprint) {
            this.expectedFingerprint = expectedFingerprint;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("Client certificate trust is not configured for this server context.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            verifyPinnedServerCertificate(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        private void verifyPinnedServerCertificate(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0 || chain[0] == null) {
                throw new CertificateException("The server presented no certificate.");
            }
            X509Certificate leaf = chain[0];
            try {
                leaf.checkValidity();
            } catch (CertificateException exception) {
                throw new CertificateException("The pinned server certificate is expired or not yet valid.", exception);
            }
            String presentedFingerprint = CertificateFingerprint.sha256(leaf);
            if (!expectedFingerprint.equals(presentedFingerprint)) {
                throw new CertificateException("The presented server certificate does not match the approved fingerprint.");
            }
        }
    }

    private static final class BasicTrustManagerAdapter extends X509ExtendedTrustManager {

        private final X509TrustManager delegate;

        private BasicTrustManagerAdapter(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) throws CertificateException {
            checkServerTrusted(chain, authType);
        }
    }
}
