package com.jadaptive.sslteam.client.tls.discovery;

import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Captures a peer leaf certificate using a TLS handshake that cannot send HTTP bytes.
 *
 * <p>The temporary trust manager records the presented public chain and deliberately aborts the
 * handshake from its trust callback. It is not a trust-all path: no certificate is accepted, no
 * application protocol is negotiated, no credentials are attached, and the socket is closed
 * before a caller receives the result. The result is an ephemeral input to explicit operator
 * approval; this class does not persist pins or create authenticated clients.</p>
 */
public final class CertificateDiscovery {

    private static final Logger LOG = Logger.getLogger(CertificateDiscovery.class.getName());
    private final Duration handshakeTimeout;

    /**
     * Creates discovery with the configured bounded TLS handshake timeout.
     *
     * @param handshakeTimeout maximum time allowed for socket connect and handshake
     */
    public CertificateDiscovery() {
        this(Duration.ofSeconds(5));
    }

    /**
     * Creates a deterministic testable discovery component with a bounded timeout.
     *
     * @param handshakeTimeout maximum time allowed for socket connect and handshake
     */
    public CertificateDiscovery(Duration handshakeTimeout) {
        if (handshakeTimeout == null || handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
            throw new TlsDiscoveryException("TLS discovery timeout must be positive.");
        }
        this.handshakeTimeout = handshakeTimeout;
    }

    /**
     * Performs TLS-only certificate discovery for one HTTPS origin.
     *
     * @param origin normalized HTTPS origin; plaintext origins are rejected before socket creation
     * @return ephemeral public leaf certificate and origin
     * @throws TlsDiscoveryException when no certificate can be captured or transport fails
     */
    public TlsDiscoveryResult discover(TlsOrigin origin) {
        if (origin == null || !"https".equals(origin.scheme())) {
            throw new TlsDiscoveryException("TLS discovery requires an HTTPS origin.");
        }

        CapturingRejectingTrustManager trustManager = new CapturingRejectingTrustManager();
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager}, null);
            SSLSocketFactory socketFactory = context.getSocketFactory();
            try (Socket rawSocket = socketFactory.createSocket()) {
                rawSocket.setSoTimeout(toTimeoutMillis(handshakeTimeout));
                rawSocket.connect(new InetSocketAddress(origin.host(), origin.port()), toTimeoutMillis(handshakeTimeout));
                try (SSLSocket socket = (SSLSocket) rawSocket) {
                    socket.setSoTimeout(toTimeoutMillis(handshakeTimeout));
                    socket.startHandshake();
                }
            } catch (IOException expectedHandshakeAbort) {
                // The rejecting trust manager intentionally aborts after recording the peer chain.
                LOG.log(Level.FINE, "TLS certificate discovery handshake ended: origin={0} certificateCaptured={1}",
                    new Object[]{origin, trustManager.leaf() != null});
            }
        } catch (GeneralSecurityException exception) {
            throw new TlsDiscoveryException("Unable to initialize TLS certificate discovery.", exception);
        }

        X509Certificate leaf = trustManager.leaf();
        if (leaf == null) {
            throw new TlsDiscoveryException("TLS discovery did not receive a server certificate.");
        }
        LOG.log(Level.INFO, "TLS certificate discovered: origin={0} fingerprintAvailable=true", origin);
        return new TlsDiscoveryResult(origin, leaf);
    }

    private static int toTimeoutMillis(Duration timeout) {
        try {
            long millis = timeout.toMillis();
            if (millis < 1 || millis > Integer.MAX_VALUE) {
                throw new TlsDiscoveryException("TLS discovery timeout is outside the supported range.");
            }
            return (int) millis;
        } catch (ArithmeticException exception) {
            throw new TlsDiscoveryException("TLS discovery timeout is outside the supported range.", exception);
        }
    }

    private static final class CapturingRejectingTrustManager extends X509ExtendedTrustManager {
        private volatile X509Certificate[] chain;

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("TLS discovery does not accept client certificates.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            captureAndAbort(chain);
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

        private void captureAndAbort(X509Certificate[] presentedChain) throws CertificateException {
            if (presentedChain == null || presentedChain.length == 0 || presentedChain[0] == null) {
                throw new CertificateException("The server presented no certificate.");
            }
            chain = presentedChain.clone();
            throw new CertificateException("TLS discovery intentionally stopped before trust acceptance.");
        }

        private X509Certificate leaf() {
            X509Certificate[] captured = chain;
            return captured == null || captured.length == 0 ? null : captured[0];
        }
    }
}
