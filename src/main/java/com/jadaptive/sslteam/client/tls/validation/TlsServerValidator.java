package com.jadaptive.sslteam.client.tls.validation;

import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import com.jadaptive.sslteam.client.tls.transport.TlsTransportException;
import com.jadaptive.sslteam.client.tls.trust.TlsTrustContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import javax.net.ssl.SSLSocket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Validates one HTTPS server with an already-selected trust context and sends no HTTP bytes.
 *
 * <p>This component owns the trust-store enrollment validation phase. It accepts only a normalized
 * HTTPS origin and a context created for that origin's selected trust profile, applies the context's
 * {@code HTTPS} endpoint-identification parameters to the socket, performs one bounded TLS
 * handshake, and closes the socket before returning. It carries no credentials, does not persist
 * profiles, and never retries a certificate or hostname policy failure. Transport failures retain
 * their throwable for the command boundary's diagnostic log while exposing only a bounded message
 * to the operator.</p>
 */
public final class TlsServerValidator {

    private static final Logger LOG = Logger.getLogger(TlsServerValidator.class.getName());
    private final Duration handshakeTimeout;

    /**
     * Creates the validator with the configured bounded handshake timeout.
     *
     * @param handshakeTimeout ISO-8601 duration for connect and TLS handshake operations
     */
    public TlsServerValidator() {
        this(Duration.ofSeconds(5));
    }

    /**
     * Creates a validator with a bounded timeout for deterministic tests.
     *
     * @param handshakeTimeout positive timeout applied to socket connect and read operations
     */
    public TlsServerValidator(Duration handshakeTimeout) {
        if (handshakeTimeout == null || handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
            throw new TlsTransportException("TLS server-validation timeout must be positive.", null);
        }
        this.handshakeTimeout = handshakeTimeout;
    }

    /**
     * Performs one trust-and-hostname validation handshake for an HTTPS origin.
     *
     * @param origin normalized HTTPS origin whose host identity is verified by JSSE
     * @param context disposable trust context selected for the same origin
     * @throws TlsTransportException when the certificate, hostname, trust anchor, or transport
     *                               cannot be validated; no HTTP request is sent
     */
    public void validate(TlsOrigin origin, TlsTrustContext context) {
        if (origin == null || !"https".equals(origin.scheme())) {
            throw new TlsTransportException("TLS server validation requires an HTTPS origin.", null);
        }
        if (context == null) {
            throw new TlsTransportException("TLS server validation requires a selected trust context.", null);
        }

        int timeoutMillis = toTimeoutMillis(handshakeTimeout);
        try (Socket rawSocket = context.sslContext().getSocketFactory().createSocket()) {
            rawSocket.setSoTimeout(timeoutMillis);
            rawSocket.connect(new InetSocketAddress(origin.host(), origin.port()), timeoutMillis);
            try (SSLSocket socket = (SSLSocket) rawSocket) {
                socket.setSSLParameters(context.sslParameters());
                socket.setSoTimeout(timeoutMillis);
                socket.startHandshake();
            }
            LOG.log(Level.INFO, "TLS server validation succeeded: origin={0} httpRequestSent=false", origin);
        } catch (IOException exception) {
            throw new TlsTransportException(
                    "TLS server validation failed for " + origin + ". No HTTP request was sent.", exception);
        }
    }

    private static int toTimeoutMillis(Duration timeout) {
        try {
            long millis = timeout.toMillis();
            if (millis < 1 || millis > Integer.MAX_VALUE) {
                throw new TlsTransportException("TLS server-validation timeout is outside the supported range.", null);
            }
            return (int) millis;
        } catch (ArithmeticException exception) {
            throw new TlsTransportException("TLS server-validation timeout is outside the supported range.", exception);
        }
    }
}
