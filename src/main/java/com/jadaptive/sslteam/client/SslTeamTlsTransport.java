package com.jadaptive.sslteam.client;

import com.jadaptive.sslteam.client.tls.origin.TlsOrigin;
import com.jadaptive.sslteam.client.tls.persistence.TlsTrustProfileStore;
import com.jadaptive.sslteam.client.tls.profile.TlsTrustMode;
import com.jadaptive.sslteam.client.tls.profile.TlsTrustProfile;
import com.jadaptive.sslteam.client.tls.transport.TlsTransportException;
import com.jadaptive.sslteam.client.tls.trust.TlsTrustContext;
import com.jadaptive.sslteam.client.tls.trust.TlsTrustContextException;
import com.jadaptive.sslteam.client.tls.trust.TlsTrustContextFactory;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Origin-scoped JDK transport supporting SYSTEM, TOFU, and public trust-store profiles.
 *
 * <p>The transport owns TLS policy application and HTTP client lifecycle. It reads validated
 * profiles from the caller-provided store, creates a disposable trust context for each effective
 * profile, preserves HTTPS hostname verification, and never performs discovery or approval. A
 * profile change replaces the cached client for that exact origin before the next request.</p>
 */
public final class SslTeamTlsTransport implements SslTeamHttpTransport {

    private static final Logger LOG = Logger.getLogger(SslTeamTlsTransport.class.getName());
    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(4);

    private final TlsTrustProfileStore profileStore;
    private final TlsTrustContextFactory trustContextFactory;
    private final Duration connectTimeout;
    private final ConcurrentMap<TlsOrigin, ClientEntry> clientsByOrigin = new ConcurrentHashMap<>();

    /** Creates a transport with caller-owned profile persistence and a bounded connect timeout. */
    public SslTeamTlsTransport(TlsTrustProfileStore profileStore) {
        this(profileStore, new TlsTrustContextFactory(), DEFAULT_CONNECT_TIMEOUT);
    }

    /** Creates a transport with explicit trust-context construction and connection timeout. */
    public SslTeamTlsTransport(
            TlsTrustProfileStore profileStore,
            TlsTrustContextFactory trustContextFactory,
            Duration connectTimeout) {
        this.profileStore = Objects.requireNonNull(profileStore, "profileStore");
        this.trustContextFactory = Objects.requireNonNull(trustContextFactory, "trustContextFactory");
        if (connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()) {
            throw new IllegalArgumentException("connectTimeout must be positive");
        }
        this.connectTimeout = connectTimeout;
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        try {
            HttpResponse<T> response = clientFor(request.uri()).send(request, responseBodyHandler);
            LOG.log(Level.FINE, "SSLTeam TLS transport response: method={0} uri={1} status={2}",
                    new Object[]{request.method(), request.uri(), response.statusCode()});
            return response;
        } catch (IOException exception) {
            if (isTlsFailure(exception)) {
                throw new TlsTransportException(
                        "TLS verification failed for " + request.uri().getScheme() + "://"
                                + request.uri().getAuthority() + ". No request was sent.", exception);
            }
            throw exception;
        }
    }

    private HttpClient clientFor(URI requestUri) {
        TlsOrigin origin = TlsOrigin.normalize(requestUri.getScheme() + "://" + requestUri.getAuthority());
        if (!"https".equalsIgnoreCase(requestUri.getScheme())) {
            return clientsByOrigin.computeIfAbsent(origin,
                    ignored -> new ClientEntry(null, HttpClient.newBuilder()
                        .connectTimeout(connectTimeout)
                        .version(HttpClient.Version.HTTP_1_1)
                        .build())).client();
        }
        TlsTrustProfile profile = profileStore.findTlsProfile(origin)
                .orElseGet(() -> TlsTrustProfile.system(origin));
        return clientsByOrigin.compute(origin, (ignored, existing) -> existing != null
                && profile.equals(existing.profile())
                        ? existing
                        : createProfileClient(origin, profile)).client();
    }

    private ClientEntry createProfileClient(TlsOrigin origin, TlsTrustProfile profile) {
        try {
            LOG.log(Level.FINE, "TLS profile selected: origin={0} mode={1} persisted={2}",
                    new Object[]{origin, profile.mode(), profile.mode() != TlsTrustMode.SYSTEM});
            TlsTrustContext context = trustContextFactory.create(profile);
            return new ClientEntry(profile,
                    context.httpClientBuilder()
                        .connectTimeout(connectTimeout)
                        .version(HttpClient.Version.HTTP_1_1)
                        .build());
        } catch (TlsTrustContextException exception) {
            throw new TlsTransportException(
                    "Unable to configure TLS for " + origin + ". No request was sent.", exception);
        }
    }

    private static boolean isTlsFailure(Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 8; depth++) {
            if (current instanceof javax.net.ssl.SSLException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private record ClientEntry(TlsTrustProfile profile, HttpClient client) {
    }
}