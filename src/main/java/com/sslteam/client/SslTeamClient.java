package com.sslteam.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sslteam.cert.api.audit.CertificateAuditEntry;
import com.sslteam.cert.api.contract.intermediate.IntermediateCurrentResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediateHistoryResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediatePendingRequestsResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediateProvisioningRequest;
import com.sslteam.cert.api.contract.intermediate.IntermediateProvisioningResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediateRetireRequest;
import com.sslteam.cert.api.contract.intermediate.IntermediateRetireResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediateRevokeRequest;
import com.sslteam.cert.api.contract.intermediate.IntermediateRevokeResponse;
import com.sslteam.cert.api.contract.intermediate.IntermediateSignedImportRequest;
import com.sslteam.cert.api.contract.intermediate.IntermediateSignedImportResponse;
import com.sslteam.cert.api.contract.inventory.CaCertificateInventoryResponse;
import com.sslteam.cert.api.contract.leaf.LeafArtifactDownloadRequest;
import com.sslteam.cert.api.contract.leaf.LeafGenerateRequest;
import com.sslteam.cert.api.contract.leaf.LeafListResponse;
import com.sslteam.cert.api.contract.leaf.LeafRevokeRequest;
import com.sslteam.cert.api.contract.leaf.LeafRevokeResponse;
import com.sslteam.cert.api.contract.root.RootCaSetupCompletionRequest;
import com.sslteam.cert.api.contract.root.RootCaSetupRequest;
import com.sslteam.cert.api.contract.root.RootCaSetupResponse;
import com.sslteam.cert.api.contract.root.RootCertificateResponse;
import com.sslteam.cert.api.contract.root.RootRetireRequest;
import com.sslteam.cert.api.contract.root.RootRetireResponse;
import com.sslteam.cert.api.contract.root.RootRevokeRequest;
import com.sslteam.cert.api.contract.root.RootRevokeResponse;
import com.sslteam.cert.api.contract.scope.PkiScope;
import com.sslteam.client.tls.persistence.TlsTrustProfileStore;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Framework-neutral entry point for the SSLTeam server API.
 *
 * <p>The client owns endpoint paths, JSON contracts, correlation IDs, bounded timeouts, response
 * validation, and retry classification. TLS trust selection remains owned by the supplied
 * transport so a CLI or another application can enforce origin-scoped policy.</p>
 */
public class SslTeamClient {

    private static final Logger LOG = Logger.getLogger(SslTeamClient.class.getName());
    private static final String CORRELATION_HEADER = "X-SSL-Teams-Correlation-Id";
    private static final int MAX_IO_RETRIES = 3;
    private static final long RETRY_BACKOFF_MILLIS = 800L;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final SslTeamHttpTransport transport;
    private final ObjectMapper mapper;

    /**
     * Creates a client with reusable origin-scoped SYSTEM, TOFU, and trust-store TLS policy.
     *
     * @param profileStore caller-owned persistence for validated public TLS profiles
     */
    public SslTeamClient(TlsTrustProfileStore profileStore) {
        this(new SslTeamTlsTransport(profileStore));
    }

    /**
     * Creates a client using caller-owned transport and TLS policy.
     *
     * @param transport transport that enforces the consumer's TLS and network policy
     */
    public SslTeamClient(SslTeamHttpTransport transport) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /**
     * Calls the authenticated server ping endpoint.
     *
     * @param baseUrl HTTPS server origin, or HTTP localhost for local development
     * @param accessToken bearer access token; never logged or persisted by this client
     * @return bounded public ping response
     * @throws SslTeamHttpException when the server rejects the request
     * @throws SslTeamUnavailableException when retryable I/O remains unavailable
     */
    public PingResponse ping(String baseUrl, String accessToken) {
        URI baseUri = requireBaseUri(baseUrl);
        HttpRequest request = authorizedRequest(endpoint(baseUri, "/api/v1/auth/ping"), accessToken)
                .GET()
                .build();
        return sendJson(request, PingResponse.class);
    }

    /**
     * Exchanges a refresh token for a new token pair.
     *
     * @param baseUrl HTTPS server origin, or HTTP localhost for local development
     * @param refreshToken refresh credential; never logged or persisted by this client
     * @return token response for caller-owned secure session handling
     * @throws SslTeamHttpException when the server rejects the refresh
     * @throws SslTeamUnavailableException when the server remains unavailable
     */
    public AuthTokenResponse refresh(String baseUrl, String refreshToken) {
        URI baseUri = requireBaseUri(baseUrl);
        HttpRequest request = jsonPost(
                endpoint(baseUri, "/api/v1/auth/refresh"),
            new AuthRefreshRequest(refreshToken),
                null);
        return sendJson(request, AuthTokenResponse.class);
    }

    /**
     * Issues a CLI-channel access token using the server's username/password token endpoint.
     *
     * @param baseUrl HTTPS server origin, or HTTP localhost for local development
     * @param username operator username
     * @param password operator password; never logged or persisted by this client
     * @return token response for caller-owned secure session handling
     * @throws SslTeamHttpException when the server rejects authentication
     * @throws SslTeamUnavailableException when the server remains unavailable
     */
    public AuthTokenResponse login(String baseUrl, String username, String password) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/auth/token"),
            new AuthTokenRequest(username, password, "CLI"), null), AuthTokenResponse.class);
    }

    public DeviceAuthorizationStartResponse startDeviceAuthorization(String baseUrl, String clientId, String scope) {
        URI baseUri = requireBaseUri(baseUrl);
        String body = "client_id=" + urlEncode(clientId)
            + (scope == null || scope.isBlank() ? "" : "&scope=" + urlEncode(scope));
        return sendJson(formPost(endpoint(baseUri, "/oauth/device_authorization"), body),
            DeviceAuthorizationStartResponse.class);
    }

        public DeviceTokenPollResult exchangeDeviceCode(String baseUrl, String clientId, String deviceCode) {
        URI baseUri = requireBaseUri(baseUrl);
        String body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code")
            + "&device_code=" + urlEncode(deviceCode)
            + "&client_id=" + urlEncode(clientId);
        HttpRequest request = formPost(endpoint(baseUri, "/oauth/token"), body);
        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString());
        try {
            if (response.statusCode() < 400) {
            return DeviceTokenPollResult.success(mapper.readValue(response.body(), AuthTokenResponse.class));
            }
            return DeviceTokenPollResult.error(
                mapper.readValue(response.body(), OAuthErrorResponse.class), response.statusCode());
        } catch (IOException exception) {
            throw new SslTeamClientException("SSLTeam server returned an invalid device-flow response.", exception);
        }
        }

        public void logout(String baseUrl, String accessToken, String refreshToken) {
        URI baseUri = requireBaseUri(baseUrl);
        sendNoContent(jsonPost(endpoint(baseUri, "/api/v1/auth/logout"),
                new AuthRefreshRequest(refreshToken), accessToken));
        }

        public void logoutAll(String baseUrl, String accessToken) {
        URI baseUri = requireBaseUri(baseUrl);
        sendNoContent(authorizedRequest(endpoint(baseUri, "/api/v1/auth/logout-all"), accessToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build());
        }

        public void changePassword(String baseUrl, String accessToken, AuthPasswordChangeRequest payload) {
        URI baseUri = requireBaseUri(baseUrl);
        sendNoContent(jsonPost(endpoint(baseUri, "/api/v1/auth/password/change"), payload, accessToken));
        }

        public JwtVerifierPublicKeyResponse fetchJwtVerifierPublicKey(String baseUrl) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(unauthorizedRequest(endpoint(baseUri, "/api/v1/auth/public-key"))
            .GET().build(), JwtVerifierPublicKeyResponse.class);
        }

        public RootCaSetupResponse setupApplicationRoot(
            String baseUrl, String accessToken, PkiScope scope, String commonName,
            String organization, String organizationalUnit) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/application-ca/setup"),
            new RootCaSetupRequest(scope, commonName, organization, organizationalUnit), accessToken),
            RootCaSetupResponse.class);
        }

        public ApplicationCaStatusResponse completeApplicationRootSetup(
            String baseUrl, String accessToken, PkiScope scope, long expectedVersion) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/application-ca/complete"),
            new RootCaSetupCompletionRequest(scope, expectedVersion, true), accessToken),
            ApplicationCaStatusResponse.class);
        }

        public ApplicationCaStatusResponse applicationCaStatus(String baseUrl, String accessToken, PkiScope scope) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(authorizedRequest(endpoint(baseUri, "/api/v1/cert/application-ca/status?teamCode="
            + urlEncode(scope.team()) + "&environment=" + urlEncode(scope.environment())), accessToken)
            .GET().build(), ApplicationCaStatusResponse.class);
        }

        public RootCertificateResponse applicationRoot(
            String baseUrl, String accessToken, String teamCode, String environment) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(authorizedRequest(endpoint(baseUri, "/api/v1/cert/application-ca/root?teamCode="
            + urlEncode(teamCode) + "&environment=" + urlEncode(environment)), accessToken)
            .GET().build(), RootCertificateResponse.class);
        }

        public byte[] downloadApplicationRootCertificate(
            String baseUrl, String accessToken, String teamCode, String environment) {
        URI baseUri = requireBaseUri(baseUrl);
        HttpRequest request = authorizedRequest(endpoint(baseUri,
            "/api/v1/cert/application-ca/root/certificate?teamCode=" + urlEncode(teamCode)
                + "&environment=" + urlEncode(environment)), accessToken).GET().build();
        return requireSuccessfulBytes(request, send(request, HttpResponse.BodyHandlers.ofByteArray()),
            "Application Root certificate download");
        }

        public RootRetireResponse retireApplicationRoot(
            String baseUrl, String accessToken, String teamCode, String environment,
            long expectedVersion, long expectedFamilyVersion, String reason) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/application-ca/root/retire"),
            new RootRetireRequest(new PkiScope(teamCode, environment), expectedVersion, expectedFamilyVersion, reason),
            accessToken), RootRetireResponse.class);
        }

        public RootRevokeResponse revokeApplicationRoot(
            String baseUrl, String accessToken, String teamCode, String environment,
            long expectedVersion, long expectedFamilyVersion, String reason) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/application-ca/root/revoke"),
            new RootRevokeRequest(new PkiScope(teamCode, environment), expectedVersion, expectedFamilyVersion, reason),
            accessToken), RootRevokeResponse.class);
        }

        public IntermediateProvisioningResponse createIntermediateRequest(
            String baseUrl, String accessToken, IntermediateProvisioningRequest payload) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/intermediates/requests"), payload, accessToken),
            IntermediateProvisioningResponse.class);
        }

        public IntermediateCurrentResponse currentIntermediate(
            String baseUrl, String accessToken, String teamCode, String environment) {
        return sendJson(get(baseUrl, "/api/v1/cert/intermediates/current?teamCode=" + urlEncode(teamCode)
            + "&environment=" + urlEncode(environment), accessToken), IntermediateCurrentResponse.class);
        }

        public byte[] downloadIntermediateCertificate(
            String baseUrl, String accessToken, String teamCode, String environment) {
        return downloadIntermediateMaterial(baseUrl, accessToken, teamCode, environment, "certificate");
        }

        public byte[] downloadIntermediateChain(
            String baseUrl, String accessToken, String teamCode, String environment) {
        return downloadIntermediateMaterial(baseUrl, accessToken, teamCode, environment, "chain");
        }

        public IntermediateHistoryResponse intermediateHistory(
            String baseUrl, String accessToken, String teamCode, String environment) {
        return sendJson(get(baseUrl, "/api/v1/cert/intermediates/history?teamCode=" + urlEncode(teamCode)
            + "&environment=" + urlEncode(environment), accessToken), IntermediateHistoryResponse.class);
        }

        public IntermediatePendingRequestsResponse pendingIntermediateRequests(
            String baseUrl, String accessToken, String teamCode, String environment, String name) {
        String path = "/api/v1/cert/intermediates/requests?teamCode=" + urlEncode(teamCode)
            + "&environment=" + urlEncode(environment)
            + (name == null || name.isBlank() ? "" : "&name=" + urlEncode(name));
        return sendJson(get(baseUrl, path, accessToken), IntermediatePendingRequestsResponse.class);
        }

        public IntermediateSignedImportResponse importSignedIntermediate(
            String baseUrl, String accessToken, String requestId, IntermediateSignedImportRequest payload) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/intermediates/requests/" + urlEncode(requestId) + "/signed"),
            payload, accessToken), IntermediateSignedImportResponse.class);
        }

        public IntermediateSignedImportResponse importSignedIntermediateByName(
            String baseUrl, String accessToken, String teamCode, String environment, String name,
            IntermediateSignedImportRequest payload) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/intermediates/by-name/" + urlEncode(name)
            + "/signed?teamCode=" + urlEncode(teamCode) + "&environment=" + urlEncode(environment)),
            payload, accessToken), IntermediateSignedImportResponse.class);
        }

        public IntermediateRetireResponse retireIntermediate(
            String baseUrl, String accessToken, String teamCode, String environment, UUID intermediateId,
            long expectedVersion, long expectedFamilyVersion, String reason) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/intermediates/" + intermediateId
            + "/retire?teamCode=" + urlEncode(teamCode) + "&environment=" + urlEncode(environment)),
            new IntermediateRetireRequest(expectedVersion, expectedFamilyVersion, reason), accessToken),
            IntermediateRetireResponse.class);
        }

        public IntermediateRevokeResponse revokeIntermediate(
            String baseUrl, String accessToken, String teamCode, String environment, UUID intermediateId,
            long expectedVersion, long expectedFamilyVersion, String reason) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/intermediates/" + intermediateId
            + "/revoke?teamCode=" + urlEncode(teamCode) + "&environment=" + urlEncode(environment)),
            new IntermediateRevokeRequest(expectedVersion, expectedFamilyVersion, reason), accessToken),
            IntermediateRevokeResponse.class);
        }

        public LeafArtifactDownload generateLeaf(String baseUrl, String accessToken, LeafGenerateRequest payload) {
        URI baseUri = requireBaseUri(baseUrl);
        HttpRequest request = jsonPost(endpoint(baseUri, "/api/v1/cert/leaves/generate"), payload, accessToken);
        HttpResponse<byte[]> response = send(request, HttpResponse.BodyHandlers.ofByteArray());
        ensureSuccessful(request, response);
        String issuanceId = response.headers().firstValue("X-SSL-Teams-Issuance-Id")
            .orElseThrow(() -> new SslTeamClientException("SSLTeam leaf response was missing its issuance identifier."));
        try {
            return new LeafArtifactDownload(UUID.fromString(issuanceId), response.body());
        } catch (IllegalArgumentException exception) {
            throw new SslTeamClientException("SSLTeam leaf response contained an invalid issuance identifier.", exception);
        }
        }

        public LeafListResponse listLeaves(String baseUrl, String accessToken, String teamCode, String environment) {
        return sendJson(get(baseUrl, "/api/v1/cert/leaves?teamCode=" + urlEncode(teamCode)
            + "&environment=" + urlEncode(environment), accessToken), LeafListResponse.class);
        }

        public byte[] downloadLeafCertificate(String baseUrl, String accessToken, UUID issuanceId) {
        return downloadLeafMaterial(baseUrl, accessToken, issuanceId, "certificate");
        }

        public byte[] downloadLeafChain(String baseUrl, String accessToken, UUID issuanceId) {
        return downloadLeafMaterial(baseUrl, accessToken, issuanceId, "chain");
        }

        public byte[] downloadLeafArtifact(
            String baseUrl, String accessToken, UUID issuanceId, String outputProfile, String pkcs12Password) {
        URI baseUri = requireBaseUri(baseUrl);
        HttpRequest request = jsonPost(endpoint(baseUri, "/api/v1/cert/leaves/" + issuanceId + "/artifact"),
            new LeafArtifactDownloadRequest(outputProfile, pkcs12Password), accessToken);
        return requireSuccessfulBytes(request, send(request, HttpResponse.BodyHandlers.ofByteArray()),
            "Leaf artifact download");
        }

        public LeafRevokeResponse revokeLeaf(
            String baseUrl, String accessToken, UUID issuanceId, long expectedVersion, String reason) {
        URI baseUri = requireBaseUri(baseUrl);
        return sendJson(jsonPost(endpoint(baseUri, "/api/v1/cert/leaves/" + issuanceId + "/revoke"),
            new LeafRevokeRequest(expectedVersion, reason), accessToken), LeafRevokeResponse.class);
        }

        public CaCertificateInventoryResponse caCertificateInventory(
            String baseUrl, String accessToken, PkiScope scope) {
        return sendJson(get(baseUrl, "/api/v1/cert/inventory?teamCode=" + urlEncode(scope.team())
            + "&environment=" + urlEncode(scope.environment()), accessToken), CaCertificateInventoryResponse.class);
        }

        public List<CertificateAuditEntry> listCertificateRevocations(
            String baseUrl, String accessToken, String teamCode, String environment, int limit) {
        return sendJson(get(baseUrl, "/api/v1/cert/audit/revocations?teamCode=" + urlEncode(teamCode)
            + "&environment=" + urlEncode(environment) + "&limit=" + limit, accessToken),
            mapper.getTypeFactory().constructCollectionType(List.class, CertificateAuditEntry.class));
        }

        private byte[] downloadIntermediateMaterial(
            String baseUrl, String accessToken, String teamCode, String environment, String material) {
        HttpRequest request = get(baseUrl, "/api/v1/cert/intermediates/current/" + material
            + "?teamCode=" + urlEncode(teamCode) + "&environment=" + urlEncode(environment), accessToken);
        return requireSuccessfulBytes(request, send(request, HttpResponse.BodyHandlers.ofByteArray()),
            "Intermediate " + material + " download");
        }

        private byte[] downloadLeafMaterial(
            String baseUrl, String accessToken, UUID issuanceId, String material) {
        HttpRequest request = get(baseUrl, "/api/v1/cert/leaves/" + issuanceId + "/" + material, accessToken);
        return requireSuccessfulBytes(request, send(request, HttpResponse.BodyHandlers.ofByteArray()),
            "Leaf " + material + " download");
        }

    private <T> T sendJson(HttpRequest request, Class<T> responseType) {
        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new SslTeamHttpException(
                    request.method(),
                    request.uri().toString(),
                    response.statusCode(),
                    correlationId(response), errorCode(response.body()), errorMessage(response.body()));
        }
        try {
            return mapper.readValue(response.body(), responseType);
        } catch (IOException exception) {
            throw new SslTeamClientException("SSLTeam server returned an invalid response.", exception);
        }
    }

    private <T> T sendJson(HttpRequest request, com.fasterxml.jackson.databind.JavaType responseType) {
        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new SslTeamHttpException(request.method(), request.uri().toString(), response.statusCode(),
                    correlationId(response), errorCode(response.body()), errorMessage(response.body()));
        }
        try {
            return mapper.readValue(response.body(), responseType);
        } catch (IOException exception) {
            throw new SslTeamClientException("SSLTeam server returned an invalid response.", exception);
        }
    }

    private void sendNoContent(HttpRequest request) {
        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new SslTeamHttpException(request.method(), request.uri().toString(), response.statusCode(),
                    correlationId(response), errorCode(response.body()), errorMessage(response.body()));
        }
    }

    private static void ensureSuccessful(HttpRequest request, HttpResponse<?> response) {
        if (response.statusCode() >= 400) {
            throw new SslTeamHttpException(request.method(), request.uri().toString(), response.statusCode(),
                    correlationId(response), null, null);
        }
    }

    private static byte[] requireSuccessfulBytes(HttpRequest request, HttpResponse<byte[]> response, String operation) {
        ensureSuccessful(request, response);
        if (response.body() == null || response.body().length == 0) {
            throw new SslTeamClientException(operation + " returned an empty response.");
        }
        return response.body();
    }

    private static HttpRequest formPost(String url, String body) {
        return HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(CORRELATION_HEADER, UUID.randomUUID().toString())
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static HttpRequest get(String baseUrl, String path, String accessToken) {
        URI baseUri = requireBaseUri(baseUrl);
        return authorizedRequest(endpoint(baseUri, path), accessToken).GET().build();
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value == null ? "" : value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String errorCode(String body) {
        try {
            String value = body == null ? null : new ObjectMapper().readTree(body).path("code").asText(null);
            return value != null && value.matches("[A-Z0-9_]{1,80}") ? value : null;
        } catch (IOException exception) {
            return null;
        }
    }

    private static String errorMessage(String body) {
        try {
            String value = body == null ? null : new ObjectMapper().readTree(body).path("message").asText(null);
            if (value == null || value.isBlank()) {
                return null;
            }
            String bounded = value.replaceAll("[\\r\\n\\t]+", " ").trim();
            return bounded.length() > 240 ? bounded.substring(0, 240) + "..." : bounded;
        } catch (IOException exception) {
            return null;
        }
    }

    private <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
        int maxAttempts = isIdempotent(request) ? MAX_IO_RETRIES : 1;
        IOException lastFailure = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                HttpResponse<T> response = transport.send(request, bodyHandler);
                LOG.log(Level.FINE, "SSLTeam response method={0} uri={1} status={2} correlationId={3}",
                        new Object[]{request.method(), request.uri(), response.statusCode(), correlationId(response)});
                return response;
            } catch (IOException exception) {
                lastFailure = exception;
                LOG.log(Level.WARNING, "SSLTeam transport I/O failure attempt=" + attempt
                        + "/" + maxAttempts + " method=" + request.method()
                        + " uri=" + request.uri(), exception);
                if (attempt < maxAttempts) {
                    waitBeforeRetry();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new SslTeamUnavailableException(attempt, exception);
            }
        }
        throw new SslTeamUnavailableException(maxAttempts, lastFailure);
    }

    private HttpRequest jsonPost(String url, Object payload, String accessToken) {
        String body;
        try {
            body = mapper.writeValueAsString(payload);
        } catch (JsonProcessingException exception) {
            throw new SslTeamClientException("SSLTeam request could not be prepared.", exception);
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .header(CORRELATION_HEADER, UUID.randomUUID().toString())
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (accessToken != null && !accessToken.isBlank()) {
            builder.header("Authorization", "Bearer " + accessToken);
        }
        return builder.build();
    }

    private static HttpRequest.Builder authorizedRequest(String url, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        return unauthorizedRequest(url)
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + accessToken);
    }

    private static HttpRequest.Builder unauthorizedRequest(String url) {
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header(CORRELATION_HEADER, UUID.randomUUID().toString());
    }

    private static URI requireBaseUri(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }
        URI uri;
        try {
            uri = URI.create(baseUrl.trim());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("baseUrl must be a valid absolute URI", exception);
        }
        if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || uri.getHost() == null || uri.getScheme() == null) {
            throw new IllegalArgumentException("baseUrl must be an origin without credentials, query, or fragment");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !isLocalHttp(uri)) {
            throw new IllegalArgumentException("baseUrl must use HTTPS unless it targets localhost");
        }
        return uri;
    }

    private static boolean isLocalHttp(URI uri) {
        if (!"http".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }
        String host = uri.getHost();
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "[::1]".equals(host)
                || "::1".equals(host);
    }

    private static String endpoint(URI baseUri, String path) {
        String base = baseUri.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + path;
    }

    private static boolean isIdempotent(HttpRequest request) {
        return switch (request.method().toUpperCase()) {
            case "GET", "HEAD", "OPTIONS" -> true;
            default -> false;
        };
    }

    private static String correlationId(HttpResponse<?> response) {
        return response.headers().firstValue(CORRELATION_HEADER).orElse("<absent>");
    }

    private static void waitBeforeRetry() {
        try {
            Thread.sleep(RETRY_BACKOFF_MILLIS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new SslTeamUnavailableException(1, exception);
        }
    }

    public record DeviceTokenPollResult(AuthTokenResponse tokens, OAuthErrorResponse error, int statusCode) {

        public static DeviceTokenPollResult success(AuthTokenResponse tokens) {
            return new DeviceTokenPollResult(tokens, null, 200);
        }

        public static DeviceTokenPollResult error(OAuthErrorResponse error, int statusCode) {
            return new DeviceTokenPollResult(null, error, statusCode);
        }

        public boolean successful() {
            return tokens != null;
        }
    }

}
