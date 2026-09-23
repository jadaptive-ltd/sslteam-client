package com.sslteam.client;

public record JwtVerifierPublicKeyResponse(String algorithm, String publicKeyPem) {
}