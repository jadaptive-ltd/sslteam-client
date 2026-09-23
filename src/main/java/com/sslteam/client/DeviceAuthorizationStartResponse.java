package com.sslteam.client;

public record DeviceAuthorizationStartResponse(
        String deviceCode,
        String userCode,
        String verificationUri,
        String verificationUriComplete,
        long expiresIn,
        long interval) {
}