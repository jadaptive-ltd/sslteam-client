package com.sslteam.client;

public record AuthTokenRequest(String username, String password, String clientId) {
}