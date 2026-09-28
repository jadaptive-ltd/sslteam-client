package com.jadaptive.sslteam.client;

/** JSON request for the server token endpoint; the client uses the CLI session channel. */
public record AuthTokenRequest(String username, String password, String channel) {
}