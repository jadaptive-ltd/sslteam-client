package com.jadaptive.sslteam.client;

/**
 * Bounded response from the authenticated SSLTeam health endpoint.
 *
 * @param message public server response message
 */
public record PingResponse(String message) {
}