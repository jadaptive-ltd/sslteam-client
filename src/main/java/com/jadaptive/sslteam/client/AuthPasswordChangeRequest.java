package com.jadaptive.sslteam.client;

import java.util.UUID;

public record AuthPasswordChangeRequest(UUID userId, String currentPassword, String newPassword) {
}