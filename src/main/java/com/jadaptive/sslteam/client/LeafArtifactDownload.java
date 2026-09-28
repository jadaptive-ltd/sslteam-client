package com.jadaptive.sslteam.client;

import java.util.UUID;

public record LeafArtifactDownload(UUID issuanceId, byte[] archive) {

    public LeafArtifactDownload {
        if (issuanceId == null) {
            throw new IllegalArgumentException("issuanceId is required");
        }
        if (archive == null || archive.length == 0) {
            throw new IllegalArgumentException("leaf artifact ZIP is empty");
        }
        archive = archive.clone();
    }

    @Override
    public byte[] archive() {
        return archive.clone();
    }
}