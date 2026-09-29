package com.jadaptive.sslteam.client;

/*-
 * #%L
 * SSLTeam Java Client
 * %%
 * Copyright (C) 2026 Jadaptive Limited
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

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
