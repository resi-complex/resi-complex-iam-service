package com.resicomplex.iam.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable Refresh Token domain entity supporting single-use rotation
 * and token-family reuse breach revocation (00-governance/security-policy.md).
 */
public record RefreshTokenRecord(
    String id,
    String userId,
    String tokenFamilyId,
    String tokenHash,
    Instant expiresAt,
    Instant revokedAt,
    String replacedBy,
    Instant createdAt
) {

    public RefreshTokenRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tokenFamilyId, "tokenFamilyId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public RefreshTokenRecord revoke(String successorTokenId, Instant now) {
        return new RefreshTokenRecord(
            id,
            userId,
            tokenFamilyId,
            tokenHash,
            expiresAt,
            now,
            successorTokenId,
            createdAt
        );
    }
}
