package com.resicomplex.iam.infrastructure.persistence.entity;

import com.resicomplex.iam.domain.model.RefreshTokenRecord;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenJpaEntity {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "token_family_id", length = 36, nullable = false)
    private String tokenFamilyId;

    @Column(name = "token_hash", length = 255, nullable = false)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "replaced_by", length = 36)
    private String replacedBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public RefreshTokenJpaEntity() {
    }

    public static RefreshTokenJpaEntity fromDomain(RefreshTokenRecord domain) {
        RefreshTokenJpaEntity entity = new RefreshTokenJpaEntity();
        entity.id = domain.id();
        entity.userId = domain.userId();
        entity.tokenFamilyId = domain.tokenFamilyId();
        entity.tokenHash = domain.tokenHash();
        entity.expiresAt = domain.expiresAt();
        entity.revokedAt = domain.revokedAt();
        entity.replacedBy = domain.replacedBy();
        entity.createdAt = domain.createdAt();
        return entity;
    }

    public RefreshTokenRecord toDomain() {
        return new RefreshTokenRecord(
            id,
            userId,
            tokenFamilyId,
            tokenHash,
            expiresAt,
            revokedAt,
            replacedBy,
            createdAt
        );
    }
}
