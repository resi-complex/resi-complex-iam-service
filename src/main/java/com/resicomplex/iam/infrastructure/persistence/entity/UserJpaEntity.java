package com.resicomplex.iam.infrastructure.persistence.entity;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "users")
public class UserJpaEntity {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "email", length = 255, nullable = false, unique = true)
    private String email;

    @Column(name = "name", length = 120)
    private String name;

    @Column(name = "password_hash", length = 255, nullable = false)
    private String passwordHash;

    @Column(name = "role", length = 20, nullable = false)
    private String role;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "person_id", length = 36)
    private String personId;

    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "activation_token_hash", length = 255)
    private String activationTokenHash;

    @Column(name = "activation_expires_at")
    private Instant activationExpiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    public UserJpaEntity() {
    }

    public static UserJpaEntity fromDomain(UserAccount domain) {
        UserJpaEntity entity = new UserJpaEntity();
        entity.id = domain.id();
        entity.email = domain.email();
        entity.name = domain.name();
        entity.passwordHash = domain.passwordHash();
        entity.role = domain.role().name();
        entity.personId = domain.personId();
        entity.status = domain.status().name();
        entity.emailVerified = domain.emailVerified();
        entity.failedAttempts = domain.failedAttempts();
        entity.lockedUntil = domain.lockedUntil();
        entity.activationTokenHash = domain.activationTokenHash();
        entity.activationExpiresAt = domain.activationExpiresAt();
        entity.createdAt = domain.createdAt();
        entity.updatedAt = domain.updatedAt();
        entity.deletedAt = domain.deletedAt();
        return entity;
    }

    public UserAccount toDomain() {
        return new UserAccount(
            id,
            email,
            name,
            passwordHash,
            UserRole.fromValue(role),
            personId,
            UserStatus.fromValue(status),
            emailVerified,
            failedAttempts,
            lockedUntil,
            activationTokenHash,
            activationExpiresAt,
            createdAt,
            updatedAt,
            deletedAt
        );
    }
}
