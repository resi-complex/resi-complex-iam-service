package com.resicomplex.iam.domain.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Objects;

/**
 * Pure Domain Aggregate Root for an IAM User account (no Spring or JPA dependencies).
 * Enforces immutability via copy-on-write state transitions.
 */
public record UserAccount(
    String id,
    String email,
    String name,
    String passwordHash,
    UserRole role,
    String personId,
    UserStatus status,
    boolean emailVerified,
    int failedAttempts,
    Instant lockedUntil,
    String activationTokenHash,
    Instant activationExpiresAt,
    Instant createdAt,
    Instant updatedAt,
    Instant deletedAt
) {

    public UserAccount {
        Objects.requireNonNull(id, "id must not be null");
        if (email == null || email.isBlank() || !email.contains("@")) {
            throw new IllegalArgumentException("Valid email is required");
        }
        email = email.trim().toLowerCase(Locale.ROOT);
        Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(status, "status must not be null");
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts cannot be negative");
        }
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public UserAccount recordLoginSuccess(Instant now) {
        return new UserAccount(
            id, email, name, passwordHash, role, personId, status,
            emailVerified, 0, null, activationTokenHash, activationExpiresAt,
            createdAt, now, deletedAt
        );
    }

    public UserAccount recordLoginFailure(int maxFailedAttempts, int lockoutMinutes, Instant now) {
        int nextAttempts = failedAttempts + 1;
        Instant nextLockedUntil = nextAttempts >= maxFailedAttempts
            ? now.plus(lockoutMinutes, ChronoUnit.MINUTES)
            : lockedUntil;
        return new UserAccount(
            id, email, name, passwordHash, role, personId, status,
            emailVerified, nextAttempts, nextLockedUntil, activationTokenHash, activationExpiresAt,
            createdAt, now, deletedAt
        );
    }

    public UserAccount activate(String newPasswordHash, Instant now) {
        Objects.requireNonNull(newPasswordHash, "newPasswordHash must not be null");
        return new UserAccount(
            id, email, name, newPasswordHash, role, personId, UserStatus.ACTIVE,
            true, 0, null, null, null,
            createdAt, now, deletedAt
        );
    }

    public UserAccount withProfileUpdate(String updatedName, UserStatus updatedStatus, String updatedPersonId, Instant now) {
        return new UserAccount(
            id,
            email,
            updatedName != null ? updatedName : name,
            passwordHash,
            role,
            updatedPersonId != null ? updatedPersonId : personId,
            updatedStatus != null ? updatedStatus : status,
            emailVerified,
            failedAttempts,
            lockedUntil,
            activationTokenHash,
            activationExpiresAt,
            createdAt,
            now,
            deletedAt
        );
    }

    public UserAccount withRole(UserRole newRole, Instant now) {
        Objects.requireNonNull(newRole, "newRole must not be null");
        return new UserAccount(
            id, email, name, passwordHash, newRole, personId, status,
            emailVerified, failedAttempts, lockedUntil, activationTokenHash, activationExpiresAt,
            createdAt, now, deletedAt
        );
    }

    public UserAccount softDelete(Instant now) {
        return new UserAccount(
            id, email, name, passwordHash, role, personId, UserStatus.INACTIVE,
            emailVerified, failedAttempts, lockedUntil, null, null,
            createdAt, now, now
        );
    }
}
