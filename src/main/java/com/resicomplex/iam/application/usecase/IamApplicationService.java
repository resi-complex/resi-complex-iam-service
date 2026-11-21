package com.resicomplex.iam.application.usecase;

import com.resicomplex.iam.domain.exception.IamDomainException;
import com.resicomplex.iam.domain.model.OutboxEvent;
import com.resicomplex.iam.domain.model.RefreshTokenRecord;
import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import com.resicomplex.iam.domain.port.in.IamUseCasePort;
import com.resicomplex.iam.domain.port.out.OutboxRepositoryPort;
import com.resicomplex.iam.domain.port.out.PasswordHasherPort;
import com.resicomplex.iam.domain.port.out.RefreshTokenRepositoryPort;
import com.resicomplex.iam.domain.port.out.TokenProviderPort;
import com.resicomplex.iam.domain.port.out.UserRepositoryPort;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IamApplicationService implements IamUseCasePort {

    private final UserRepositoryPort userRepository;
    private final RefreshTokenRepositoryPort refreshTokenRepository;
    private final OutboxRepositoryPort outboxRepository;
    private final TokenProviderPort tokenProvider;
    private final PasswordHasherPort passwordHasher;
    private final long refreshExpirationDays;
    private final int maxFailedAttempts;
    private final int lockoutMinutes;

    public IamApplicationService(
        UserRepositoryPort userRepository,
        RefreshTokenRepositoryPort refreshTokenRepository,
        OutboxRepositoryPort outboxRepository,
        TokenProviderPort tokenProvider,
        PasswordHasherPort passwordHasher,
        @Value("${iam.jwt.refresh-expiration-days:7}") long refreshExpirationDays,
        @Value("${iam.security.max-failed-attempts:5}") int maxFailedAttempts,
        @Value("${iam.security.lockout-minutes:15}") int lockoutMinutes
    ) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.outboxRepository = outboxRepository;
        this.tokenProvider = tokenProvider;
        this.passwordHasher = passwordHasher;
        this.refreshExpirationDays = refreshExpirationDays;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockoutMinutes = lockoutMinutes;
    }

    @Override
    @Transactional
    public AuthTokensResult register(RegisterCommand command) {
        String normalizedEmail = normalizeEmail(command.email());
        validatePasswordComplexity(command.password());
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IamDomainException("EMAIL_ALREADY_EXISTS", "Email is already registered", 409);
        }

        Instant now = Instant.now();
        UserRole assignedRole = command.role() != null ? command.role() : UserRole.PERSON;
        UserAccount created = new UserAccount(
            UUID.randomUUID().toString(),
            normalizedEmail,
            command.name(),
            passwordHasher.hash(command.password()),
            assignedRole,
            command.personId(),
            UserStatus.ACTIVE,
            true,
            0,
            null,
            null,
            null,
            now,
            now,
            null
        );
        UserAccount saved = userRepository.save(created);
        recordOutboxEvent("UserAccountCreated", saved.id(), "iam.user.created",
            "{\"userId\":\"" + saved.id() + "\",\"email\":\"" + saved.email() + "\",\"role\":\"" + saved.role().name() + "\"}", now);

        return issueTokensForUser(saved, UUID.randomUUID().toString(), now);
    }

    @Override
    @Transactional(noRollbackFor = IamDomainException.class)
    public AuthTokensResult login(LoginCommand command) {
        String normalizedEmail = normalizeEmail(command.email());
        Instant now = Instant.now();

        UserAccount user = userRepository.findActiveByEmail(normalizedEmail)
            .orElseThrow(() -> new IamDomainException("INVALID_CREDENTIALS", "Invalid email or password", 401));

        if (user.isLocked(now)) {
            throw new IamDomainException("ACCOUNT_LOCKED", "Account is temporarily locked due to failed login attempts", 423);
        }

        if (user.status() != UserStatus.ACTIVE) {
            throw new IamDomainException("ACCOUNT_NOT_ACTIVE", "User account is not active (" + user.status() + ")", 403);
        }

        if (!passwordHasher.matches(command.password(), user.passwordHash())) {
            UserAccount updatedFailure = user.recordLoginFailure(maxFailedAttempts, lockoutMinutes, now);
            userRepository.save(updatedFailure);
            throw new IamDomainException("INVALID_CREDENTIALS", "Invalid email or password", 401);
        }

        UserAccount loggedIn = userRepository.save(user.recordLoginSuccess(now));
        return issueTokensForUser(loggedIn, UUID.randomUUID().toString(), now);
    }

    @Override
    @Transactional(noRollbackFor = IamDomainException.class)
    public AuthTokensResult refreshToken(String rawRefreshToken) {
        if (rawRefreshToken == null || !rawRefreshToken.contains(".")) {
            throw new IamDomainException("INVALID_REFRESH_TOKEN", "Malformed refresh token", 401);
        }
        String[] parts = rawRefreshToken.split("\\.", 2);
        String tokenId = parts[0];
        String tokenSecret = parts[1];
        Instant now = Instant.now();

        RefreshTokenRecord existing = refreshTokenRepository.findById(tokenId)
            .orElseThrow(() -> new IamDomainException("INVALID_REFRESH_TOKEN", "Refresh token not found", 401));

        if (existing.isRevoked()) {
            refreshTokenRepository.revokeAllByTokenFamilyId(existing.tokenFamilyId(), now);
            throw new IamDomainException("REFRESH_TOKEN_REUSED",
                "Revoked refresh token reuse detected; token family has been invalidated", 401);
        }

        if (existing.isExpired(now) || !passwordHasher.matches(tokenSecret, existing.tokenHash())) {
            throw new IamDomainException("INVALID_REFRESH_TOKEN", "Refresh token is expired or invalid", 401);
        }

        UserAccount user = userRepository.findActiveById(existing.userId())
            .orElseThrow(() -> new IamDomainException("USER_NOT_FOUND", "Associated user account is inactive or missing", 401));

        if (user.status() != UserStatus.ACTIVE) {
            throw new IamDomainException("ACCOUNT_NOT_ACTIVE", "User account is no longer active", 403);
        }

        String nextTokenId = UUID.randomUUID().toString();
        refreshTokenRepository.save(existing.revoke(nextTokenId, now));

        return issueTokensWithId(user, nextTokenId, existing.tokenFamilyId(), now);
    }

    @Override
    @Transactional
    public void logout(String userId, String rawRefreshToken, boolean allDevices) {
        Instant now = Instant.now();
        if (allDevices && userId != null && !userId.isBlank()) {
            refreshTokenRepository.revokeAllByUserId(userId, now);
            return;
        }
        if (rawRefreshToken != null && rawRefreshToken.contains(".")) {
            String tokenId = rawRefreshToken.split("\\.", 2)[0];
            refreshTokenRepository.findById(tokenId).ifPresent(token -> {
                if (!token.isRevoked()) {
                    refreshTokenRepository.save(token.revoke(null, now));
                }
            });
        } else if (userId != null && !userId.isBlank()) {
            refreshTokenRepository.revokeAllByUserId(userId, now);
        }
    }

    @Override
    @Transactional
    public ProvisionUserResult provisionUserByAdmin(ProvisionUserCommand command) {
        String normalizedEmail = normalizeEmail(command.email());
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IamDomainException("EMAIL_ALREADY_EXISTS", "Email is already registered", 409);
        }
        if (command.role() == null) {
            throw new IamDomainException("INVALID_ROLE", "Role is required", 400);
        }

        Instant now = Instant.now();
        String rawActivationToken = UUID.randomUUID().toString();
        String initialSecret = (command.password() != null && !command.password().isBlank())
            ? command.password()
            : UUID.randomUUID().toString() + "Aa1!";
        if (command.password() != null && !command.password().isBlank()) {
            validatePasswordComplexity(command.password());
        }

        UserStatus initialStatus = command.activateImmediately()
            ? UserStatus.ACTIVE
            : UserStatus.PENDING_ACTIVATION;

        UserAccount provisioned = new UserAccount(
            UUID.randomUUID().toString(),
            normalizedEmail,
            command.name(),
            passwordHasher.hash(initialSecret),
            command.role(),
            command.personId(),
            initialStatus,
            command.activateImmediately(),
            0,
            null,
            command.activateImmediately() ? null : passwordHasher.hash(rawActivationToken),
            command.activateImmediately() ? null : now.plus(48, ChronoUnit.HOURS),
            now,
            now,
            null
        );

        UserAccount saved = userRepository.save(provisioned);
        recordOutboxEvent("UserAccountProvisioned", saved.id(), "iam.user.provisioned",
            "{\"userId\":\"" + saved.id() + "\",\"email\":\"" + saved.email() + "\",\"role\":\"" + saved.role().name()
                + "\",\"status\":\"" + saved.status().name() + "\"}", now);

        return new ProvisionUserResult(saved, command.activateImmediately() ? null : rawActivationToken);
    }

    @Override
    @Transactional
    public UserAccount activateAccount(ActivateAccountCommand command) {
        String normalizedEmail = normalizeEmail(command.email());
        validatePasswordComplexity(command.newPassword());
        Instant now = Instant.now();

        UserAccount user = userRepository.findActiveByEmail(normalizedEmail)
            .orElseThrow(() -> new IamDomainException("USER_NOT_FOUND", "User account not found", 404));

        if (user.status() == UserStatus.ACTIVE) {
            throw new IamDomainException("ALREADY_ACTIVE", "User account is already active", 409);
        }

        if (user.activationTokenHash() == null || user.activationExpiresAt() == null
            || !user.activationExpiresAt().isAfter(now)
            || !passwordHasher.matches(command.activationToken(), user.activationTokenHash())) {
            throw new IamDomainException("INVALID_ACTIVATION_TOKEN", "Activation token is invalid or expired", 400);
        }

        UserAccount activated = userRepository.save(user.activate(passwordHasher.hash(command.newPassword()), now));
        recordOutboxEvent("UserAccountActivated", activated.id(), "iam.user.activated",
            "{\"userId\":\"" + activated.id() + "\",\"email\":\"" + activated.email() + "\"}", now);
        return activated;
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserAccount> listUsers(UserRole roleFilter, UserStatus statusFilter) {
        return userRepository.findAllActive(roleFilter, statusFilter);
    }

    @Override
    @Transactional(readOnly = true)
    public UserAccount getUserById(String userId) {
        return userRepository.findActiveById(userId)
            .orElseThrow(() -> new IamDomainException("USER_NOT_FOUND", "User not found: " + userId, 404));
    }

    @Override
    @Transactional
    public UserAccount updateUser(UpdateUserCommand command) {
        Instant now = Instant.now();
        UserAccount existing = getUserById(command.userId());
        UserAccount updated = existing.withProfileUpdate(command.name(), command.status(), command.personId(), now);
        return userRepository.save(updated);
    }

    @Override
    @Transactional
    public UserAccount updateUserRole(String userId, UserRole newRole) {
        Instant now = Instant.now();
        UserAccount existing = getUserById(userId);
        UserAccount updated = userRepository.save(existing.withRole(newRole, now));
        recordOutboxEvent("UserRoleUpdated", updated.id(), "iam.user.role.updated",
            "{\"userId\":\"" + updated.id() + "\",\"role\":\"" + updated.role().name() + "\"}", now);
        return updated;
    }

    @Override
    @Transactional
    public void softDeleteUser(String userId) {
        Instant now = Instant.now();
        UserAccount existing = getUserById(userId);
        userRepository.save(existing.softDelete(now));
        refreshTokenRepository.revokeAllByUserId(userId, now);
        recordOutboxEvent("UserAccountDeactivated", userId, "iam.user.deactivated",
            "{\"userId\":\"" + userId + "\"}", now);
    }

    @Override
    public List<UserRole> listRolesCatalog() {
        return Arrays.asList(UserRole.values());
    }

    private AuthTokensResult issueTokensForUser(UserAccount user, String familyId, Instant now) {
        return issueTokensWithId(user, UUID.randomUUID().toString(), familyId, now);
    }

    private AuthTokensResult issueTokensWithId(UserAccount user, String tokenId, String familyId, Instant now) {
        String accessToken = tokenProvider.generateAccessToken(user, now);
        String secretPart = UUID.randomUUID().toString();
        String compositeRefreshToken = tokenId + "." + secretPart;

        RefreshTokenRecord refreshRecord = new RefreshTokenRecord(
            tokenId,
            user.id(),
            familyId,
            passwordHasher.hash(secretPart),
            now.plus(refreshExpirationDays, ChronoUnit.DAYS),
            null,
            null,
            now
        );
        refreshTokenRepository.save(refreshRecord);

        return new AuthTokensResult(
            accessToken,
            compositeRefreshToken,
            "Bearer",
            tokenProvider.getAccessExpirationSeconds(),
            user
        );
    }

    private void recordOutboxEvent(String eventType, String aggregateId, String routingKey, String payloadJson, Instant now) {
        OutboxEvent event = new OutboxEvent(
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString(),
            eventType,
            "UserAccount",
            aggregateId,
            payloadJson,
            routingKey,
            "PENDING",
            0,
            now
        );
        outboxRepository.save(event);
    }

    private static String normalizeEmail(String email) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            throw new IamDomainException("INVALID_EMAIL", "A valid email address is required", 400);
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static void validatePasswordComplexity(String password) {
        if (password == null || password.length() < 8) {
            throw new IamDomainException("WEAK_PASSWORD", "Password must be at least 8 characters long", 400);
        }
    }
}
