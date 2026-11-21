package com.resicomplex.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.resicomplex.iam.domain.exception.IamDomainException;
import com.resicomplex.iam.domain.model.OutboxEvent;
import com.resicomplex.iam.domain.model.RefreshTokenRecord;
import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.ActivateAccountCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.LoginCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.ProvisionUserCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.RegisterCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.UpdateUserCommand;
import com.resicomplex.iam.domain.port.out.OutboxRepositoryPort;
import com.resicomplex.iam.domain.port.out.RefreshTokenRepositoryPort;
import com.resicomplex.iam.domain.port.out.UserRepositoryPort;
import com.resicomplex.iam.infrastructure.security.BcryptPasswordHasherAdapter;
import com.resicomplex.iam.infrastructure.security.Hs256JwtTokenProviderAdapter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IamApplicationServiceTest {

    private Map<String, UserAccount> userStore;
    private Map<String, RefreshTokenRecord> tokenStore;
    private List<OutboxEvent> outboxStore;
    private Hs256JwtTokenProviderAdapter jwtProvider;
    private BcryptPasswordHasherAdapter passwordHasher;
    private IamApplicationService service;

    @BeforeEach
    void setUp() {
        userStore = new ConcurrentHashMap<>();
        tokenStore = new ConcurrentHashMap<>();
        outboxStore = new ArrayList<>();
        jwtProvider = new Hs256JwtTokenProviderAdapter(
            "resicomplex-unit-test-secret-key-with-at-least-256-bits-2026",
            3600
        );
        passwordHasher = new BcryptPasswordHasherAdapter();

        UserRepositoryPort userRepo = new UserRepositoryPort() {
            @Override
            public UserAccount save(UserAccount user) {
                userStore.put(user.id(), user);
                return user;
            }

            @Override
            public Optional<UserAccount> findActiveById(String id) {
                return Optional.ofNullable(userStore.get(id)).filter(u -> !u.isDeleted());
            }

            @Override
            public Optional<UserAccount> findActiveByEmail(String email) {
                return userStore.values().stream()
                    .filter(u -> !u.isDeleted() && u.email().equalsIgnoreCase(email))
                    .findFirst();
            }

            @Override
            public boolean existsByEmail(String email) {
                return userStore.values().stream().anyMatch(u -> u.email().equalsIgnoreCase(email));
            }

            @Override
            public List<UserAccount> findAllActive(UserRole roleFilter, UserStatus statusFilter) {
                return userStore.values().stream()
                    .filter(u -> !u.isDeleted())
                    .filter(u -> roleFilter == null || u.role() == roleFilter)
                    .filter(u -> statusFilter == null || u.status() == statusFilter)
                    .toList();
            }
        };

        RefreshTokenRepositoryPort tokenRepo = new RefreshTokenRepositoryPort() {
            @Override
            public RefreshTokenRecord save(RefreshTokenRecord token) {
                tokenStore.put(token.id(), token);
                return token;
            }

            @Override
            public Optional<RefreshTokenRecord> findById(String id) {
                return Optional.ofNullable(tokenStore.get(id));
            }

            @Override
            public void revokeAllByTokenFamilyId(String tokenFamilyId, Instant revokedAt) {
                tokenStore.replaceAll((k, v) -> v.tokenFamilyId().equals(tokenFamilyId) && !v.isRevoked()
                    ? v.revoke(null, revokedAt)
                    : v);
            }

            @Override
            public void revokeAllByUserId(String userId, Instant revokedAt) {
                tokenStore.replaceAll((k, v) -> v.userId().equals(userId) && !v.isRevoked()
                    ? v.revoke(null, revokedAt)
                    : v);
            }
        };

        OutboxRepositoryPort outboxRepo = event -> {
            outboxStore.add(event);
            return event;
        };

        service = new IamApplicationService(userRepo, tokenRepo, outboxRepo, jwtProvider, passwordHasher, 7, 3, 15);
    }

    @Test
    void registerLoginRefreshAndDetectTokenReuseBreach() {
        var regResult = service.register(new RegisterCommand(
            "Admin@ResiComplex.com", "StrongPass123!", "Fabian Trujillo", UserRole.ADMINISTRATOR, null
        ));
        assertNotNull(regResult.accessToken());
        assertNotNull(regResult.refreshToken());
        assertEquals(UserRole.ADMINISTRATOR, regResult.user().role());
        assertEquals(1, outboxStore.size());

        var claims = jwtProvider.verifyAccessToken(regResult.accessToken(), Instant.now());
        assertEquals("admin@resicomplex.com", claims.email());
        assertEquals("ADMINISTRATOR", claims.role());

        var loginResult = service.login(new LoginCommand("admin@resicomplex.com", "StrongPass123!"));
        String firstRefresh = loginResult.refreshToken();

        var rotated = service.refreshToken(firstRefresh);
        assertNotNull(rotated.refreshToken());

        // Reusing a rotated refresh token must trigger breach detection & revoke the whole token family
        IamDomainException reuseEx = assertThrows(
            IamDomainException.class,
            () -> service.refreshToken(firstRefresh)
        );
        assertEquals("REFRESH_TOKEN_REUSED", reuseEx.getErrorCode());

        // Subsequent use of the newly rotated token in the same family must also fail
        assertThrows(IamDomainException.class, () -> service.refreshToken(rotated.refreshToken()));
    }

    @Test
    void lockAccountAfterMaxConsecutiveFailedLogins() {
        service.register(new RegisterCommand(
            "resident@resicomplex.com", "ResidentPass123!", "Resident One", UserRole.PERSON, "p-1"
        ));

        for (int i = 0; i < 3; i++) {
            assertThrows(IamDomainException.class,
                () -> service.login(new LoginCommand("resident@resicomplex.com", "WrongPass999!")));
        }

        IamDomainException lockedEx = assertThrows(
            IamDomainException.class,
            () -> service.login(new LoginCommand("resident@resicomplex.com", "ResidentPass123!"))
        );
        assertEquals(423, lockedEx.getHttpStatus());
        assertEquals("ACCOUNT_LOCKED", lockedEx.getErrorCode());
    }

    @Test
    void provisionStaffAccountAndCompleteActivationFlow() {
        var provision = service.provisionUserByAdmin(new ProvisionUserCommand(
            "guard@resicomplex.com", null, "Pedro Guarda", UserRole.SECURITY_GUARD, null, false
        ));
        assertEquals(UserStatus.PENDING_ACTIVATION, provision.user().status());
        assertNotNull(provision.activationToken());

        // Cannot log in before activation
        IamDomainException pendingEx = assertThrows(
            IamDomainException.class,
            () -> service.login(new LoginCommand("guard@resicomplex.com", "AnyPass123!"))
        );
        assertEquals(403, pendingEx.getHttpStatus());

        UserAccount activated = service.activateAccount(new ActivateAccountCommand(
            "guard@resicomplex.com", provision.activationToken(), "GuardNewPass123!"
        ));
        assertEquals(UserStatus.ACTIVE, activated.status());
        assertTrue(activated.emailVerified());

        var loginOk = service.login(new LoginCommand("guard@resicomplex.com", "GuardNewPass123!"));
        assertEquals("SECURITY_GUARD", loginOk.user().role().name());

        // Update profile, role, list and soft-delete
        UserAccount updated = service.updateUser(new UpdateUserCommand(
            activated.id(), "Pedro Guarda Jefe", UserStatus.ACTIVE, null
        ));
        assertEquals("Pedro Guarda Jefe", updated.name());

        UserAccount roleChanged = service.updateUserRole(activated.id(), UserRole.MAINTENANCE_STAFF);
        assertEquals(UserRole.MAINTENANCE_STAFF, roleChanged.role());
        assertEquals(5, service.listRolesCatalog().size());

        service.softDeleteUser(activated.id());
        assertThrows(IamDomainException.class, () -> service.getUserById(activated.id()));
    }
}
