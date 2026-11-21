package com.resicomplex.iam.infrastructure.web.dto;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.AuthTokensResult;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

public final class IamPayloads {

    private IamPayloads() {}

    public record RegisterPayload(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8, max = 100) String password,
        String name,
        String role,
        String personId
    ) {}

    public record LoginPayload(
        @NotBlank @Email String email,
        @NotBlank String password
    ) {}

    public record RefreshPayload(
        @NotBlank String refreshToken
    ) {}

    public record LogoutPayload(
        String refreshToken,
        Boolean allDevices
    ) {}

    public record ActivatePayload(
        @NotBlank @Email String email,
        @NotBlank String activationToken,
        @NotBlank @Size(min = 8, max = 100) String newPassword
    ) {}

    public record ProvisionUserPayload(
        @NotBlank @Email String email,
        String password,
        String name,
        String role,
        List<String> roles,
        String personId,
        Boolean activateImmediately
    ) {
        public UserRole resolveTargetRole() {
            if (role != null && !role.isBlank()) {
                return UserRole.fromValue(role);
            }
            if (roles != null && !roles.isEmpty()) {
                return UserRole.fromValue(roles.getFirst());
            }
            return UserRole.PERSON;
        }
    }

    public record PatchUserPayload(
        String name,
        String status,
        String personId
    ) {}

    public record RoleAssignmentPayload(
        String role,
        List<String> roles
    ) {
        public UserRole resolveTargetRole() {
            if (role != null && !role.isBlank()) {
                return UserRole.fromValue(role);
            }
            if (roles != null && !roles.isEmpty()) {
                return UserRole.fromValue(roles.getFirst());
            }
            throw new IllegalArgumentException("A target role is required");
        }
    }

    public record UserView(
        String id,
        String email,
        String name,
        String role,
        List<String> roles,
        List<String> permissions,
        String status,
        String personId,
        String activationToken,
        Instant createdAt,
        Instant updatedAt,
        Instant deletedAt
    ) {
        public static UserView of(UserAccount account, String rawActivationToken) {
            return new UserView(
                account.id(),
                account.email(),
                account.name(),
                account.role().name(),
                List.of(account.role().name()),
                account.role().getPermissions(),
                account.status().name(),
                account.personId(),
                rawActivationToken,
                account.createdAt(),
                account.updatedAt(),
                account.deletedAt()
            );
        }
    }

    public record TokenBundleView(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserView user
    ) {
        public static TokenBundleView of(AuthTokensResult res) {
            return new TokenBundleView(
                res.accessToken(),
                res.refreshToken(),
                res.tokenType(),
                res.expiresIn(),
                UserView.of(res.user(), null)
            );
        }
    }

    public record RoleCatalogItem(
        String role,
        String name,
        String description,
        List<String> defaultPermissions
    ) {
        public static RoleCatalogItem of(UserRole r) {
            return new RoleCatalogItem(
                r.name(),
                r.getDisplayName(),
                r.getDescription(),
                r.getPermissions()
            );
        }
    }

    public record ApiProblemView(
        String type,
        String title,
        int status,
        String error,
        String message,
        Instant timestamp
    ) {}
}
