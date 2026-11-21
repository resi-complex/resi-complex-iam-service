package com.resicomplex.iam.domain.port.in;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import java.util.List;

/**
 * Driving Port (Input Port) for IAM use cases (FR01 & FR20).
 */
public interface IamUseCasePort {

    record AuthTokensResult(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserAccount user
    ) {}

    record ProvisionUserResult(
        UserAccount user,
        String activationToken
    ) {}

    record RegisterCommand(
        String email,
        String password,
        String name,
        UserRole role,
        String personId
    ) {}

    record LoginCommand(
        String email,
        String password
    ) {}

    record ActivateAccountCommand(
        String email,
        String activationToken,
        String newPassword
    ) {}

    record ProvisionUserCommand(
        String email,
        String password,
        String name,
        UserRole role,
        String personId,
        boolean activateImmediately
    ) {}

    record UpdateUserCommand(
        String userId,
        String name,
        UserStatus status,
        String personId
    ) {}

    AuthTokensResult register(RegisterCommand command);

    AuthTokensResult login(LoginCommand command);

    AuthTokensResult refreshToken(String rawRefreshToken);

    void logout(String userId, String rawRefreshToken, boolean allDevices);

    UserAccount activateAccount(ActivateAccountCommand command);

    ProvisionUserResult provisionUserByAdmin(ProvisionUserCommand command);

    List<UserAccount> listUsers(UserRole roleFilter, UserStatus statusFilter);

    UserAccount getUserById(String userId);

    UserAccount updateUser(UpdateUserCommand command);

    UserAccount updateUserRole(String userId, UserRole newRole);

    void softDeleteUser(String userId);

    List<UserRole> listRolesCatalog();
}
