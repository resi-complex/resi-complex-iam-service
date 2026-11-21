package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserStatus;
import com.resicomplex.iam.domain.port.in.IamUseCasePort;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.UpdateUserCommand;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.PatchUserPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.RoleAssignmentPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.UserView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IamUserMutationEndpoint {

    private final IamUseCasePort useCase;
    private final IamHeaderGuard guard;

    public IamUserMutationEndpoint(IamUseCasePort useCase, IamHeaderGuard guard) {
        this.useCase = useCase;
        this.guard = guard;
    }

    @PatchMapping({"/users/{userId}", "/api/v1/auth/users/{userId}", "/api/v1/users/{userId}"})
    public UserView modifyProfile(
        HttpServletRequest req,
        @PathVariable("userId") String userId,
        @Valid @RequestBody PatchUserPayload payload
    ) {
        guard.requireAdmin(req);
        UserStatus nextStatus = (payload.status() != null && !payload.status().isBlank())
            ? UserStatus.fromValue(payload.status())
            : null;
        UserAccount updated = useCase.updateUser(new UpdateUserCommand(
            userId, payload.name(), nextStatus, payload.personId()
        ));
        return UserView.of(updated, null);
    }

    @PutMapping({"/users/{userId}/roles", "/api/v1/auth/users/{userId}/roles", "/api/v1/users/{userId}/roles"})
    public UserView assignRole(
        HttpServletRequest req,
        @PathVariable("userId") String userId,
        @Valid @RequestBody RoleAssignmentPayload payload
    ) {
        guard.requireAdmin(req);
        UserAccount updated = useCase.updateUserRole(userId, payload.resolveTargetRole());
        return UserView.of(updated, null);
    }

    @DeleteMapping({"/users/{userId}", "/api/v1/auth/users/{userId}", "/api/v1/users/{userId}"})
    public ResponseEntity<Void> deactivateAccount(
        HttpServletRequest req,
        @PathVariable("userId") String userId
    ) {
        guard.requireAdmin(req);
        useCase.softDeleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}
