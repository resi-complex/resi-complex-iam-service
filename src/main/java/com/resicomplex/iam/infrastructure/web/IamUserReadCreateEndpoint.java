package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import com.resicomplex.iam.domain.port.in.IamUseCasePort;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.ProvisionUserCommand;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.ProvisionUserPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.UserView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IamUserReadCreateEndpoint {

    private final IamUseCasePort useCase;
    private final IamHeaderGuard guard;

    public IamUserReadCreateEndpoint(IamUseCasePort useCase, IamHeaderGuard guard) {
        this.useCase = useCase;
        this.guard = guard;
    }

    @GetMapping({"/users", "/api/v1/auth/users", "/api/v1/users"})
    public List<UserView> queryDirectory(
        HttpServletRequest req,
        @RequestParam(name = "role", required = false) String roleParam,
        @RequestParam(name = "status", required = false) String statusParam
    ) {
        guard.requireAdmin(req);
        UserRole rFilter = (roleParam != null && !roleParam.isBlank()) ? UserRole.fromValue(roleParam) : null;
        UserStatus sFilter = (statusParam != null && !statusParam.isBlank()) ? UserStatus.fromValue(statusParam) : null;
        return useCase.listUsers(rFilter, sFilter).stream()
            .map(acc -> UserView.of(acc, null))
            .toList();
    }

    @PostMapping({"/users", "/api/v1/auth/users", "/api/v1/users"})
    public ResponseEntity<UserView> createStaffOrResident(
        HttpServletRequest req,
        @Valid @RequestBody ProvisionUserPayload payload
    ) {
        guard.requireAdmin(req);
        boolean immediate = Boolean.TRUE.equals(payload.activateImmediately());
        var out = useCase.provisionUserByAdmin(new ProvisionUserCommand(
            payload.email(),
            payload.password(),
            payload.name(),
            payload.resolveTargetRole(),
            payload.personId(),
            immediate
        ));
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(UserView.of(out.user(), out.activationToken()));
    }

    @GetMapping({"/users/{userId}", "/api/v1/auth/users/{userId}", "/api/v1/users/{userId}"})
    public UserView inspectAccount(
        HttpServletRequest req,
        @PathVariable("userId") String userId
    ) {
        guard.requireAdmin(req);
        UserAccount acc = useCase.getUserById(userId);
        return UserView.of(acc, null);
    }
}
