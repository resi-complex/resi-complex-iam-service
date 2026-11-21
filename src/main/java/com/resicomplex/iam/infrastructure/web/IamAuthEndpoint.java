package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.port.in.IamUseCasePort;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.ActivateAccountCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.LoginCommand;
import com.resicomplex.iam.domain.port.in.IamUseCasePort.RegisterCommand;
import com.resicomplex.iam.domain.port.out.TokenProviderPort.VerifiedJwtClaims;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.ActivatePayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.LoginPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.LogoutPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.RefreshPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.RegisterPayload;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.TokenBundleView;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.UserView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IamAuthEndpoint {

    private final IamUseCasePort useCase;
    private final IamHeaderGuard guard;

    public IamAuthEndpoint(IamUseCasePort useCase, IamHeaderGuard guard) {
        this.useCase = useCase;
        this.guard = guard;
    }

    @GetMapping({"/health", "/health/ready", "/api/v1/auth/health"})
    public Map<String, String> health() {
        return Map.of("status", "ok", "service", "iam-service", "db", "connected");
    }

    @PostMapping({"/register", "/auth/register", "/api/v1/auth/register"})
    public ResponseEntity<TokenBundleView> register(@Valid @RequestBody RegisterPayload payload) {
        UserRole role = (payload.role() != null && !payload.role().isBlank())
            ? UserRole.fromValue(payload.role())
            : UserRole.PERSON;
        var res = useCase.register(new RegisterCommand(
            payload.email(), payload.password(), payload.name(), role, payload.personId()
        ));
        return ResponseEntity.status(HttpStatus.CREATED).body(TokenBundleView.of(res));
    }

    @PostMapping({"/login", "/auth/login", "/api/v1/auth/login"})
    public TokenBundleView login(@Valid @RequestBody LoginPayload payload) {
        var res = useCase.login(new LoginCommand(payload.email(), payload.password()));
        return TokenBundleView.of(res);
    }

    @PostMapping({"/refresh", "/auth/refresh", "/api/v1/auth/refresh"})
    public TokenBundleView refresh(@Valid @RequestBody RefreshPayload payload) {
        var res = useCase.refreshToken(payload.refreshToken());
        return TokenBundleView.of(res);
    }

    @PostMapping({"/logout", "/auth/logout", "/api/v1/auth/logout"})
    public ResponseEntity<Void> logout(
        HttpServletRequest req,
        @RequestBody(required = false) LogoutPayload payload
    ) {
        VerifiedJwtClaims claims = guard.requireAuthenticated(req);
        String rt = payload != null ? payload.refreshToken() : null;
        boolean all = payload != null && Boolean.TRUE.equals(payload.allDevices());
        useCase.logout(claims.userId(), rt, all);
        return ResponseEntity.noContent().build();
    }

    @PostMapping({"/activate", "/auth/activate", "/api/v1/auth/activate"})
    public UserView activate(@Valid @RequestBody ActivatePayload payload) {
        UserAccount active = useCase.activateAccount(new ActivateAccountCommand(
            payload.email(), payload.activationToken(), payload.newPassword()
        ));
        return UserView.of(active, null);
    }
}
