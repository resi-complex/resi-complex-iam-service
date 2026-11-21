package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.exception.IamDomainException;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.port.out.TokenProviderPort;
import com.resicomplex.iam.domain.port.out.TokenProviderPort.VerifiedJwtClaims;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.springframework.stereotype.Component;

@Component
public class IamHeaderGuard {

    private final TokenProviderPort tokenProvider;

    public IamHeaderGuard(TokenProviderPort tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    public VerifiedJwtClaims requireAuthenticated(HttpServletRequest req) {
        String rawHeader = req.getHeader("Authorization");
        if (rawHeader != null && rawHeader.startsWith("Bearer ")) {
            return tokenProvider.verifyAccessToken(rawHeader.substring(7).trim(), Instant.now());
        }
        String forwardedId = req.getHeader("X-User-Id");
        String forwardedRole = req.getHeader("X-User-Roles");
        if (forwardedId != null && !forwardedId.isBlank() && forwardedRole != null && !forwardedRole.isBlank()) {
            UserRole r = UserRole.fromValue(forwardedRole.split(",")[0]);
            Instant now = Instant.now();
            return new VerifiedJwtClaims(forwardedId, "gateway@resicomplex.local", r.name(), r.getPermissions(), "gw", now, now.plusSeconds(3600));
        }
        throw new IamDomainException("UNAUTHORIZED", "Authentication required", 401);
    }

    public VerifiedJwtClaims requireAdmin(HttpServletRequest req) {
        VerifiedJwtClaims claims = requireAuthenticated(req);
        if (!UserRole.ADMINISTRATOR.name().equals(claims.role())) {
            throw new IamDomainException("FORBIDDEN", "Administrator role is required for this operation", 403);
        }
        return claims;
    }
}
