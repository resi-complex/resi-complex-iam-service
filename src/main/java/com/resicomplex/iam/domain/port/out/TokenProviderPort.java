package com.resicomplex.iam.domain.port.out;

import com.resicomplex.iam.domain.model.UserAccount;
import java.time.Instant;
import java.util.List;

public interface TokenProviderPort {

    record VerifiedJwtClaims(
        String userId,
        String email,
        String role,
        List<String> permissions,
        String jti,
        Instant issuedAt,
        Instant expiresAt
    ) {}

    String generateAccessToken(UserAccount user, Instant now);

    VerifiedJwtClaims verifyAccessToken(String token, Instant now);

    long getAccessExpirationSeconds();
}
