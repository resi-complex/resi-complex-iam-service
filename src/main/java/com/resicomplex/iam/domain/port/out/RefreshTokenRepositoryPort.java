package com.resicomplex.iam.domain.port.out;

import com.resicomplex.iam.domain.model.RefreshTokenRecord;
import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepositoryPort {
    RefreshTokenRecord save(RefreshTokenRecord token);
    Optional<RefreshTokenRecord> findById(String id);
    void revokeAllByTokenFamilyId(String tokenFamilyId, Instant revokedAt);
    void revokeAllByUserId(String userId, Instant revokedAt);
}
