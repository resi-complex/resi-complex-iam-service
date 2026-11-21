package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.domain.model.RefreshTokenRecord;
import com.resicomplex.iam.domain.port.out.RefreshTokenRepositoryPort;
import com.resicomplex.iam.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class JpaRefreshTokenRepositoryAdapter implements RefreshTokenRepositoryPort {

    private final SpringDataRefreshTokenRepository springDataRepository;

    public JpaRefreshTokenRepositoryAdapter(SpringDataRefreshTokenRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public RefreshTokenRecord save(RefreshTokenRecord token) {
        return springDataRepository.save(RefreshTokenJpaEntity.fromDomain(token)).toDomain();
    }

    @Override
    public Optional<RefreshTokenRecord> findById(String id) {
        return springDataRepository.findById(id).map(RefreshTokenJpaEntity::toDomain);
    }

    @Override
    public void revokeAllByTokenFamilyId(String tokenFamilyId, Instant revokedAt) {
        springDataRepository.revokeByFamilyId(tokenFamilyId, revokedAt);
    }

    @Override
    public void revokeAllByUserId(String userId, Instant revokedAt) {
        springDataRepository.revokeByUserId(userId, revokedAt);
    }
}
