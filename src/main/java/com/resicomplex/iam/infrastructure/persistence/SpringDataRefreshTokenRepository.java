package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SpringDataRefreshTokenRepository extends JpaRepository<RefreshTokenJpaEntity, String> {

    @Modifying
    @Query("UPDATE RefreshTokenJpaEntity r SET r.revokedAt = :revokedAt WHERE r.tokenFamilyId = :familyId AND r.revokedAt IS NULL")
    void revokeByFamilyId(@Param("familyId") String familyId, @Param("revokedAt") Instant revokedAt);

    @Modifying
    @Query("UPDATE RefreshTokenJpaEntity r SET r.revokedAt = :revokedAt WHERE r.userId = :userId AND r.revokedAt IS NULL")
    void revokeByUserId(@Param("userId") String userId, @Param("revokedAt") Instant revokedAt);
}
