package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.infrastructure.persistence.entity.UserJpaEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringDataUserRepository extends JpaRepository<UserJpaEntity, String> {
    Optional<UserJpaEntity> findByIdAndDeletedAtIsNull(String id);
    Optional<UserJpaEntity> findByEmailAndDeletedAtIsNull(String email);
    boolean existsByEmail(String email);
    List<UserJpaEntity> findByDeletedAtIsNullOrderByCreatedAtDesc();
}
