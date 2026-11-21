package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import com.resicomplex.iam.domain.port.out.UserRepositoryPort;
import com.resicomplex.iam.infrastructure.persistence.entity.UserJpaEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class JpaUserRepositoryAdapter implements UserRepositoryPort {

    private final SpringDataUserRepository springDataRepository;

    public JpaUserRepositoryAdapter(SpringDataUserRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public UserAccount save(UserAccount user) {
        return springDataRepository.save(UserJpaEntity.fromDomain(user)).toDomain();
    }

    @Override
    public Optional<UserAccount> findActiveById(String id) {
        return springDataRepository.findByIdAndDeletedAtIsNull(id).map(UserJpaEntity::toDomain);
    }

    @Override
    public Optional<UserAccount> findActiveByEmail(String email) {
        return springDataRepository.findByEmailAndDeletedAtIsNull(email).map(UserJpaEntity::toDomain);
    }

    @Override
    public boolean existsByEmail(String email) {
        return springDataRepository.existsByEmail(email);
    }

    @Override
    public List<UserAccount> findAllActive(UserRole roleFilter, UserStatus statusFilter) {
        return springDataRepository.findByDeletedAtIsNullOrderByCreatedAtDesc().stream()
            .map(UserJpaEntity::toDomain)
            .filter(u -> roleFilter == null || u.role() == roleFilter)
            .filter(u -> statusFilter == null || u.status() == statusFilter)
            .toList();
    }
}
