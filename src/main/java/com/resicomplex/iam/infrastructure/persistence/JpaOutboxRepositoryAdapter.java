package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.domain.model.OutboxEvent;
import com.resicomplex.iam.domain.port.out.OutboxRepositoryPort;
import com.resicomplex.iam.infrastructure.persistence.entity.OutboxJpaEntity;
import org.springframework.stereotype.Repository;

@Repository
public class JpaOutboxRepositoryAdapter implements OutboxRepositoryPort {

    private final SpringDataOutboxRepository springDataRepository;

    public JpaOutboxRepositoryAdapter(SpringDataOutboxRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public OutboxEvent save(OutboxEvent event) {
        return springDataRepository.save(OutboxJpaEntity.fromDomain(event)).toDomain();
    }
}
