package com.resicomplex.iam.infrastructure.persistence;

import com.resicomplex.iam.infrastructure.persistence.entity.OutboxJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringDataOutboxRepository extends JpaRepository<OutboxJpaEntity, String> {
}
