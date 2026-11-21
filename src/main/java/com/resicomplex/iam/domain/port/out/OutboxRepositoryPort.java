package com.resicomplex.iam.domain.port.out;

import com.resicomplex.iam.domain.model.OutboxEvent;

public interface OutboxRepositoryPort {
    OutboxEvent save(OutboxEvent event);
}
