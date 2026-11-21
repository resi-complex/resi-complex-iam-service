package com.resicomplex.iam.domain.model;

import java.time.Instant;
import java.util.Objects;

public record OutboxEvent(
    String id,
    String eventId,
    String eventType,
    String aggregateType,
    String aggregateId,
    String payload,
    String routingKey,
    String status,
    int retryCount,
    Instant createdAt
) {
    public OutboxEvent {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(eventId, "eventId must not be null");
        Objects.requireNonNull(eventType, "eventType must not be null");
        Objects.requireNonNull(aggregateType, "aggregateType must not be null");
        Objects.requireNonNull(aggregateId, "aggregateId must not be null");
        Objects.requireNonNull(payload, "payload must not be null");
        Objects.requireNonNull(routingKey, "routingKey must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }
}
