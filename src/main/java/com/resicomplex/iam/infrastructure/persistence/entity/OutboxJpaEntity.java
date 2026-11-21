package com.resicomplex.iam.infrastructure.persistence.entity;

import com.resicomplex.iam.domain.model.OutboxEvent;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "outbox")
public class OutboxJpaEntity {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "event_id", length = 36, nullable = false, unique = true)
    private String eventId;

    @Column(name = "event_type", length = 100, nullable = false)
    private String eventType;

    @Column(name = "aggregate_type", length = 100, nullable = false)
    private String aggregateType;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "aggregate_id", length = 36, nullable = false)
    private String aggregateId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", columnDefinition = "json", nullable = false)
    private String payload;

    @Column(name = "routing_key", length = 150, nullable = false)
    private String routingKey;

    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "retry_count", nullable = false)
    private int retryCount;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "processed_at")
    private Instant processedAt;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    public OutboxJpaEntity() {
    }

    public static OutboxJpaEntity fromDomain(OutboxEvent domain) {
        OutboxJpaEntity entity = new OutboxJpaEntity();
        entity.id = domain.id();
        entity.eventId = domain.eventId();
        entity.eventType = domain.eventType();
        entity.aggregateType = domain.aggregateType();
        entity.aggregateId = domain.aggregateId();
        entity.payload = domain.payload();
        entity.routingKey = domain.routingKey();
        entity.status = domain.status();
        entity.retryCount = domain.retryCount();
        entity.createdAt = domain.createdAt();
        return entity;
    }

    public OutboxEvent toDomain() {
        return new OutboxEvent(
            id,
            eventId,
            eventType,
            aggregateType,
            aggregateId,
            payload,
            routingKey,
            status,
            retryCount,
            createdAt
        );
    }
}
