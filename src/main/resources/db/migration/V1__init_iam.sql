-- V1__init_iam.sql
-- Schema for iam-service (iam_db) aligned with 06-data/models.md (MySQL 8 InnoDB, utf8mb4)

CREATE TABLE users (
  id                     CHAR(36)     NOT NULL,
  email                  VARCHAR(255) NOT NULL,
  name                   VARCHAR(120) NULL,
  password_hash          VARCHAR(255) NOT NULL,
  role                   VARCHAR(20)  NOT NULL,
  person_id              CHAR(36)     NULL,
  status                 VARCHAR(20)  NOT NULL DEFAULT 'PENDING_ACTIVATION',
  email_verified         BOOLEAN      NOT NULL DEFAULT FALSE,
  failed_attempts        INT          NOT NULL DEFAULT 0,
  locked_until           TIMESTAMP    NULL,
  activation_token_hash  VARCHAR(255) NULL,
  activation_expires_at  TIMESTAMP    NULL,
  created_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  deleted_at             TIMESTAMP    NULL,

  PRIMARY KEY (id),
  CONSTRAINT uq_users_email UNIQUE (email),
  CONSTRAINT chk_users_role CHECK (role IN ('ADMINISTRATOR','BOARD','PERSON','MAINTENANCE_STAFF','SECURITY_GUARD')),
  CONSTRAINT chk_users_status CHECK (status IN ('ACTIVE','INACTIVE','PENDING_ACTIVATION')),
  CONSTRAINT chk_users_failed_attempts CHECK (failed_attempts >= 0),

  INDEX idx_users_role (role),
  INDEX idx_users_person_id (person_id),
  INDEX idx_users_deleted (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE refresh_tokens (
  id              CHAR(36)     NOT NULL,
  user_id         CHAR(36)     NOT NULL,
  token_family_id CHAR(36)     NOT NULL,
  token_hash      VARCHAR(255) NOT NULL,
  expires_at      TIMESTAMP    NOT NULL,
  revoked_at      TIMESTAMP    NULL,
  replaced_by     CHAR(36)     NULL,
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,

  INDEX idx_refresh_tokens_user_revoked (user_id, revoked_at),
  INDEX idx_refresh_tokens_family (token_family_id),
  INDEX idx_refresh_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE outbox (
  id             CHAR(36)     NOT NULL,
  event_id       CHAR(36)     NOT NULL,
  event_type     VARCHAR(100) NOT NULL,
  aggregate_type VARCHAR(100) NOT NULL,
  aggregate_id   CHAR(36)     NOT NULL,
  payload        JSON         NOT NULL,
  routing_key    VARCHAR(150) NOT NULL,
  status         VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
  retry_count    INT          NOT NULL DEFAULT 0,
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  processed_at   DATETIME(3)  NULL,
  error_message  TEXT         NULL,

  PRIMARY KEY (id),
  CONSTRAINT uq_outbox_event_id UNIQUE (event_id),
  CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING','PUBLISHED','FAILED')),
  CONSTRAINT chk_outbox_retry CHECK (retry_count >= 0),

  INDEX idx_outbox_status_created (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
