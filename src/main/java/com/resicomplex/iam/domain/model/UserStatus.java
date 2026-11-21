package com.resicomplex.iam.domain.model;

import java.util.Locale;

public enum UserStatus {
    PENDING_ACTIVATION,
    ACTIVE,
    INACTIVE;

    public static UserStatus fromValue(String rawStatus) {
        if (rawStatus == null || rawStatus.isBlank()) {
            throw new IllegalArgumentException("Status is required");
        }
        return UserStatus.valueOf(rawStatus.trim().toUpperCase(Locale.ROOT));
    }
}
