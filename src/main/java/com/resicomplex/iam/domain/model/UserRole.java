package com.resicomplex.iam.domain.model;

import java.util.List;
import java.util.Locale;

/**
 * Canonical 5 RBAC roles defined in 00-governance/security-policy.md,
 * 04-requirements/functional.md (FR01, FR20), and 06-data/models.md (chk_users_role).
 * Also resolves legacy aliases (e.g. ADMIN, BOARD_MEMBER,BOARD_OF_TRUSTEES, RESIDENT, MERCHANT).
 */
public enum UserRole {
    ADMINISTRATOR(
        "Administrador",
        "Manages the complex's daily operation and staff provisioning",
        List.of(
            "users:*",
            "units:*",
            "people:*",
            "fees:*",
            "requests:read",
            "requests:assign",
            "announcements:*",
            "expenses:create",
            "reports:read"
        )
    ),
    BOARD(
        "Junta Directiva (Board of Trustees)",
        "Decides on extraordinary expense proposals and reviews reports",
        List.of(
            "expenses:approve",
            "expenses:reject",
            "expenses:read",
            "reports:read"
        )
    ),
    PERSON(
        "Persona (Resident / Commercial Owner or Tenant)",
        "Resident or commercial occupant operating on their own unit resources",
        List.of(
            "requests:create",
            "requests:read:own",
            "fees:read:own",
            "announcements:read",
            "correspondence:read:own",
            "visits:preauthorize:own"
        )
    ),
    MAINTENANCE_STAFF(
        "Personal de Mantenimiento",
        "Handles assigned maintenance requests",
        List.of(
            "requests:read:assigned",
            "requests:update:assigned"
        )
    ),
    SECURITY_GUARD(
        "Guarda de Seguridad",
        "Registers visitors, vehicles, and incoming correspondence at the perimeter",
        List.of(
            "visits:create",
            "visits:read",
            "vehicles:create",
            "correspondence:create",
            "correspondence:deliver"
        )
    );

    private final String displayName;
    private final String description;
    private final List<String> permissions;

    UserRole(String displayName, String description, List<String> permissions) {
        this.displayName = displayName;
        this.description = description;
        this.permissions = List.copyOf(permissions);
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public static UserRole fromValue(String rawRole) {
        if (rawRole == null || rawRole.isBlank()) {
            throw new IllegalArgumentException("Role is required");
        }
        String normalized = rawRole.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ADMINISTRATOR", "ADMIN" -> ADMINISTRATOR;
            case "BOARD", "BOARD_OF_TRUSTEES", "BOARD_MEMBER" -> BOARD;
            case "PERSON", "RESIDENT", "MERCHANT" -> PERSON;
            case "MAINTENANCE_STAFF" -> MAINTENANCE_STAFF;
            case "SECURITY_GUARD" -> SECURITY_GUARD;
            default -> throw new IllegalArgumentException("Invalid role: " + rawRole);
        };
    }
}
