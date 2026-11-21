# resi-complex-iam-service

Identity and Access Management (`IAM`) microservice for **resi-complex** (`FR01`, `FR20`, `HU-IAM-001`, `HU-IAM-002`), implemented with **Hexagonal Architecture (Ports & Adapters)**, **Java 25**, **Spring Boot 4.0.8**, **MySQL 8 (`iam_db`)**, and **Flyway**.

## Configuration
- **Port:** `8081` (`SERVER_PORT`)
- **MySQL 8 Database:** `iam_db` (`ddl-auto=validate`, `open-in-view=false`)
- **Flyway Migration:** `src/main/resources/db/migration/V1__init_iam.sql` (`users`, `refresh_tokens`, `outbox`)
- **Swagger UI:** `http://localhost:8081/swagger-ui/index.html`

## Canonical 5 RBAC Roles (`00-governance/security-policy.md`)
- `ADMINISTRATOR`
- `BOARD`
- `PERSON`
- `MAINTENANCE_STAFF`
- `SECURITY_GUARD`

## Main Endpoints
- `GET /health` (`/api/v1/auth/health`) — Service & DB health check
- `POST /auth/register` (`/register`, `/api/v1/auth/register`) — Account registration (`201 Created`)
- `POST /auth/login` (`/login`, `/api/v1/auth/login`) — Authenticate & issue 1h HS256 JWT + 7d single-use Refresh Token
- `POST /auth/refresh` (`/refresh`, `/api/v1/auth/refresh`) — Mandatory refresh-token rotation with token-family reuse breach revocation
- `POST /auth/logout` (`/logout`, `/api/v1/auth/logout`) — Revoke session / refresh tokens (`204 No Content`)
- `POST /auth/activate` (`/activate`, `/api/v1/auth/activate`) — Complete user account activation (`HU-IAM-002`)
- `GET /users` / `POST /users` / `GET /users/{userId}` / `PATCH /users/{userId}` / `PUT /users/{userId}/roles` / `DELETE /users/{userId}` — Admin user management (`FR20`)
- `GET /roles` — Catalog of the 5 RBAC roles and their default permissions
