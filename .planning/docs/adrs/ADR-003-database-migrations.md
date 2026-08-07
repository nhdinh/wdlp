# ADR-003: Database and migration strategy

## Status

Proposed

## Context

The server stores administrators, users, devices, device groups, policies, policy versions, configuration bundles, enforcement events, health reports, and administrative audit events. The database must:
- Support relational consistency for device-state transitions and policy assignments.
- Allow forward-controlled migrations.
- Run well in a Docker Compose deployment.

Candidates considered:
- **PostgreSQL** — robust relational database, excellent Rust ecosystem (`sqlx`, `tokio-postgres`, `sea-orm`), runs in containers.
- **SQLite** — simpler for single-host, but harder to scale horizontally and manage concurrent writers at target scale.
- **MySQL/MariaDB** — viable, but PostgreSQL has stronger type system and migration tooling.

## Decision

Use **PostgreSQL** with **SQLx** for compile-time checked queries and schema migrations managed by `sqlx migrate`.

## Consequences

- **Positive:** Strong consistency guarantees for the control plane.
- **Positive:** `sqlx` provides compile-time query checking when migrations are applied.
- **Positive:** Forward migrations are version-controlled under `migrations/`.
- **Negative:** Requires running PostgreSQL in Docker Compose; slightly heavier than SQLite.
- **Risk:** Migrations must be tested against representative data to avoid downtime.

## Migration Rules

- Migrations are forward-only in normal operation.
- Backward compatibility is maintained for at least one release unless explicitly planned.
- Migrations are applied before server startup in container initialization.
- Seed data for development lives in `config/` and is not applied automatically in production.

## References

- PROJECT.md server deployment target
- Workspace structure: `migrations/` directory
