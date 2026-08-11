# LAB-SERVER01 Setup

**Role:** Native PostgreSQL database server for Phase 1  
**Hostname:** LAB-SERVER01  
**IP Address:** 192.168.50.12  
**OS:** Ubuntu Server (LTS)  
**Database:** PostgreSQL 18.x (native package installation)

## Overview

LAB-SERVER01 hosts the DLP management server's PostgreSQL database natively. This replaces the earlier Docker Compose deployment model for the database tier. The management server (LAB-DC01) and developer orchestration host (hungdinh-lt) connect to this database over the lab network.

## Network Placement

- LAB-SERVER01 is reachable from hungdinh-lt, LAB-DC01, and LAB-CLIENT01 on `192.168.50.12/24`.
- PostgreSQL listens on the standard TCP port `5432`.
- Firewall rules must allow PostgreSQL connections from LAB-DC01 and hungdinh-lt only.

## Required Runtime Secrets

The runtime-only secret provider supplies the following values. They are never committed, logged, or passed on command lines.

| Secret | Purpose |
|--------|---------|
| `DLP_DATABASE_URL` | Full PostgreSQL connection string for the `dlp` database. Example: `postgres://dlp_server:<password>@192.168.50.12:5432/dlp` |
| `DLP_SERVER_HOST` | Management server hostname/IP used by probes. Currently `192.168.50.12` while LAB-SERVER01 co-hosts initial services; update when the management server moves to LAB-DC01. |

## PostgreSQL Configuration

1. Install PostgreSQL 18.x from the official PostgreSQL APT repository.
2. Create the `dlp` database:
   ```sql
   CREATE DATABASE dlp;
   ```
3. Create the application role:
   ```sql
   CREATE USER dlp_server WITH ENCRYPTED PASSWORD '<from-runtime-provider>';
   GRANT ALL PRIVILEGES ON DATABASE dlp TO dlp_server;
   ```
4. Allow password authentication from the lab subnet in `pg_hba.conf`:
   ```
   host  dlp  dlp_server  192.168.50.0/24  scram-sha-256
   ```
5. Ensure `postgresql.conf` binds to the lab interface:
   ```
   listen_addresses = '192.168.50.12,localhost'
   ```

## Migration Execution

Migrations are run from the orchestration host (hungdinh-lt) or the management server (LAB-DC01) using `sqlx-cli` against `DLP_DATABASE_URL`:

```bash
export DATABASE_URL="$DLP_DATABASE_URL"
sqlx migrate run --source migrations/
```

Repeat runs must be idempotent; SQLx tracks applied migrations in `_sqlx_migrations`.

## Verification

From an authorized host:

```bash
psql "$DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"
```

Expected result after all three Phase 1 migrations: `3`.

## Notes

- Docker and Docker Compose are no longer used for the Phase 1 database tier.
- The `deploy/compose.yaml` file remains as a reference for container-based deployments but is not exercised in this lab.
- All database evidence for Plan 01-13 is collected against this native PostgreSQL instance, not a local SQLite or containerized substitute.
