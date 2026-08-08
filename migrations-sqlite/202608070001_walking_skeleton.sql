-- Test-only SQLite substitute for the PostgreSQL migration in ../migrations.
-- It exists solely for the user-authorized local migration-ledger verification.

CREATE TABLE device_allowlist (
    device_id TEXT PRIMARY KEY CHECK (length(device_id) BETWEEN 1 AND 128),
    fingerprint_digest BLOB NOT NULL CHECK (length(fingerprint_digest) = 32),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enrollment_tokens (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE TABLE signed_configurations (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    bundle_version INTEGER NOT NULL CHECK (bundle_version > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    canonical_bundle BLOB NOT NULL CHECK (length(canonical_bundle) > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (device_id, bundle_version)
);

CREATE TABLE health_reports (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    status TEXT NOT NULL CHECK (length(status) BETWEEN 1 AND 256),
    reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX health_reports_device_reported_at_idx
    ON health_reports (device_id, reported_at DESC);
