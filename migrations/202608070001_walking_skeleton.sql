CREATE TABLE device_allowlist (
    device_id TEXT PRIMARY KEY CHECK (char_length(device_id) BETWEEN 1 AND 128),
    fingerprint_digest BYTEA NOT NULL CHECK (octet_length(fingerprint_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enrollment_tokens (
    token_digest BYTEA PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE TABLE signed_configurations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    bundle_version BIGINT NOT NULL CHECK (bundle_version > 0),
    schema_version SMALLINT NOT NULL CHECK (schema_version = 1),
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    canonical_bundle BYTEA NOT NULL CHECK (octet_length(canonical_bundle) > 0),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (device_id, bundle_version)
);

CREATE TABLE health_reports (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device_allowlist(device_id),
    status TEXT NOT NULL CHECK (char_length(status) BETWEEN 1 AND 256),
    reported_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX health_reports_device_reported_at_idx
    ON health_reports (device_id, reported_at DESC);
