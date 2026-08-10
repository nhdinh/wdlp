-- Forward-only PostgreSQL authority ledger. No seed rows, raw hardware serials,
-- plaintext enrollment tokens, endpoint private keys, or CA material are stored.
CREATE TABLE enrollment_authority (
    device_id TEXT PRIMARY KEY CHECK (char_length(device_id) BETWEEN 1 AND 128),
    fingerprint_version SMALLINT NOT NULL CHECK (fingerprint_version = 1),
    fingerprint_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(fingerprint_digest) = 32),
    ad_object_guid BYTEA NOT NULL CHECK (octet_length(ad_object_guid) = 16),
    ad_object_sid BYTEA NOT NULL CHECK (octet_length(ad_object_sid) BETWEEN 8 AND 68),
    ad_dns_name TEXT NOT NULL CHECK (char_length(ad_dns_name) BETWEEN 1 AND 255),
    ad_domain TEXT NOT NULL CHECK (char_length(ad_domain) BETWEEN 1 AND 255),
    preferred_drive_letter CHAR(1) NOT NULL CHECK (preferred_drive_letter ~ '^[A-Z]$'),
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    token_expires_at TIMESTAMPTZ NOT NULL,
    token_consumed_at TIMESTAMPTZ,
    active_serial BYTEA UNIQUE CHECK (active_serial IS NULL OR octet_length(active_serial) BETWEEN 1 AND 20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (token_expires_at > created_at),
    CHECK (token_consumed_at IS NULL OR token_consumed_at >= created_at)
);

CREATE TABLE revoked_device_credentials (
    serial BYTEA PRIMARY KEY CHECK (octet_length(serial) BETWEEN 1 AND 20),
    device_id TEXT NOT NULL REFERENCES enrollment_authority(device_id),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX enrollment_authority_active_serial_idx
    ON enrollment_authority (active_serial) WHERE active_serial IS NOT NULL;
