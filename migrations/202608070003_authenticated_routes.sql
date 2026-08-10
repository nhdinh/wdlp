-- PostgreSQL persistence for authenticated post-enrollment routes. The active
-- credential index guarantees that a device cannot have two accepted serials.
CREATE TABLE device_route_credentials (
    device_id TEXT NOT NULL REFERENCES enrollment_authority(device_id),
    credential_serial BYTEA PRIMARY KEY CHECK (octet_length(credential_serial) BETWEEN 1 AND 20),
    credential_status TEXT NOT NULL CHECK (credential_status IN ('active', 'revoked')),
    public_certificate_digest BYTEA NOT NULL CHECK (octet_length(public_certificate_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    CHECK ((credential_status = 'active' AND revoked_at IS NULL) OR (credential_status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX device_route_credentials_one_active_per_device
    ON device_route_credentials (device_id) WHERE credential_status = 'active';

ALTER TABLE signed_configurations
    ADD COLUMN content_digest BYTEA CHECK (octet_length(content_digest) = 32),
    ADD COLUMN audience TEXT CHECK (char_length(audience) BETWEEN 1 AND 128);
