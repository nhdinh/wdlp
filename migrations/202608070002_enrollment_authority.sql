-- Forward-only enrollment authority. Production PostgreSQL applies the equivalent migration;
-- the ignored SQLite development evidence uses the portable constraints below.
CREATE TABLE IF NOT EXISTS enrollment_authority (
  device_id TEXT PRIMARY KEY NOT NULL,
  fingerprint_version INTEGER NOT NULL CHECK (fingerprint_version = 1),
  fingerprint_digest BLOB NOT NULL UNIQUE,
  ad_object_guid BLOB NOT NULL,
  ad_object_sid BLOB NOT NULL,
  ad_dns_name TEXT NOT NULL,
  ad_domain TEXT NOT NULL,
  preferred_drive_letter TEXT NOT NULL,
  token_digest BLOB NOT NULL UNIQUE,
  token_expires_at TEXT NOT NULL,
  token_consumed_at TEXT,
  active_serial BLOB UNIQUE
);
CREATE TABLE IF NOT EXISTS revoked_device_credentials (
  serial BLOB PRIMARY KEY NOT NULL,
  device_id TEXT NOT NULL REFERENCES enrollment_authority(device_id),
  revoked_at TEXT NOT NULL
);
