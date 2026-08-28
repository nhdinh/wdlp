INSERT INTO device_allowlist (device_id, fingerprint_digest)
SELECT device_id, fingerprint_digest
FROM enrollment_authority
ON CONFLICT (device_id) DO UPDATE
SET fingerprint_digest = EXCLUDED.fingerprint_digest;
