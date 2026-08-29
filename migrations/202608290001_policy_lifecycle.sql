-- Phase 2 policy authority. Certificate principals are opaque SHA-256 pairs;
-- certificate subjects, serial text, and caller-provided role claims are never
-- authorization keys.
CREATE TABLE administrator_principals (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer_sha256 BYTEA NOT NULL CHECK (octet_length(issuer_sha256) = 32),
    leaf_sha256 BYTEA NOT NULL CHECK (octet_length(leaf_sha256) = 32),
    principal_role TEXT NOT NULL CHECK (principal_role IN ('administrator', 'auditor')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    UNIQUE (issuer_sha256, leaf_sha256),
    CHECK ((active AND revoked_at IS NULL) OR (NOT active AND revoked_at IS NOT NULL))
);

CREATE TABLE initial_admin_bootstrap (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    principal_id BIGINT NOT NULL UNIQUE REFERENCES administrator_principals(id),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Metadata-only security evidence. Details deliberately exclude certificate
-- subjects, DER, request role claims, policy content, and secrets.
CREATE TABLE policy_audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_code TEXT NOT NULL CHECK (char_length(event_code) BETWEEN 1 AND 96),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE policy_drafts (
    policy_id TEXT PRIMARY KEY CHECK (char_length(policy_id) BETWEEN 1 AND 128),
    source_json BYTEA NOT NULL CHECK (octet_length(source_json) BETWEEN 2 AND 1048576),
    validated_digest BYTEA CHECK (octet_length(validated_digest) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE published_policy_versions (
    policy_id TEXT NOT NULL CHECK (char_length(policy_id) BETWEEN 1 AND 128),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    schema_version SMALLINT NOT NULL CHECK (schema_version = 2),
    source_json BYTEA NOT NULL CHECK (octet_length(source_json) BETWEEN 2 AND 1048576),
    content_digest BYTEA NOT NULL CHECK (octet_length(content_digest) = 32),
    published_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (policy_id, policy_version)
);

-- Publication is deliberately separate from deployment. These tables hold
-- only explicit pointers to immutable published versions; changing a draft or
-- publishing another version cannot alter an endpoint's desired policy.
CREATE TABLE organization_policy_assignment (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    policy_id TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id, policy_version)
        REFERENCES published_policy_versions(policy_id, policy_version)
);

CREATE TABLE device_policy_assignments (
    device_id TEXT PRIMARY KEY REFERENCES device_allowlist(device_id),
    policy_id TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id, policy_version)
        REFERENCES published_policy_versions(policy_id, policy_version)
);

-- Bundle versions are monotonic per authenticated device. Issued, activated,
-- and error cursors refer to bundle versions rather than mutable policy rows.
CREATE TABLE device_policy_distribution (
    device_id TEXT PRIMARY KEY REFERENCES device_allowlist(device_id),
    desired_policy_id TEXT NOT NULL,
    desired_policy_version BIGINT NOT NULL,
    desired_bundle_version BIGINT NOT NULL CHECK (desired_bundle_version > 0),
    issued_bundle_version BIGINT CHECK (
        issued_bundle_version IS NULL OR
        (issued_bundle_version > 0 AND issued_bundle_version <= desired_bundle_version)
    ),
    activated_bundle_version BIGINT CHECK (
        activated_bundle_version IS NULL OR
        (activated_bundle_version > 0 AND
         activated_bundle_version <= desired_bundle_version AND
         issued_bundle_version IS NOT NULL AND
         activated_bundle_version <= issued_bundle_version)
    ),
    error_bundle_version BIGINT CHECK (
        error_bundle_version IS NULL OR
        (error_bundle_version > 0 AND error_bundle_version <= desired_bundle_version)
    ),
    last_error_code TEXT CHECK (
        last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 64
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (desired_policy_id, desired_policy_version)
        REFERENCES published_policy_versions(policy_id, policy_version),
    CHECK ((error_bundle_version IS NULL) = (last_error_code IS NULL))
);

CREATE FUNCTION reject_published_policy_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'published_policy_immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER published_policy_versions_no_update
BEFORE UPDATE ON published_policy_versions
FOR EACH ROW EXECUTE FUNCTION reject_published_policy_mutation();

CREATE TRIGGER published_policy_versions_no_delete
BEFORE DELETE ON published_policy_versions
FOR EACH ROW EXECUTE FUNCTION reject_published_policy_mutation();
