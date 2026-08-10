//! Read-only process and dependency health contracts.

use axum::http::StatusCode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessDependencies {
    pub database: bool,
    pub migration_ledger: bool,
    pub signer: bool,
    pub device_issuer: bool,
    pub tls_material: bool,
    pub ad_primary: bool,
    pub ad_secondary: bool,
}

impl ReadinessDependencies {
    pub const fn none_ready() -> Self {
        Self {
            database: false,
            migration_ledger: false,
            signer: false,
            device_issuer: false,
            tls_material: false,
            ad_primary: false,
            ad_secondary: false,
        }
    }

    pub const fn all_ready() -> Self {
        Self {
            database: true,
            migration_ledger: true,
            signer: true,
            device_issuer: true,
            tls_material: true,
            ad_primary: true,
            ad_secondary: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessReport {
    pub status: StatusCode,
    pub missing: Vec<&'static str>,
}

/// Liveness is process-only: it performs no I/O and does not mutate state.
pub const fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Readiness evaluates an already-collected bounded dependency snapshot. It is
/// deliberately pure so a probe cannot consume enrollment tokens, issue a
/// credential, alter configuration selection, or persist health.
pub fn readiness(dependencies: &ReadinessDependencies) -> ReadinessReport {
    let mut missing = Vec::new();
    if !dependencies.database {
        missing.push("database");
    }
    if !dependencies.migration_ledger {
        missing.push("migration_ledger");
    }
    if !dependencies.signer {
        missing.push("signer");
    }
    if !dependencies.device_issuer {
        missing.push("device_issuer");
    }
    if !dependencies.tls_material {
        missing.push("tls_material");
    }
    if !dependencies.ad_primary {
        missing.push("ad_primary");
    }
    if !dependencies.ad_secondary {
        missing.push("ad_secondary");
    }
    ReadinessReport {
        status: if missing.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        missing,
    }
}
