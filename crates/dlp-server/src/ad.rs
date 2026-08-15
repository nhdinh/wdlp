//! Direct, fail-closed corroboration of a computer record from two configured DCs.
//!
//! The URL host is deliberately a DNS name, never an IP literal: this preserves
//! hostname validation even where a provisioning station cannot resolve its AD zone.

use async_trait::async_trait;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::{net::IpAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::time::timeout;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedComputerIdentity {
    pub object_guid: Vec<u8>,
    pub object_sid: Vec<u8>,
    pub dns_name: String,
    pub domain: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    InvalidConfiguration,
    Unavailable,
    NotFound,
    Disabled,
    Disagreement,
}

/// Object-safe seam for production and test directory corroboration.
#[async_trait]
pub trait DirectoryVerifier: Send + Sync {
    /// Re-queries the configured directory controllers for `computer_dns_name`
    /// and returns a single verified identity only when both enabled results
    /// agree on GUID, SID, DNS name, and domain.
    async fn corroborate_computer(
        &self,
        computer_dns_name: &str,
    ) -> Result<VerifiedComputerIdentity, DirectoryError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapDirectoryVerifier {
    primary_ldaps_url: String,
    secondary_ldaps_url: String,
    base_dn: String,
}

impl LdapDirectoryVerifier {
    pub fn new(
        primary_ldaps_url: impl Into<String>,
        secondary_ldaps_url: impl Into<String>,
        base_dn: impl Into<String>,
    ) -> Result<Self, DirectoryError> {
        let primary_ldaps_url = primary_ldaps_url.into();
        let secondary_ldaps_url = secondary_ldaps_url.into();
        let base_dn = base_dn.into();
        if !is_hostname_ldaps_url(&primary_ldaps_url)
            || !is_hostname_ldaps_url(&secondary_ldaps_url)
            || primary_ldaps_url == secondary_ldaps_url
            || base_dn.trim().is_empty()
        {
            return Err(DirectoryError::InvalidConfiguration);
        }
        Ok(Self {
            primary_ldaps_url,
            secondary_ldaps_url,
            base_dn,
        })
    }

    pub fn corroborate(
        &self,
        primary: Result<VerifiedComputerIdentity, DirectoryError>,
        secondary: Result<VerifiedComputerIdentity, DirectoryError>,
    ) -> Result<VerifiedComputerIdentity, DirectoryError> {
        let primary = primary?;
        let secondary = secondary?;
        if !primary.enabled || !secondary.enabled {
            return Err(DirectoryError::Disabled);
        }
        if primary != secondary {
            return Err(DirectoryError::Disagreement);
        }
        Ok(primary)
    }

    /// Production callers must independently obtain both configured hostname
    /// LDAPS records. The callback boundary keeps LDAP transport credentials
    /// out of request handling while preserving the fail-closed two-DC rule.
    pub async fn corroborate_computer<F, Fut>(
        &self,
        computer_dns_name: &str,
        mut lookup: F,
    ) -> Result<VerifiedComputerIdentity, DirectoryError>
    where
        F: FnMut(&str, &str, &str) -> Fut,
        Fut: std::future::Future<Output = Result<VerifiedComputerIdentity, DirectoryError>>,
    {
        if computer_dns_name.is_empty() || !computer_dns_name.contains('.') {
            return Err(DirectoryError::NotFound);
        }
        let primary = lookup(&self.primary_ldaps_url, &self.base_dn, computer_dns_name).await;
        let secondary = lookup(&self.secondary_ldaps_url, &self.base_dn, computer_dns_name).await;
        self.corroborate(primary, secondary)
    }

    pub fn configured_urls(&self) -> (&str, &str) {
        (&self.primary_ldaps_url, &self.secondary_ldaps_url)
    }

    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }
}

/// Production LDAPS adapter that queries two configured DCs over TLS with a
/// custom CA, simple bind, and bounded timeouts. The plaintext bind password
/// is held only for the connection attempt and is never logged.
#[derive(Clone, Debug)]
pub struct LdapDirectoryAdapter {
    verifier: LdapDirectoryVerifier,
    bind_dn: String,
    bind_password: String,
    ca_cert_path: PathBuf,
    domain: String,
    timeout: Duration,
}

impl LdapDirectoryAdapter {
    pub fn new(
        primary_ldaps_url: impl Into<String>,
        secondary_ldaps_url: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
        ca_cert_path: impl Into<PathBuf>,
        domain: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, DirectoryError> {
        let verifier = LdapDirectoryVerifier::new(
            primary_ldaps_url,
            secondary_ldaps_url,
            base_dn,
        )?;
        let bind_dn = bind_dn.into();
        let bind_password = bind_password.into();
        let ca_cert_path = ca_cert_path.into();
        let domain = domain.into();
        if bind_dn.trim().is_empty()
            || bind_password.is_empty()
            || domain.trim().is_empty()
            || !ca_cert_path.is_file()
        {
            return Err(DirectoryError::InvalidConfiguration);
        }
        Ok(Self {
            verifier,
            bind_dn,
            bind_password,
            ca_cert_path,
            domain,
            timeout,
        })
    }

    pub fn from_environment() -> Result<Self, DirectoryError> {
        Self::new(
            std::env::var("DLP_AD_PRIMARY_LDAPS_URL").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_SECONDARY_LDAPS_URL").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_BASE_DN").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_BIND_DN").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_BIND_PASSWORD").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_CA_CERT_PEM").map_err(|_| DirectoryError::InvalidConfiguration)?,
            std::env::var("DLP_AD_DOMAIN").map_err(|_| DirectoryError::InvalidConfiguration)?,
            Duration::from_secs(
                std::env::var("DLP_AD_TIMEOUT_SECONDS")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(10),
            ),
        )
    }

    fn ldap_client_config(&self) -> Result<rustls_ldap::ClientConfig, DirectoryError> {
        let ca_pem = std::fs::read(&self.ca_cert_path).map_err(|_| DirectoryError::InvalidConfiguration)?;
        let mut root_store = rustls_ldap::RootCertStore::empty();
        let certificates = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .map_err(|_| DirectoryError::InvalidConfiguration)?;
        for certificate in certificates {
            root_store
                .add(&rustls_ldap::Certificate(certificate))
                .map_err(|_| DirectoryError::InvalidConfiguration)?;
        }
        if root_store.is_empty() {
            return Err(DirectoryError::InvalidConfiguration);
        }
        Ok(rustls_ldap::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }

    async fn query_dc(
        &self,
        url: &str,
        computer_dns_name: &str,
    ) -> Result<VerifiedComputerIdentity, DirectoryError> {
        let config = self.ldap_client_config()?;
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.timeout)
            .set_config(Arc::new(config));
        let (conn, mut ldap) = timeout(
            self.timeout,
            LdapConnAsync::with_settings(settings, url),
        )
        .await
        .map_err(|_| DirectoryError::Unavailable)?
        .map_err(|_| DirectoryError::Unavailable)?;
        ldap3::drive!(conn);
        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .map_err(|_| DirectoryError::Unavailable)?;

        let filter = format!(
            "(&(objectClass=computer)(dNSHostName={}))",
            sanitize_filter_value(computer_dns_name)
        );
        let search_result = timeout(
            self.timeout,
            ldap.search(
                self.verifier.base_dn(),
                Scope::Subtree,
                &filter,
                &["objectGUID", "objectSid", "dNSHostName", "userAccountControl"],
            ),
        )
        .await
        .map_err(|_| DirectoryError::Unavailable)?
        .map_err(|_| DirectoryError::Unavailable)?;

        let raw = search_result
            .0
            .into_iter()
            .next()
            .ok_or(DirectoryError::NotFound)?;
        let entry = SearchEntry::construct(raw);
        let object_guid = entry
            .bin_attrs
            .get("objectGUID")
            .and_then(|values| values.first())
            .cloned()
            .filter(|value| value.len() == 16)
            .ok_or(DirectoryError::Unavailable)?;
        let object_sid = entry
            .bin_attrs
            .get("objectSid")
            .and_then(|values| values.first())
            .cloned()
            .filter(|value| value.len() >= 8 && value.len() <= 68)
            .ok_or(DirectoryError::Unavailable)?;
        let dns_name = entry
            .attrs
            .get("dNSHostName")
            .and_then(|values| values.first())
            .cloned()
            .filter(|value| !value.is_empty())
            .ok_or(DirectoryError::Unavailable)?;
        let user_account_control = entry
            .attrs
            .get("userAccountControl")
            .and_then(|values| values.first())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(DirectoryError::Unavailable)?;
        let enabled = user_account_control & 0x2 == 0;
        if dns_name.to_lowercase() != computer_dns_name.to_lowercase() {
            return Err(DirectoryError::NotFound);
        }
        Ok(VerifiedComputerIdentity {
            object_guid,
            object_sid,
            dns_name,
            domain: self.domain.clone(),
            enabled,
        })
    }
}

#[async_trait]
impl DirectoryVerifier for LdapDirectoryAdapter {
    async fn corroborate_computer(
        &self,
        computer_dns_name: &str,
    ) -> Result<VerifiedComputerIdentity, DirectoryError> {
        if computer_dns_name.is_empty() || !computer_dns_name.contains('.') {
            return Err(DirectoryError::NotFound);
        }
        let (primary_url, secondary_url) = self.verifier.configured_urls();
        let primary = self.query_dc(primary_url, computer_dns_name).await;
        let secondary = self.query_dc(secondary_url, computer_dns_name).await;
        self.verifier.corroborate(primary, secondary)
    }
}

fn is_hostname_ldaps_url(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("ldaps://") else {
        return false;
    };
    let host = authority
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    !host.is_empty() && IpAddr::from_str(host).is_err() && host.contains('.')
}

fn sanitize_filter_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '.' || *character == '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VerifiedComputerIdentity {
        VerifiedComputerIdentity {
            object_guid: vec![1; 16],
            object_sid: vec![2; 16],
            dns_name: "device.lab.local".into(),
            domain: "LAB".into(),
            enabled: true,
        }
    }

    #[test]
    fn requires_two_hostname_verified_ldaps_endpoints_to_agree() {
        let verifier = LdapDirectoryVerifier::new(
            "ldaps://LAB-DC01.lab.local",
            "ldaps://LAB-DC02.lab.local",
            "DC=lab,DC=local",
        )
        .unwrap();
        assert_eq!(
            verifier.corroborate(Ok(identity()), Ok(identity())),
            Ok(identity())
        );
        assert!(matches!(
            verifier.corroborate(Ok(identity()), Err(DirectoryError::Unavailable)),
            Err(DirectoryError::Unavailable)
        ));
        assert!(
            LdapDirectoryVerifier::new(
                "ldaps://192.168.50.10",
                "ldaps://LAB-DC02.lab.local",
                "DC=lab,DC=local"
            )
            .is_err()
        );
    }

    #[test]
    fn adapter_rejects_invalid_configuration() {
        assert!(
            LdapDirectoryAdapter::new(
                "ldaps://LAB-DC01.lab.local",
                "ldaps://LAB-DC02.lab.local",
                "DC=lab,DC=local",
                "",
                "secret",
                std::path::Path::new("/nonexistent/ca.pem"),
                "LAB",
                Duration::from_secs(5),
            )
            .is_err()
        );
    }
}
