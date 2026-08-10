//! Direct, fail-closed corroboration of a computer record from two configured DCs.
//!
//! The URL host is deliberately a DNS name, never an IP literal: this preserves
//! hostname validation even where a provisioning station cannot resolve its AD zone.

use std::{net::IpAddr, str::FromStr};

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
        Ok(Self { primary_ldaps_url, secondary_ldaps_url, base_dn })
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

    pub fn configured_urls(&self) -> (&str, &str) {
        (&self.primary_ldaps_url, &self.secondary_ldaps_url)
    }

    pub fn base_dn(&self) -> &str { &self.base_dn }
}

fn is_hostname_ldaps_url(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("ldaps://") else { return false };
    let host = authority.split('/').next().unwrap_or_default().split(':').next().unwrap_or_default();
    !host.is_empty() && IpAddr::from_str(host).is_err() && host.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VerifiedComputerIdentity {
        VerifiedComputerIdentity { object_guid: vec![1; 16], object_sid: vec![2; 16], dns_name: "device.lab.local".into(), domain: "LAB".into(), enabled: true }
    }

    #[test]
    fn requires_two_hostname_verified_ldaps_endpoints_to_agree() {
        let verifier = LdapDirectoryVerifier::new("ldaps://LAB-DC01.lab.local", "ldaps://LAB-DC02.lab.local", "DC=lab,DC=local").unwrap();
        assert_eq!(verifier.corroborate(Ok(identity()), Ok(identity())), Ok(identity()));
        assert!(matches!(verifier.corroborate(Ok(identity()), Err(DirectoryError::Unavailable)), Err(DirectoryError::Unavailable)));
        assert!(LdapDirectoryVerifier::new("ldaps://192.168.50.10", "ldaps://LAB-DC02.lab.local", "DC=lab,DC=local").is_err());
    }
}
