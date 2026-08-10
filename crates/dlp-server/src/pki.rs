//! Constrained device-leaf issuance.  The issuer only sees a CSR and returns public material.

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedDeviceCredential {
    pub certificate_chain_pem: String,
    pub serial: Vec<u8>,
    pub expires_after_days: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateError {
    InvalidConfiguration,
    InvalidCsr,
    IssuanceFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RcgenDeviceCertificateIssuer {
    root_certificate_path: PathBuf,
    issuing_certificate_path: PathBuf,
    issuing_key_path: PathBuf,
}

impl RcgenDeviceCertificateIssuer {
    pub fn new(
        root_certificate_path: impl Into<PathBuf>,
        issuing_certificate_path: impl Into<PathBuf>,
        issuing_key_path: impl Into<PathBuf>,
        root_private_key_path: Option<&Path>,
    ) -> Result<Self, CertificateError> {
        let root_certificate_path = root_certificate_path.into();
        let issuing_certificate_path = issuing_certificate_path.into();
        let issuing_key_path = issuing_key_path.into();
        if root_private_key_path.is_some()
            || root_certificate_path == issuing_key_path
            || issuing_certificate_path == issuing_key_path
        {
            return Err(CertificateError::InvalidConfiguration);
        }
        Ok(Self {
            root_certificate_path,
            issuing_certificate_path,
            issuing_key_path,
        })
    }

    pub fn issue_from_csr(
        &self,
        device_uuid: &str,
        csr_pem: &str,
        serial: Vec<u8>,
    ) -> Result<IssuedDeviceCredential, CertificateError> {
        if device_uuid.is_empty() || serial.is_empty() || serial.len() > 20 {
            return Err(CertificateError::InvalidCsr);
        }
        // Parses and verifies the CSR signature before it is ever eligible for issuance.
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| CertificateError::InvalidCsr)?;
        if csr.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(CertificateError::InvalidCsr);
        }
        let root = fs::read_to_string(&self.root_certificate_path)
            .map_err(|_| CertificateError::InvalidConfiguration)?;
        let issuer_certificate = fs::read_to_string(&self.issuing_certificate_path)
            .map_err(|_| CertificateError::InvalidConfiguration)?;
        let issuer_key = fs::read_to_string(&self.issuing_key_path)
            .map_err(|_| CertificateError::InvalidConfiguration)?;
        if root.contains("PRIVATE KEY") || issuer_certificate.contains("PRIVATE KEY") {
            return Err(CertificateError::InvalidConfiguration);
        }
        let key = rcgen::KeyPair::from_pem(&issuer_key)
            .map_err(|_| CertificateError::InvalidConfiguration)?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&issuer_certificate, key)
            .map_err(|_| CertificateError::InvalidConfiguration)?;
        let mut params: CertificateParams = csr.params;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let device_uri = format!("urn:dlp:device:{device_uuid}");
        let device_uri = device_uri
            .as_str()
            .try_into()
            .map_err(|_| CertificateError::InvalidCsr)?;
        params.subject_alt_names = vec![rcgen::SanType::URI(device_uri)];
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let (not_before_year, not_before_month, not_before_day) = utc_date_after_days(0);
        let (not_after_year, not_after_month, not_after_day) = utc_date_after_days(30);
        params.not_before = rcgen::date_time_ymd(
            not_before_year,
            not_before_month,
            not_before_day,
        );
        params.not_after = rcgen::date_time_ymd(not_after_year, not_after_month, not_after_day);
        let certificate = params
            .signed_by(&csr.public_key, &issuer)
            .map_err(|_| CertificateError::IssuanceFailed)?;
        Ok(IssuedDeviceCredential {
            certificate_chain_pem: format!(
                "{}\n{}\n{}",
                certificate.pem(),
                issuer_certificate,
                root
            ),
            serial,
            expires_after_days: 30,
        })
    }
}

/// Converts a UTC day count to a civil date without pulling a new time crate
/// into the approved dependency graph. Certificate validity is date-bounded to
/// the fixed Phase 1 30-day profile.
fn utc_date_after_days(additional_days: i64) -> (i32, u8, u8) {
    let unix_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        / 86_400
        + additional_days;
    let z = unix_days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}
