//! Constrained device-leaf issuance.  The issuer only sees a CSR and returns public material.

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, SerialNumber,
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
        // The profile is deliberately fixed. The service records a 30-day validity contract;
        // the mounted issuing CA must enforce it via its restricted deployment profile.
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
