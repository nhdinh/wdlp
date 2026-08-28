use sqlx::{Row, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use std::{env, fmt, path::PathBuf};
mod provisioning {
    use sha2::{Digest, Sha256};
    use std::process::Command;

    const VERSION: &[u8] = b"dlp-fingerprint/v1\0";

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct FingerprintSources {
        system_uuid: String,
        bios_serial: String,
        system_disk_serial: String,
    }

    impl FingerprintSources {
        pub fn new(
            system_uuid: impl AsRef<str>,
            bios_serial: impl AsRef<str>,
            system_disk_serial: impl AsRef<str>,
        ) -> Result<Self, ()> {
            Ok(Self {
                system_uuid: normalize(system_uuid.as_ref())?,
                bios_serial: normalize(bios_serial.as_ref())?,
                system_disk_serial: normalize(system_disk_serial.as_ref())?,
            })
        }
    }

    pub fn fingerprint_v1(sources: &FingerprintSources) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(VERSION);
        for (name, value) in [
            (b"smbios_uuid".as_slice(), sources.system_uuid.as_bytes()),
            (b"bios_serial".as_slice(), sources.bios_serial.as_bytes()),
            (
                b"system_disk_serial".as_slice(),
                sources.system_disk_serial.as_bytes(),
            ),
        ] {
            hasher.update((name.len() as u16).to_be_bytes());
            hasher.update(name);
            hasher.update((value.len() as u16).to_be_bytes());
            hasher.update(value);
        }
        hasher.finalize().into()
    }

    /// Uses Kerberos WinRM-over-HTTPS and keeps raw CIM values local to the trusted station.
    pub fn collect_from_trusted_station(
        computer: &str,
        allow_lab_virtual_disk_unique_id: bool,
    ) -> Result<FingerprintSources, ()> {
        let script = "$ErrorActionPreference='Stop';$computer=$env:DLP_PROVISIONING_COMPUTER;$mode=$env:DLP_PROVISIONING_DISK_MODE;if([string]::IsNullOrWhiteSpace($computer) -or $mode -notin @('production','lab-only')){throw 'invalid trusted collector configuration'};$o=New-CimSessionOption -UseSsl;$s=New-CimSession -ComputerName $computer -Authentication Kerberos -SessionOption $o;try{$p=Get-CimInstance -CimSession $s Win32_ComputerSystemProduct;$b=Get-CimInstance -CimSession $s Win32_BIOS;$l=Get-CimInstance -CimSession $s Win32_LogicalDisk -Filter \"DeviceID='C:'\";$part=Get-CimAssociatedInstance -CimSession $s -InputObject $l -Association Win32_LogicalDiskToPartition;$disk=Get-CimAssociatedInstance -CimSession $s -InputObject $part -Association Win32_DiskDriveToDiskPartition;if(@($p).Count -ne 1 -or @($b).Count -ne 1 -or @($l).Count -ne 1 -or @($part).Count -ne 1 -or @($disk).Count -ne 1){throw 'unexpected CIM cardinality'};$identity=$disk.SerialNumber;if([string]::IsNullOrWhiteSpace($identity)){if($mode -ne 'lab-only'){throw 'physical disk serial missing'};$virtual=Get-CimInstance -CimSession $s -Namespace root/Microsoft/Windows/Storage MSFT_Disk -Filter ('Number='+$disk.Index);if(@($virtual).Count -ne 1 -or -not $virtual.IsBoot -or -not $virtual.IsSystem -or [string]::IsNullOrWhiteSpace($virtual.UniqueId)){throw 'lab virtual boot disk identity unavailable'};$identity=$virtual.UniqueId};Write-Output $p.UUID;Write-Output $b.SerialNumber;Write-Output $identity}finally{Remove-CimSession $s}";
        let mode = if allow_lab_virtual_disk_unique_id {
            "lab-only"
        } else {
            "production"
        };
        let output = Command::new("powershell.exe")
            .env("DLP_PROVISIONING_COMPUTER", computer)
            .env("DLP_PROVISIONING_DISK_MODE", mode)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|_| ())?;
        if !output.status.success() {
            return Err(());
        }
        let values = String::from_utf8(output.stdout).map_err(|_| ())?;
        let mut values = values.lines();
        let result = FingerprintSources::new(
            values.next().ok_or(())?,
            values.next().ok_or(())?,
            values.next().ok_or(())?,
        );
        if values.next().is_some() {
            return Err(());
        }
        result
    }

    fn normalize(value: &str) -> Result<String, ()> {
        let value = value.trim().to_uppercase();
        if value.is_empty()
            || value.len() > 512
            || [
                "UNKNOWN",
                "NONE",
                "N/A",
                "TO BE FILLED BY O.E.M.",
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            ]
            .contains(&value.as_str())
        {
            Err(())
        } else {
            Ok(value)
        }
    }

    #[cfg(test)]
    pub fn child_environment_for_test(computer: &str, lab_mode: bool) -> [(&str, &str); 2] {
        [
            ("DLP_PROVISIONING_COMPUTER", computer),
            (
                "DLP_PROVISIONING_DISK_MODE",
                if lab_mode { "lab-only" } else { "production" },
            ),
        ]
    }
}

struct FileSecretProvider {
    path: std::path::PathBuf,
}

impl FileSecretProvider {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl dlpctl::RuntimeSecretProvider for FileSecretProvider {
    fn handoff_enrollment_token(&mut self, token: String) -> Result<(), dlpctl::ProvisioningError> {
        use std::io::Write;
        let mut file = std::fs::File::create(&self.path)
            .map_err(|_| dlpctl::ProvisioningError::SecretHandoff)?;
        file.write_all(token.as_bytes())
            .map_err(|_| dlpctl::ProvisioningError::SecretHandoff)?;
        Ok(())
    }
}

pub const MIGRATION_VERSION: i64 = 202608070001;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    MigrationStatus,
    ConfigurationPublicKey,
    Phase1Smoke { database_url: Option<String> },
    ProvisionDevice { computer: String, recovery: bool },
    EnrollmentTokenCreate { ttl_minutes: u32 },
}

impl Command {
    pub fn parse<I, S>(arguments: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut arguments = arguments.into_iter();
        match arguments
            .next()
            .map(|argument| argument.as_ref().to_owned())
        {
            Some(argument) if argument == "migration-status" && arguments.next().is_none() => {
                Ok(Self::MigrationStatus)
            }
            Some(argument)
                if argument == "configuration-public-key" && arguments.next().is_none() =>
            {
                Ok(Self::ConfigurationPublicKey)
            }
            Some(argument) if argument == "phase1-smoke" => {
                match (arguments.next(), arguments.next()) {
                    (None, None) => Ok(Self::Phase1Smoke { database_url: None }),
                    (Some(flag), Some(value))
                        if flag.as_ref() == "--database-url" && arguments.next().is_none() =>
                    {
                        Ok(Self::Phase1Smoke {
                            database_url: Some(value.as_ref().to_owned()),
                        })
                    }
                    _ => Err(CliError::Usage),
                }
            }
            Some(argument) if argument == "provision-device" => {
                let remaining = arguments
                    .map(|argument| argument.as_ref().to_owned())
                    .collect::<Vec<_>>();
                match remaining.as_slice() {
                    [flag, computer] if flag == "--computer" && valid_fqdn(computer) => {
                        Ok(Self::ProvisionDevice {
                            computer: computer.to_owned(),
                            recovery: false,
                        })
                    }
                    [flag, computer, recover]
                        if flag == "--computer"
                            && valid_fqdn(computer)
                            && recover == "--recover" =>
                    {
                        Ok(Self::ProvisionDevice {
                            computer: computer.to_owned(),
                            recovery: true,
                        })
                    }
                    _ => Err(CliError::Usage),
                }
            }
            Some(argument) if argument == "enrollment-token" => {
                match (arguments.next(), arguments.next(), arguments.next()) {
                    (Some(create), Some(ttl_flag), Some(ttl))
                        if create.as_ref() == "create" && ttl_flag.as_ref() == "--ttl" =>
                    {
                        ttl.as_ref()
                            .parse()
                            .ok()
                            .filter(|ttl: &u32| *ttl > 0 && *ttl <= 10_080)
                            .map(|ttl_minutes| Self::EnrollmentTokenCreate { ttl_minutes })
                            .ok_or(CliError::Usage)
                    }
                    _ => Err(CliError::Usage),
                }
            }
            _ => Err(CliError::Usage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    Usage,
    MissingDatabaseUrl,
    DatabaseUnavailable,
    MigrationMissing,
    TrustedStationRequired,
    ProvisioningApiUnavailable,
    InvalidSigningSeed,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Usage => {
                "usage: dlpctl migration-status | configuration-public-key | phase1-smoke [--database-url sqlite:... ] | provision-device --computer <FQDN> | enrollment-token create --ttl <minutes>"
            }
            Self::MissingDatabaseUrl => "database_url_missing",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::MigrationMissing => "expected_migration_missing",
            Self::TrustedStationRequired => "trusted_station_required",
            Self::ProvisioningApiUnavailable => "provisioning_api_unavailable",
            Self::InvalidSigningSeed => "configuration_signing_seed_invalid",
        };
        write!(formatter, "{code}")
    }
}

fn valid_fqdn(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

impl std::error::Error for CliError {}

async fn migration_status() -> Result<(), CliError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| CliError::MissingDatabaseUrl)?;
    if database_url.starts_with("sqlite:") {
        return sqlite_migration_status(&database_url).await;
    }
    let pool = PgPoolOptions::new()
        .connect(&database_url)
        .await
        .map_err(|_| CliError::DatabaseUnavailable)?;
    let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
        .bind(MIGRATION_VERSION)
        .fetch_one(&pool)
        .await
        .map_err(|_| CliError::DatabaseUnavailable)?;
    let applied: bool = row.try_get(0).map_err(|_| CliError::DatabaseUnavailable)?;
    if applied {
        println!("migration {MIGRATION_VERSION}: applied");
        Ok(())
    } else {
        Err(CliError::MigrationMissing)
    }
}

async fn sqlite_migration_status(database_url: &str) -> Result<(), CliError> {
    let pool = SqlitePoolOptions::new()
        .connect(database_url)
        .await
        .map_err(|_| CliError::DatabaseUnavailable)?;
    let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = ?)")
        .bind(MIGRATION_VERSION)
        .fetch_one(&pool)
        .await
        .map_err(|_| CliError::DatabaseUnavailable)?;
    let applied: bool = row.try_get(0).map_err(|_| CliError::DatabaseUnavailable)?;
    if applied {
        println!("migration {MIGRATION_VERSION}: applied");
        Ok(())
    } else {
        Err(CliError::MigrationMissing)
    }
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    // Enable rustls trace logging when the orchestrator sets RUST_LOG. This
    // captures the exact certificate validation decision without changing the
    // default quiet behavior.
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }

    // dlpctl depends on reqwest with the rustls feature but no explicit crypto
    // provider feature. Other workspace crates enable rustls providers, so the
    // process-level default is ambiguous. Install ring explicitly to avoid the
    // "Could not automatically determine the process-level CryptoProvider" panic.
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Command::parse(env::args().skip(1))? {
        Command::MigrationStatus => migration_status().await,
        Command::ConfigurationPublicKey => {
            let seed_hex = env::var("DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX")
                .map_err(|_| CliError::InvalidSigningSeed)?;
            let seed: [u8; 32] = hex_decode(&seed_hex)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(CliError::InvalidSigningSeed)?;
            let signer = dlp_crypto::ConfigurationSigner::from_seed("derive-only", seed);
            let public_key = signer
                .public_key_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            println!("{public_key}");
            Ok(())
        }
        Command::Phase1Smoke { database_url } => {
            let root = PathBuf::from("target").join("phase1-smoke");
            let database_url = database_url.unwrap_or_else(|| {
                format!("sqlite://{}?mode=rwc", root.join("tracer.sqlite").display())
            });
            dlpctl::run_phase1_smoke_in_runtime(&database_url, &root)
                .await
                .map_err(|_| CliError::DatabaseUnavailable)?;
            println!("phase1-smoke: passed");
            Ok(())
        }
        Command::ProvisionDevice { computer, recovery } => {
            let lab_mode = env::var("DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID")
                .ok()
                .as_deref()
                == Some("true");
            let sources = provisioning::collect_from_trusted_station(&computer, lab_mode)
                .map_err(|_| CliError::TrustedStationRequired)?;
            let fingerprint_digest = provisioning::fingerprint_v1(&sources);

            let guid = env::var("DLP_PROVISIONING_AD_OBJECT_GUID")
                .map_err(|_| CliError::TrustedStationRequired)
                .and_then(|value| hex_decode(&value).ok_or(CliError::TrustedStationRequired))?;
            let sid = env::var("DLP_PROVISIONING_AD_OBJECT_SID")
                .map_err(|_| CliError::TrustedStationRequired)
                .and_then(|value| hex_decode(&value).ok_or(CliError::TrustedStationRequired))?;
            let preferred_drive_letter = env::var("DLP_PROVISIONING_PREFERRED_DRIVE_LETTER")
                .ok()
                .and_then(|value| value.chars().next())
                .unwrap_or('P');
            let mut request = dlpctl::ProvisioningRequest::new(
                &computer,
                fingerprint_digest,
                guid,
                sid,
                preferred_drive_letter,
            )
            .map_err(|_| CliError::Usage)?;
            if recovery {
                request = request.authorize_recovery();
            }

            let endpoint = env::var("DLP_PROVISIONING_ENDPOINT")
                .map_err(|_| CliError::TrustedStationRequired)?;
            let provisioning_root_ca = env::var("DLP_PROVISIONING_ROOT_CA_PATH")
                .map_err(|_| CliError::TrustedStationRequired)?;
            let provisioning_admin_cert = env::var("DLP_PROVISIONING_ADMIN_CERT_PATH")
                .map_err(|_| CliError::TrustedStationRequired)?;
            let provisioning_admin_key = env::var("DLP_PROVISIONING_ADMIN_KEY_PATH")
                .map_err(|_| CliError::TrustedStationRequired)?;
            // Optional trust anchor for validating the configured provisioning
            // administrator material. ProvisioningClient deliberately omits a
            // self-signed administrator root from the transmitted identity.
            let provisioning_admin_ca: Option<String> =
                env::var("DLP_PROVISIONING_ADMIN_CA_CERT_PATH").ok();
            let handoff_path = env::var("DLP_PROVISIONING_TOKEN_HANDOFF_PATH")
                .map_err(|_| CliError::TrustedStationRequired)?;

            let client = dlpctl::ProvisioningClient::new(
                endpoint,
                std::path::Path::new(&provisioning_root_ca),
                std::path::Path::new(&provisioning_admin_cert),
                std::path::Path::new(&provisioning_admin_key),
                provisioning_admin_ca.as_deref().map(std::path::Path::new),
            )
            .map_err(|_| CliError::ProvisioningApiUnavailable)?;
            let mut provider = FileSecretProvider::new(std::path::PathBuf::from(handoff_path));
            client
                .provision(&request, &mut provider)
                .await
                .map_err(|_| CliError::ProvisioningApiUnavailable)?;
            Ok(())
        }
        Command::EnrollmentTokenCreate { ttl_minutes: _ } => {
            // Token display is deliberately an authenticated provisioning-station operation.
            Err(CliError::TrustedStationRequired)
        }
    }
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Command, MIGRATION_VERSION,
        provisioning::{FingerprintSources, child_environment_for_test, fingerprint_v1},
    };

    #[test]
    fn migration_status_command_is_explicit_and_read_only() {
        assert_eq!(
            Command::parse(["migration-status"]),
            Ok(Command::MigrationStatus)
        );
        assert_eq!(MIGRATION_VERSION, 202608070001);
    }

    #[test]
    fn configuration_public_key_command_is_explicit() {
        assert_eq!(
            Command::parse(["configuration-public-key"]),
            Ok(Command::ConfigurationPublicKey)
        );
    }

    #[test]
    fn enrollment_fingerprint_is_a_versioned_digest_of_only_the_three_required_sources() {
        let sources =
            FingerprintSources::new(" system-uuid ", "bios-serial", "disk-serial").unwrap();
        let first = fingerprint_v1(&sources);
        assert_eq!(first, fingerprint_v1(&sources));
        assert_ne!(
            first,
            fingerprint_v1(
                &FingerprintSources::new("system-uuid", "bios-serial", "different-disk").unwrap()
            )
        );
        assert!(FingerprintSources::new("", "bios", "disk").is_err());
        assert!(
            FingerprintSources::new("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "bios", "disk")
                .is_err()
        );
    }

    #[test]
    fn provisioning_accepts_only_a_computer_fqdn_and_no_serial_or_mac_arguments() {
        assert_eq!(
            Command::parse(["provision-device", "--computer", "device.lab.local"]),
            Ok(Command::ProvisionDevice {
                computer: "device.lab.local".into(),
                recovery: false,
            })
        );
        assert_eq!(
            Command::parse([
                "provision-device",
                "--computer",
                "device.lab.local",
                "--recover",
            ]),
            Ok(Command::ProvisionDevice {
                computer: "device.lab.local".into(),
                recovery: true,
            })
        );
        assert!(Command::parse(["provision-device", "--serial", "raw"]).is_err());
    }

    #[test]
    fn collector_passes_named_environment_without_relying_on_powershell_args() {
        assert_eq!(
            child_environment_for_test("LAB-CLIENT01.lab.local", true),
            [
                ("DLP_PROVISIONING_COMPUTER", "LAB-CLIENT01.lab.local"),
                ("DLP_PROVISIONING_DISK_MODE", "lab-only")
            ]
        );
    }
}
