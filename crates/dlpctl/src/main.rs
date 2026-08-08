use sqlx::{Row, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use std::{env, fmt};

pub const MIGRATION_VERSION: i64 = 202608070001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    MigrationStatus,
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
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Usage => "usage: dlpctl migration-status",
            Self::MissingDatabaseUrl => "database_url_missing",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::MigrationMissing => "expected_migration_missing",
        };
        write!(formatter, "{code}")
    }
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
    match Command::parse(env::args().skip(1))? {
        Command::MigrationStatus => migration_status().await,
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, MIGRATION_VERSION};

    #[test]
    fn migration_status_command_is_explicit_and_read_only() {
        assert_eq!(
            Command::parse(["migration-status"]),
            Ok(Command::MigrationStatus)
        );
        assert_eq!(MIGRATION_VERSION, 202608070001);
    }
}
