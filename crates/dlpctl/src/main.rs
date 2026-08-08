#[cfg(test)]
mod tests {
    use super::{Command, MIGRATION_VERSION};

    #[test]
    fn migration_status_command_is_explicit_and_read_only() {
        assert_eq!(Command::parse(["migration-status"]), Ok(Command::MigrationStatus));
        assert_eq!(MIGRATION_VERSION, 202608070001);
    }
}
