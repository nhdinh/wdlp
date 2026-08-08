#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{
        ActiveConfigurationSet, ConfigurationActivator, EnrollmentPort, HealthReporter,
    };

    #[test]
    fn exposes_portable_enrollment_configuration_and_health_ports() {
        fn assert_ports<T: EnrollmentPort + ConfigurationActivator + HealthReporter>() {}
        let _ = std::marker::PhantomData::<ActiveConfigurationSet>;
        assert_ports::<()>();
    }
}
