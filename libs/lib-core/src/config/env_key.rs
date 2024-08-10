use std::{
    env::{self},
    net::Ipv4Addr,
    str::FromStr,
};

/// # Use this for reading config from Environment Variables
/// The goal with this enum is to provide a way to access typed configuration from Environement
/// variables.
///
/// This will allow the type to be validated before it is used by the program.
///
/// ## Steps to add new Environment Variables:
/// 1. Add the key name to this enum.
/// 1. Add the new variant in the `as_str` impl
///   (use the name of the env var you would like to provide).
/// 1. Implement the 'From' trait. You should implement this for the value
///   that you would like the Env Var to be read as.
///
/// ### Valid Examples
/// This is what using an env variable for a boolean would look like.
/// ```
/// use std::env;
/// use poc_rear_config_lib::config_env::ConfigEnvKey;
///
/// env::set_var(ConfigEnvKey::DevMode.as_str(), "true");
/// let is_dev_mode = bool::from(ConfigEnvKey::DevMode);
///
/// assert_eq!(is_dev_mode, true);
/// ```
///
/// And if no value is provided you can choose to add a default value.
/// ```
/// use std::env;
/// use poc_rear_config_lib::config_env::ConfigEnvKey;
///
/// // In this case the default for `ConfigEnvKey` is `false`.
/// env::remove_var(ConfigEnvKey::DevMode.as_str());
/// let is_dev_mode = bool::from(ConfigEnvKey::DevMode);
///
/// assert_eq!(is_dev_mode, false);
/// ```
/// ### Panic Examples
/// If you try to read an invalid value into your program, it *SHOULD* panic at config time.
/// ```should_panic
/// use std::env;
/// use poc_rear_config_lib::config_env::ConfigEnvKey;
///
/// // In this case the default for `ConfigEnvKey` is `false`.
/// env::set_var(ConfigEnvKey::DevMode.as_str(), "123not_bool");
/// let is_dev_mode = bool::from(ConfigEnvKey::DevMode);
/// ```
#[derive(Debug, Clone)]
pub enum EnvKey {
    /// Uri used to configure otlp service.
    OtelCollectorUri,
    /// Uri used to connect to mongodb.
    MongoDBUri,
    /// Port that the service will bind to.
    ServicePort,
    /// Ip that the service will bind to.
    ServiceIp,
    /// Determines if the app should be configured for development, or production.
    DevMode,
}

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const DEFAULT_SERVICE_PORT: u16 = 8080;
pub const DEFAULT_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
pub const DEFAULT_OTEL_URI: &str = "https://0.0.0.0:4317";
pub const DEFAULT_MONGO_URI: &str = "mongodb://0.0.0.0:27017";
pub const DEFAULT_LOG_FILTER: &str = "INFO";
pub const DEFAULT_DEV_MODE: bool = false;
pub const AUTH_TOKEN_STRING: &str = "access_token";

pub const ENV_KEY_SERVICE_PORT: &str = "SERVICE_PORT";
pub const ENV_KEY_SERVICE_IP: &str = "SERVICE_IP";
pub const ENV_KEY_OTEL_COLLECTOR_URI: &str = "OTEL_COLLECTOR_URI";
pub const ENV_KEY_MONGO_URI: &str = "MONGO_URI";
pub const ENV_KEY_DEV_MODE: &str = "DEV_MODE";

pub trait AsStr {
    fn as_str(&self) -> &'static str;
}

impl AsStr for EnvKey {
    fn as_str(&self) -> &'static str {
        match self {
            EnvKey::ServicePort => ENV_KEY_SERVICE_PORT,
            EnvKey::ServiceIp => ENV_KEY_SERVICE_IP,
            EnvKey::OtelCollectorUri => ENV_KEY_OTEL_COLLECTOR_URI,
            EnvKey::MongoDBUri => ENV_KEY_MONGO_URI,
            EnvKey::DevMode => ENV_KEY_DEV_MODE,
        }
    }
}

use std::sync::OnceLock;

pub fn config() -> &'static Config {
    static INSTANCE: OnceLock<Config> = OnceLock::new();

    INSTANCE.get_or_init(Config::from_env)
}

#[allow(non_snake_case)]
pub struct Config {
    pub SERVICE_PORT: u16,
    pub SERVICE_IP: Ipv4Addr,
    pub OTEL_COLLECTOR_URI: Option<String>,
    pub MONGO_DB_URI: String,
    pub DEV_MODE: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let service_port = get_value(EnvKey::ServicePort, DEFAULT_SERVICE_PORT);
        let service_ip = get_value(EnvKey::ServiceIp, DEFAULT_SERVICE_IP);
        let otel_collector_uri = get_optional_value(EnvKey::OtelCollectorUri);
        let mongo_db_uri = get_value(EnvKey::MongoDBUri, DEFAULT_MONGO_URI.to_string());
        let dev_mode = get_value(EnvKey::DevMode, DEFAULT_DEV_MODE);

        Config {
            SERVICE_PORT: service_port,
            SERVICE_IP: service_ip,
            OTEL_COLLECTOR_URI: otel_collector_uri,
            MONGO_DB_URI: mongo_db_uri,
            DEV_MODE: dev_mode,
        }
    }
}

fn get_value<T, R>(key: T, default: R) -> R
where
    T: AsStr,
    R: FromStr,
{
    match env::var(key.as_str()) {
      Ok(value) => value.parse::<R>().unwrap_or_else(|_| {
          panic!(
              "{} should be a valid {}! {} is not valid. To use default unset {} environment variable.",
              key.as_str(),
              std::any::type_name::<R>(),
              value,
              key.as_str(),
          )
      }),
      Err(_) => default,
  }
}

fn get_optional_value<T, R>(key: T) -> Option<R>
where
    T: AsStr,
    R: FromStr,
{
    match env::var(key.as_str()) {
      Ok(value) => Some(value.parse::<R>().unwrap_or_else(|_| {
          panic!(
              "{} should be a valid {}! {} is not valid. To use default unset {} environment variable.",
              key.as_str(),
              std::any::type_name::<R>(),
              value,
              key.as_str(),
          )
      })),
      Err(_) => None,
  }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rstest::rstest;
    use similar_asserts::assert_eq;

    use super::get_value;
    use super::EnvKey;
    use crate::config::env_key::AsStr;

    #[rstest]
    #[case(EnvKey::ServicePort, 8080)]
    fn test_loading_default_u16(#[case] env_key: EnvKey, #[case] default: u16) {
        // Arrange
        std::env::remove_var(env_key.as_str());

        // Act
        let result = get_value(env_key, default);

        // Assert
        assert_eq!(result, default);
    }

    #[rstest]
    #[case(EnvKey::ServicePort, "8081", 8081)]
    fn test_loading_from_env_u16(
        #[case] env_key: EnvKey,
        #[case] str_value: &str,
        #[case] expected: u16,
    ) {
        // Arrange
        std::env::set_var(env_key.as_str(), str_value);

        // Act
        let result = get_value(env_key.clone(), 0000);

        // Assert
        assert_eq!(result, expected);

        // Cleanup
        std::env::remove_var(env_key.as_str())
    }

    #[rstest]
    #[case(EnvKey::ServiceIp, Ipv4Addr::new(0, 0, 0, 0))]
    fn test_loading_default_ipv4_addr(#[case] env_key: EnvKey, #[case] default: Ipv4Addr) {
        // Arrange
        std::env::remove_var(env_key.as_str());

        // Act
        let result = get_value(env_key, default);

        // Assert
        assert_eq!(result, default);
    }

    #[rstest]
    #[case(EnvKey::ServiceIp, "127.0.0.1", Ipv4Addr::new(127, 0, 0, 1))]
    fn test_loading_from_env_ipv4_addr(
        #[case] env_key: EnvKey,
        #[case] str_value: &str,
        #[case] expected: Ipv4Addr,
    ) {
        // Arrange
        std::env::set_var(env_key.as_str(), str_value);

        // Act
        let result = get_value(env_key.clone(), Ipv4Addr::new(0, 0, 0, 0));

        // Assert
        assert_eq!(result, expected);

        // Cleanup
        std::env::remove_var(env_key.as_str())
    }

    #[rstest]
    #[case(EnvKey::DevMode, true)]
    #[case(EnvKey::DevMode, false)]
    fn test_loading_default_bool(#[case] env_key: EnvKey, #[case] default: bool) {
        // Arrange
        std::env::remove_var(env_key.as_str());

        // Act
        let result = get_value(env_key, default);

        // Assert
        assert_eq!(result, default);
    }

    #[rstest]
    #[case(EnvKey::MongoDBUri, "TEST_MONGO_DEFAULT")]
    fn test_loading_default_string(#[case] env_key: EnvKey, #[case] default: &str) {
        // Arrange
        std::env::remove_var(env_key.as_str());

        // Act
        let result = get_value(env_key, default.to_string());

        // Assert
        assert_eq!(result, default);
    }
}
