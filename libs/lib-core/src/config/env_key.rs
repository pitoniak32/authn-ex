use std::{
    env::{self},
    net::Ipv4Addr,
    str::FromStr,
};

#[derive(Debug, Clone)]
pub enum EnvKey {
    /// Uri used to configure otlp service.
    OtelCollectorUri,
    /// Uri used to connect to mongodb.
    MongoDbUri,
    /// Name used to create db in mongodb.
    MongoDbName,
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
pub const ENV_KEY_MONGO_DB_URI: &str = "MONGO_DB_URI";
pub const ENV_KEY_MONGO_DB_NAME: &str = "MONGO_DB_NAME";
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
            EnvKey::MongoDbUri => ENV_KEY_MONGO_DB_URI,
            EnvKey::MongoDbName => ENV_KEY_MONGO_DB_NAME,
            EnvKey::DevMode => ENV_KEY_DEV_MODE,
        }
    }
}

use std::sync::OnceLock;

pub fn get_config() -> &'static Config {
    static INSTANCE: OnceLock<Config> = OnceLock::new();

    INSTANCE.get_or_init(Config::from_env)
}

#[allow(non_snake_case)]
pub struct Config {
    pub SERVICE_PORT: u16,
    pub SERVICE_IP: Ipv4Addr,
    pub OTEL_COLLECTOR_URI: Option<String>,
    pub MONGO_DB_URI: String,
    pub MONGO_DB_NAME: String,
    pub DEV_MODE: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let service_port = get_value(EnvKey::ServicePort, DEFAULT_SERVICE_PORT);
        let service_ip = get_value(EnvKey::ServiceIp, DEFAULT_SERVICE_IP);
        let otel_collector_uri = get_optional_value(EnvKey::OtelCollectorUri);
        let mongo_db_uri = get_value(EnvKey::MongoDbUri, DEFAULT_MONGO_URI.to_string());
        let mongo_db_name = get_value(EnvKey::MongoDbName, APP_NAME.to_string());
        let dev_mode = get_value(EnvKey::DevMode, DEFAULT_DEV_MODE);

        Config {
            SERVICE_PORT: service_port,
            SERVICE_IP: service_ip,
            OTEL_COLLECTOR_URI: otel_collector_uri,
            MONGO_DB_URI: mongo_db_uri,
            MONGO_DB_NAME: mongo_db_name,
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
