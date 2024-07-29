// // Declare all the environment variables needed by the application.
// // Call a function to ensure all the required variables are present.
// // Quick access to the values based on keys

// use std::{collections::HashMap, env::VarError};

// use lazy_static::lazy_static;

// lazy_static! {
//     static ref ENVIRONMENT: HashMap<EnvKey, String> = {
//         let mut m = HashMap::new();
//         let result = load_env(&mut m);
//         m.insert(EnvKey::MongoUri, std::env::var("MONGO_URI").unwrap_or("TEST".to_string()));
//         m
//     };
//     static ref ENVIONMENT_COUNT: usize = ENVIRONMENT.len();
// }

// const ENV_KEY_MONGO_URI: &'static str = "MONGO_URI";
// const ENV_DEFAULT_MONGO_URI: &'static str = "mongodb://0.0.0.0:27017";

// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub enum EnvKey {
//   MongoUri,
// }

// fn load_env(map: &mut HashMap<EnvKey, String>) -> Vec<VarError> {
//   map.insert(EnvKey::MongoUri, std::env::var(ENV_KEY_MONGO_URI).unwrap_or(ENV_DEFAULT_MONGO_URI.to_owned()));
//   vec![]
// }

// #[cfg(test)]
// mod tests {
//     use rstest::rstest;
//     use similar_asserts::assert_eq;

//     use crate::config::env::{EnvKey, ENVIONMENT_COUNT, ENVIRONMENT};

//     #[rstest]
//     fn test_lazy_environment() {
//         // Arrange
//         // Act
//         let mongo_uri = EnvKey::MongoUri.get();

//         // Assert
//         assert_eq!(mongo_uri, "TEST".to_string());
//     }
// }
