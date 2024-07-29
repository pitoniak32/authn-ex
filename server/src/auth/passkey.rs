// use axum::{
//     extract::State,
//     http::StatusCode,
//     response::{IntoResponse, Response},
//     Json,
// };
// use passkey::types::{
//     rand::random_vec,
//     webauthn::{
//         AttestationConveyancePreference, AuthenticatedPublicKeyCredential, CollectedClientData,
//         CreatedPublicKeyCredential, CredentialCreationOptions, PublicKeyCredentialCreationOptions,
//         PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
//         PublicKeyCredentialUserEntity,
//     },
// };

// use coset::iana;
// use url::Url;

// #[tracing::instrument(skip_all)]
// pub async fn get_passkeys(state: State<SharedState>) -> Result<Response, StatusCode> {
//     tracing::info!("getting passkeys from store");

//     Ok((
//         StatusCode::OK,
//         Json(
//             state
//                 .lock()
//                 .await
//                 .creds
//                 .values()
//                 .cloned()
//                 .collect::<Vec<_>>(),
//         ),
//     )
//         .into_response())
// }

// /// Return the creation options for credentials
// ///
// /// Currently returning mocked values for learning.
// #[tracing::instrument(skip_all)]
// pub async fn request_credential_creation_options() -> Result<Response, StatusCode> {
//     let origin = Url::parse("https://future.1password.com").expect("origin url should parse");
//     let options = CredentialCreationOptions {
//         public_key: PublicKeyCredentialCreationOptions {
//             rp: PublicKeyCredentialRpEntity {
//                 id: None, // Leaving the ID as None means use the effective domain
//                 name: origin.domain().unwrap().into(),
//             },
//             user: PublicKeyCredentialUserEntity {
//                 id: random_vec(32).into(),
//                 display_name: "Johnny Passkey".into(),
//                 name: "jpasskey@example.org".into(),
//             },
//             challenge: random_vec(32).into(),
//             pub_key_cred_params: vec![PublicKeyCredentialParameters {
//                 ty: PublicKeyCredentialType::PublicKey,
//                 alg: iana::Algorithm::ES256,
//             }],
//             timeout: None,
//             exclude_credentials: None,
//             authenticator_selection: None,
//             hints: None,
//             attestation: AttestationConveyancePreference::None,
//             attestation_formats: None,
//             extensions: None,
//         },
//     };
//     Ok((StatusCode::OK, Json(options)).into_response())
// }

// /// Return the creation options for credentials
// ///
// /// Currently returning mocked values for learning.
// #[tracing::instrument(skip_all)]
// pub async fn register_created_credentials(
//     state: State<SharedState>,
//     credentials: Json<CreatedPublicKeyCredential>,
// ) -> Result<Response, StatusCode> {
//     println!("registering!");

//     dbg!(&state
//         .lock()
//         .await
//         .creds
//         .insert(credentials.id.clone(), credentials.response.clone()));

//     Ok((StatusCode::CREATED, "thank you, come again!").into_response())
// }

// /// Return the creation options for credentials
// ///
// /// Currently returning mocked values for learning.
// #[tracing::instrument(skip_all)]
// pub async fn validate_authenticated_credential(
//     credentials: Json<AuthenticatedPublicKeyCredential>,
// ) -> Result<Response, StatusCode> {
//     tracing::info!("validating!");

//     let result: CollectedClientData =
//         serde_json::from_slice(&credentials.response.client_data_json.to_vec()).unwrap();

//     dbg!(&result);

//     Ok((StatusCode::OK, "yup, looks good!").into_response())
// }
