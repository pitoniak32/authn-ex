use anyhow::Result;
use passkey::{authenticator::{Authenticator, UserValidationMethod}, types::{Passkey, ctap2::Aaguid, webauthn::{CredentialCreationOptions, AuthenticatorAttestationResponse, CredentialRequestOptions, PublicKeyCredentialRequestOptions, UserVerificationRequirement, AttestationConveyancePreference, AuthenticatorAssertionResponse}, rand::random_vec}, client::{self, Client}};
use serde_json::Value;
use url::Url;

use std::time::Duration;

use reqwest::{ClientBuilder, header};

use base64::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .build()?;

    let origin = Url::parse("https://future.1password.com").expect("Should Parse");

    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};
    let store: Option<Passkey> = None;
    let my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);

    let res = client.post("http://localhost:8080/auth/request-credential-create-options").header("cookie", "TOKEN=yersh").send().await?;

    let credential_create_options: CredentialCreationOptions = serde_json::from_str(&res.text().await.unwrap()).unwrap();


    let mut my_client = Client::new(my_authenticator);

    let my_webauthn_credential = my_client
        .register(&origin, credential_create_options, None)
        .await.unwrap();

    let res = client.post("http://localhost:8080/auth/register-created-credentials").header("cookie", "TOKEN=yersh").header(header::CONTENT_TYPE, "application/json").body(serde_json::to_string(&my_webauthn_credential).unwrap()).send().await?;

    println!("{}", res.text().await.unwrap());


    list_creds(&client).await?;

    let credential_request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: random_vec(32).into(),
            timeout: None,
            rp_id: Some(String::from(origin.domain().unwrap())),
            allow_credentials: None,
            user_verification: UserVerificationRequirement::default(),
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let authenticated_cred = my_client
        .authenticate(&origin, credential_request, None)
        .await.unwrap();

    let res = client.post("http://localhost:8080/auth/validate-authenticated-credentials").header("cookie", "TOKEN=yersh").header(header::CONTENT_TYPE, "application/json").body(serde_json::to_string(&authenticated_cred).unwrap()).send().await?;

    dbg!(&res);

    Ok(())
}

pub async fn list_creds(client: &reqwest::Client) -> Result<()> {
    let res = client.get("http://localhost:8080/auth/passkeys").header("cookie", "TOKEN=yersh").send().await?;

    let keys: Vec<AuthenticatorAttestationResponse> = serde_json::from_str(&res.text().await.unwrap()).unwrap();

    dbg!(&keys.len());

    Ok(())
}

// MyUserValidationMethod is a stub impl of the UserValidationMethod trait, used later.
struct MyUserValidationMethod {}

#[async_trait::async_trait]
impl UserValidationMethod for MyUserValidationMethod {
    async fn check_user_verification(&self) -> bool {
        true
    }

    async fn check_user_presence(&self) -> bool {
        true
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}