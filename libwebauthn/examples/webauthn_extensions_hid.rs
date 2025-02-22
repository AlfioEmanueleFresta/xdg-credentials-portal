use std::convert::TryInto;
use std::error::Error;
use std::time::Duration;

use ctap_types::ctap2::credential_management::CredentialProtectionPolicy;
use rand::{thread_rng, Rng};
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialRequest,
    MakeCredentialsRequestExtensions, UserVerificationRequirement,
};
use libwebauthn::pin::{PinProvider, StdinPromptPinProvider};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let pin_provider: Box<dyn PinProvider> = Box::new(StdinPromptPinProvider::new());

    let extensions = MakeCredentialsRequestExtensions {
        cred_protect: Some(CredentialProtectionPolicy::Required),
        cred_blob: Some(r"My own little blob".into()),
        large_blob_key: None,
        min_pin_length: Some(true),
        hmac_secret: Some(true),
    };

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        device.wink(TIMEOUT).await?;

        let mut channel = device.channel().await?;

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            origin: "example.org".to_owned(),
            hash: Vec::from(challenge),
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            require_resident_key: true,
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(extensions.clone()),
            timeout: TIMEOUT,
        };

        let response = loop {
            match channel
                .webauthn_make_credential(&make_credentials_request, &pin_provider)
                .await
            {
                Ok(response) => break Ok(response),
                Err(WebAuthnError::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    break Err(WebAuthnError::Ctap(ctap_error));
                }
                Err(err) => break Err(err),
            };
        }
        .unwrap();
        // println!("WebAuthn MakeCredential response: {:?}", response);
        println!(
            "WebAuthn MakeCredential extensions: {:?}",
            response.authenticator_data.extensions
        );

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            hash: Vec::from(challenge),
            allow: vec![credential],
            user_verification: UserVerificationRequirement::Discouraged,
            extensions: Some(GetAssertionRequestExtensions {
                cred_blob: Some(true),
            }),
            timeout: TIMEOUT,
        };

        let response = loop {
            match channel
                .webauthn_get_assertion(&get_assertion, &pin_provider)
                .await
            {
                Ok(response) => break Ok(response),
                Err(WebAuthnError::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    break Err(WebAuthnError::Ctap(ctap_error));
                }
                Err(err) => break Err(err),
            };
        }
        .unwrap();
        // println!("WebAuthn GetAssertion response: {:?}", response);
        println!(
            "WebAuthn GetAssertion extensions: {:?}",
            response.assertions[0].authenticator_data.extensions
        );
        let blob = if let Some(ext) = &response.assertions[0].authenticator_data.extensions {
            ext.cred_blob
                .clone()
                .map(|x| String::from_utf8_lossy(&x).to_string())
        } else {
            None
        };
        println!("Credential blob: {blob:?}");
    }

    Ok(())
}
