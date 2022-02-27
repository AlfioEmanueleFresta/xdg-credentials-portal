use std::convert::TryInto;
use std::error::Error;
use std::time::Duration;

use rand::{thread_rng, Rng};
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, UserVerificationRequirement,
};
use libwebauthn::pin::{PinProvider, StdinPromptPinProvider};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::WebAuthn;

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
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions_cbor: vec![],
            timeout: TIMEOUT,
        };

        let response = channel
            .webauthn_make_credential(&make_credentials_request, &pin_provider)
            .await
            .unwrap();
        println!("WebAuthn MakeCredential response: {:?}", response);

        let credential: Ctap2PublicKeyCredentialDescriptor = (&response).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            hash: Vec::from(challenge),
            allow: vec![credential],
            user_verification: UserVerificationRequirement::Discouraged,
            extensions_cbor: None,
            timeout: TIMEOUT,
        };
        let response = channel
            .webauthn_get_assertion(&get_assertion, &pin_provider)
            .await
            .unwrap();
        println!("WebAuthn GetAssertion response: {:?}", response);
    }

    Ok(())
}
