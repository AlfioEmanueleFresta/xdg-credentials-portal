use std::error::Error;
use std::time::Duration;

use libwebauthn::transport::cable::discovery::CableDiscoveryManager;
use libwebauthn::transport::cable::known_devices::{
    CableKnownDeviceInfoStore, EphemeralDeviceInfoStore,
};
use libwebauthn::transport::cable::qr_code_device::{
    CableAdvertisementData, CableQrCode, CableQrCodeDevice,
};
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

    let mut device_info_store: Box<dyn CableKnownDeviceInfoStore> =
        Box::new(EphemeralDeviceInfoStore::default());
    let cable_discovery = CableDiscoveryManager::default();

    // Generate a QR code and wait for advertisement.
    let (qr_code, adv_data): (CableQrCode, CableAdvertisementData) =
        cable_discovery.generate_qr_code().await;
    println!("Generated QR code: {:?}", qr_code);

    println!("Awaiting QR code scan and BLE advertisement...");
    let mut device: CableQrCodeDevice = cable_discovery
        .await_advertisement(&adv_data, Some(&mut device_info_store))
        .await?;

    // Connect to a known device
    println!("Device advertisement received: {:?}", device);

    println!("Attempting connection to tunnel service.");
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let pin_provider: Box<dyn PinProvider> = Box::new(StdinPromptPinProvider::new());

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
    println!("WebAuthn GetAssertion response: {:?}", response);

    Ok(())
}
