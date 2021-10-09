extern crate base64_url;
extern crate log;

use backend::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use backend::pin::StaticPinProvider;
use backend::proto::ctap2::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialType,
    Ctap2PublicKeyCredentialUserEntity,
};
use backend::transport::hid::list_devices;
use backend::webauthn::{WebAuthn, WebAuthnManager};

use log::info;
use std::convert::TryInto;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let devices = list_devices().await.unwrap();
    info!("Devices found: {:?}", devices);

    let challenge = base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
    let pin_provider = StaticPinProvider::new("12312");
    let manager = WebAuthnManager::new(&pin_provider);

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        device.wink(TIMEOUT).await?;

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            origin: "example.org".to_owned(),
            hash: challenge.to_owned(),
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(
                &[32u8; 42],
                "mario.rossi",
                "Mario Rossi",
            ),
            require_resident_key: false,
            require_user_verification: false,
            algorithms: vec![Ctap2CredentialType {
                public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
                algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            }],
            exclude: None,
            extensions_cbor: vec![],
            timeout: TIMEOUT,
        };

        let response = manager
            .make_credential(&mut device, &make_credentials_request)
            .await
            .unwrap();
        info!("WebAuthn MakeCredential response: {:?}", response);

        let credential: Ctap2PublicKeyCredentialDescriptor = (&response).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            hash: challenge.to_owned(),
            allow: vec![credential],
            require_user_presence: false,
            require_user_verification: false,
            extensions_cbor: None,
            timeout: TIMEOUT,
        };
        let response = manager
            .get_assertion(&mut device, &get_assertion)
            .await
            .unwrap();
        info!("WebAuthn GetAssertion response: {:?}", response);
    }

    Ok(())
}
