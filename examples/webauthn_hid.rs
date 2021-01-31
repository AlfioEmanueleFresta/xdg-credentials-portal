extern crate base64_url;
extern crate log;

use backend::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use backend::proto::ctap2::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use backend::transport::hid::{
    list_devices, webauthn_get_assertion, webauthn_make_credential, wink,
};

use log::info;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Devices enumeration
    let devices = list_devices().await?;
    println!("Found devices: {:?}", devices);

    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    // Selecting a device
    for device in devices {
        println!("Selected BLE authenticator: {}", &device);
        wink(&device);

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            origin: "example.org".to_owned(),
            hash: Vec::from(challenge),
            relying_party: Ctap2PublicKeyCredentialRpEntity {
                id: "example.org".to_owned(),
            },
            user: Ctap2PublicKeyCredentialUserEntity {
                id: vec![0x42],
                display_name: "Mario Rossi".to_owned(),
            },
            require_resident_key: false,
            require_user_presence: true,
            require_user_verification: false,
            algorithms: vec![Ctap2CredentialType {
                public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
                algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            }],
            exclude: None,
            extensions_cbor: vec![],
            timeout: Duration::from_secs(5),
        };
        let response = webauthn_make_credential(&device, &make_credentials_request)
            .await
            .unwrap();
        info!("WebAuthn MakeCredential response: {:?}", response);

        // Get Assertion ceremony

        // TODO
    }

    Ok(())
}
