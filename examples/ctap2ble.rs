use backend::ops::webauthn::MakeCredentialRequest;
use backend::proto::ctap2::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use backend::transport::ble::{list_devices, webauthn_make_credential};

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    //const APP_ID: &str = "https://foo.example.org";
    //const TIMEOUT: u32 = 5; // Seconds
    //let challenge: &[u8] =
    //    &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    // Devices enumeration
    let devices = list_devices().await?;
    println!("Found devices: {:?}", devices);

    // Selecting a device
    let device = devices.get(0).expect("No FIDO BLE devices found.");
    println!("Selected BLE authenticator: {}", device.alias());

    // Make Credentials ceremony
    let make_credentials_request = MakeCredentialRequest {
        origin: "example.org".to_owned(),
        hash: vec![0x01, 0x02],
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
    };

    webauthn_make_credential(device, &make_credentials_request)
        .await
        .unwrap();

    // Get Assertion ceremony
    // TODO

    Ok(())
}
