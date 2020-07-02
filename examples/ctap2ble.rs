extern crate backend;
extern crate base64_url;
extern crate blurz;
extern crate log;
extern crate tokio;

use backend::ops::webauthn::MakeCredentialRequest;
use backend::proto::ctap2::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use backend::transport::ble::BleDevicePath;
use backend::Platform;

use blurz::bluetooth_adapter::BluetoothAdapter as Adapter;
use blurz::bluetooth_device::BluetoothDevice as Device;
use blurz::bluetooth_session::BluetoothSession as Session;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    //const APP_ID: &str = "https://foo.example.org";
    //const TIMEOUT: u32 = 5; // Seconds
    //let challenge: &[u8] =
    //    &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    let platform = Platform::new();
    let ble_manager = platform.get_ble_manager().unwrap();

    // Selecting a device
    let bt_session = &Session::create_session(None)?;
    let bt_adapter = Adapter::init(bt_session)?;
    //bt_adapter.start_discovery()?;
    let bt_device_ids = bt_adapter.get_device_list()?;
    let bt_device = bt_device_ids
        .iter()
        .map(|device_id| Device::new(bt_session, device_id.to_string()))
        .find(|device| {
            device.get_alias().unwrap() == "U2F FT" || device.get_alias().unwrap() == "KVTAHN"
        });

    if let None = bt_device {
        panic!(
            "BLE pairing and discovery is outside of the scope of this example. Ensure your \
                BLE authenticator is paired, and try again."
        )
    }
    let bt_device = bt_device.unwrap();
    println!(
        "Selected BLE authenticator {} ({})",
        bt_device.get_alias()?,
        bt_device.get_address()?
    );

    let bt_device: BleDevicePath = bt_device.get_id();
    //let bt_device = "/org/bluez/hci0/dev_AC_9A_22_B1_82_02".to_owned();
    let bt_device = ble_manager.connect(&bt_device).unwrap();

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

    ble_manager
        .webauthn_make_credential(&bt_device, make_credentials_request)
        .await
        .unwrap();

    // Get Assertion ceremony
    // TODO

    Ok(())
}
