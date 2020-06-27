extern crate backend;
extern crate base64_url;
extern crate tokio;

use blurz::bluetooth_adapter::BluetoothAdapter as Adapter;
use blurz::bluetooth_device::BluetoothDevice as Device;
use blurz::bluetooth_session::BluetoothSession as Session;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::transport::ble::BleDevicePath;
use backend::Platform;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: u32 = 5; // Seconds
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

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

    let device: BleDevicePath = bt_device.get_id();

    // Registration ceremony
    println!("Registration request sent (timeout: {} seconds).", TIMEOUT);
    let register_request = RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT);
    let response = ble_manager.u2f_register(&device, register_request).await?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = SignRequest::new(&APP_ID, &challenge, vec![new_key], TIMEOUT);
    let response = ble_manager.u2f_sign(&device, sign_request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
