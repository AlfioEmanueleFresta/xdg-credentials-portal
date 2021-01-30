extern crate backend;
extern crate base64_url;
extern crate log;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::transport::ble::{list_devices, u2f_register, u2f_sign};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn build_client_data(challenge: &Vec<u8>, app_id: &str) -> (String, Vec<u8>) {
    let challenge_base64url = base64_url::encode(&challenge);
    let version_string = "U2F_V2";

    let client_data = format!(
        "{{\"challenge\": \"{}\", \"version:\": \"{}\", \"appId\": \"{}\"}}",
        challenge_base64url, version_string, app_id
    );

    let mut hasher = Sha256::default();
    hasher.input(client_data.as_bytes());
    let client_data_hash = hasher.result().to_vec();

    (client_data, client_data_hash)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: Duration = Duration::from_secs(10);
    let challenge = base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
    let (_, client_data_hash) = build_client_data(&challenge, APP_ID);

    // Devices enumeration
    let devices = list_devices().await?;
    println!("Found devices: {:?}", devices);

    // Selecting a device
    let device = devices.get(0).expect("No FIDO BLE devices found.");
    println!("Selected BLE authenticator: {}", device.alias());

    // Registration ceremony
    println!(
        "Registration request sent (timeout: {:?} seconds).",
        TIMEOUT
    );
    let register_request =
        RegisterRequest::new_u2f_v2(&APP_ID, &client_data_hash, vec![], TIMEOUT, true);
    let response = u2f_register(device, &register_request).await?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {:?} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = SignRequest::new(
        &APP_ID,
        &client_data_hash,
        &new_key.key_handle,
        TIMEOUT,
        true,
    );
    let response = u2f_sign(device, &sign_request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
