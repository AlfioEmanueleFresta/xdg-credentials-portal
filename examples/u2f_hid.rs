extern crate backend;
extern crate log;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::transport::hid::list_devices;
use backend::u2f::{U2FManager, U2F};

use log::info;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let devices = list_devices(true).await?;

    info!("Found {} devices.", devices.len());
    for mut device in devices {
        info!("Winking device: {}", device);
        device.wink(TIMEOUT).await?;

        const APP_ID: &str = "https://foo.example.org";
        let challenge: &[u8] =
            &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
        // Registration ceremony
        info!("Registration request sent (timeout: {:?}).", TIMEOUT);
        let register_request =
            RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT, false);
        let response = U2FManager::register(&mut device, &register_request).await?;
        info!("Response: {:?}", response);

        // Signature ceremony
        info!("Signature request sent (timeout: {:?} seconds).", TIMEOUT);
        let new_key = response.as_registered_key()?;
        let sign_request =
            SignRequest::new(&APP_ID, &challenge, &new_key.key_handle, TIMEOUT, true);
        let response = U2FManager::sign(&mut device, &sign_request).await?;
        info!("Response: {:?}", response);
    }

    return Ok(());
}
