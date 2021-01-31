extern crate backend;
extern crate log;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::transport::hid::{ctap1_register, ctap1_sign, ctap1_version, list_devices, wink};
use log::info;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let devices = list_devices().await?;

    info!("Found {} devices.", devices.len());
    for device in &devices {
        info!("Winking device: {}", device);
        wink(&device).await?;

        info!("Requesting version");
        ctap1_version(&device).await?;

        const APP_ID: &str = "https://foo.example.org";
        const TIMEOUT: Duration = Duration::from_secs(10);
        let challenge: &[u8] =
            &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
        // Registration ceremony
        info!("Registration request sent (timeout: {:?}).", TIMEOUT);
        let register_request =
            RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT, false);
        let response = ctap1_register(&device, &register_request).await?;
        info!("Response: {:?}", response);

        // Signature ceremony
        info!("Signature request sent (timeout: {:?} seconds).", TIMEOUT);
        let new_key = response.as_registered_key()?;
        let sign_request =
            SignRequest::new(&APP_ID, &challenge, &new_key.key_handle, TIMEOUT, true);
        let response = ctap1_sign(&device, &sign_request).await?;
        info!("Response: {:?}", response);
    }

    return Ok(());
}
