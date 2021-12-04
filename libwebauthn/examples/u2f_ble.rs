use std::time::Duration;

use tracing::info;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::u2f::{RegisterRequest, SignRequest};
use libwebauthn::transport::ble::list_devices;
use libwebauthn::u2f::{U2FManager, U2F};

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let devices = list_devices().await?;

    info!("Found {} devices.", devices.len());
    for mut device in devices {
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
