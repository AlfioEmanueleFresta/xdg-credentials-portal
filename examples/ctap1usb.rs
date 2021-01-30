extern crate backend;
extern crate base64_url;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::transport::usb::{u2f_register, u2f_sign};
use std::time::Duration;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: Duration = Duration::from_secs(10);
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    // Registration ceremony
    println!(
        "Registration request sent (timeout: {:?} seconds).",
        TIMEOUT
    );
    let register_request = RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT, true);
    let response = u2f_register(register_request).await?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {:?} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = SignRequest::new(&APP_ID, &challenge, &new_key.key_handle, TIMEOUT, true);
    let response = u2f_sign(sign_request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
