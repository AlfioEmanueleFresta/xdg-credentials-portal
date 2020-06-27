extern crate backend;
extern crate base64_url;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::Platform;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: u32 = 5; // Seconds
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    let platform = Platform::new();

    // Choose the CTAP1/USB authenticator
    let usb_manager = platform.get_usb_manager().unwrap();

    // Registration ceremony
    println!("Registration request sent (timeout: {} seconds).", TIMEOUT);
    let register_request = RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT);
    let response = usb_manager.u2f_register(register_request).await?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = SignRequest::new(&APP_ID, &challenge, vec![new_key], TIMEOUT);
    let response = usb_manager.u2f_sign(sign_request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
