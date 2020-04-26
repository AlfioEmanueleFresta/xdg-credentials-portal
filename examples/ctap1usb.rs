extern crate backend;
extern crate base64_url;

use backend::ctap1::protocol::{Ctap1RegisterRequest, Ctap1SignRequest};
use backend::{AuthenticatorBackend, LocalAuthenticatorBackend};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: u32 = 5; // Seconds
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    let backend = LocalAuthenticatorBackend::new();

    // Enumerate available transports
    println!("Available transports: {:?}", backend.list_transports());

    // Choose the CTAP1/USB authenticator
    let ctap1_hid_authenticator = backend.get_ctap1_hid_authenticator().unwrap();

    // Registration ceremony
    println!("Registration request sent (timeout: {} seconds).", TIMEOUT);
    let register_request = Ctap1RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT);
    let response = ctap1_hid_authenticator.register(register_request).unwrap();
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = Ctap1SignRequest::new(&APP_ID, &challenge, vec![new_key], TIMEOUT);
    let response = ctap1_hid_authenticator.sign(sign_request).unwrap();
    println!("Response: {:?}", response);

    Ok(())
}
