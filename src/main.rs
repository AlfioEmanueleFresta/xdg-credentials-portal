mod ui;

extern crate log;

use backend::ctap1::protocol::{Ctap1RegisterRequest, Ctap1SignRequest};
use backend::{AuthenticatorBackend, LocalAuthenticatorBackend};
use dbus::blocking::Connection;
use std::time::Duration;
use ui::{NotificationPortalUI, UI};

use log::{info, warn};

// TODO: portal API (d-bus session service)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Connect to the session bus, and initialise the UI
    let mut session_bus = Connection::new_session()?;
    info!(
        "Created connection to D-Bus session bus: {:?}",
        session_bus.unique_name()
    );
    let ui = NotificationPortalUI::new(&mut session_bus);

    // Initialise the CTAP1/USB authentication backend
    let backend = LocalAuthenticatorBackend::new();
    let authenticator = backend.get_ctap1_hid_authenticator().unwrap();

    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: u32 = 30; // Seconds
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    // Registration ceremony
    println!("Registration request sent (timeout: {} seconds).", TIMEOUT);
    let dialog = ui.confirm_u2f_usb_register(APP_ID, TIMEOUT, |_| {
        warn!("User cancelled the request.");
    })?;
    let register_request = Ctap1RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT);
    let response = authenticator.register(register_request).unwrap();
    ui.cancel(dialog)?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = Ctap1SignRequest::new(&APP_ID, &challenge, vec![new_key], TIMEOUT);
    let dialog = ui.confirm_u2f_usb_sign(APP_ID, TIMEOUT, |_| {
        warn!("User cancelled the request.");
    })?;
    let response = authenticator.sign(sign_request).unwrap();
    ui.cancel(dialog)?;
    println!("Response: {:?}", response);

    // Listen to incoming signals forever.
    loop {
        session_bus.process(Duration::from_millis(1000))?;
    }
}
