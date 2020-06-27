mod ui;

extern crate log;
extern crate tokio;

use backend::ops::u2f::{RegisterRequest, SignRequest};
use backend::Platform;

use dbus::blocking::Connection;
use ui::{NotificationPortalUI, UI};

use log::{info, warn};

// TODO: portal API (d-bus session service)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Connect to the session bus, and initialise the UI
    let mut session_bus = Connection::new_session()?;
    info!(
        "Created connection to D-Bus session bus: {:?}",
        session_bus.unique_name()
    );
    let ui = NotificationPortalUI::new(&mut session_bus);

    // Initialise the CTAP1/USB authentication backend
    let platform = Platform::new();
    let manager = platform.get_usb_manager().unwrap();

    const APP_ID: &str = "https://foo.example.org";
    const TIMEOUT: u32 = 30; // Seconds
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    // Registration ceremony
    println!("Registration request sent (timeout: {} seconds).", TIMEOUT);
    let dialog = ui.confirm_u2f_usb_register(APP_ID, TIMEOUT, |_| {
        warn!("User cancelled the request.");
    })?;
    let register_request = RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT);
    let response = manager.u2f_register(register_request).await?;
    ui.cancel(dialog)?;
    println!("Response: {:?}", response);

    // Signature ceremony
    println!("Signature request sent (timeout: {} seconds).", TIMEOUT);
    let new_key = response.as_registered_key()?;
    let sign_request = SignRequest::new(&APP_ID, &challenge, vec![new_key], TIMEOUT);
    let dialog = ui.confirm_u2f_usb_sign(APP_ID, TIMEOUT, |_| {
        warn!("User cancelled the request.");
    })?;
    let response = manager.u2f_sign(sign_request).await?;
    ui.cancel(dialog)?;
    println!("Response: {:?}", response);

    Ok(())
}
