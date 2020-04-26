pub mod ctap1;

use ctap1::usb::MozillaCtap1HidAuthenticator;
use ctap1::Ctap1HidAuthenticator;

#[derive(Debug)]
pub enum Transport {
    Ctap1Hid,
    Ctap2Hid,
    Ctap2Ble,
    Ctap2Nfc,
}

pub trait AuthenticatorBackend {
    fn list_transports(&self) -> Vec<Transport>;
    fn get_ctap1_hid_authenticator(&self) -> Option<&dyn Ctap1HidAuthenticator>;
}

pub struct LocalAuthenticatorBackend {
    ctap1_hid_authenticator: MozillaCtap1HidAuthenticator,
}

impl LocalAuthenticatorBackend {
    pub fn new() -> Self {
        let mozilla_ctap1_hid_authenticator = MozillaCtap1HidAuthenticator::new();
        Self {
            ctap1_hid_authenticator: mozilla_ctap1_hid_authenticator,
        }
    }
}

impl AuthenticatorBackend for LocalAuthenticatorBackend {
    fn list_transports(&self) -> Vec<Transport> {
        vec![Transport::Ctap1Hid]
    }

    fn get_ctap1_hid_authenticator(&self) -> Option<&dyn Ctap1HidAuthenticator> {
        Some(&self.ctap1_hid_authenticator)
    }
}
