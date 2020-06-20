#[macro_use]
extern crate num_derive;

pub mod ctap1;
pub mod ctap2;

use ctap1::{Ctap1HidAuthenticator, MozillaCtap1HidAuthenticator};
use ctap2::{BlueZCtap2BleAuthenticator, Ctap2BleAuthenticator};

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
    fn get_ctap2_ble_authenticator(&self) -> Option<&dyn Ctap2BleAuthenticator>;
}

pub struct LocalAuthenticatorBackend {
    ctap1_hid_authenticator: MozillaCtap1HidAuthenticator,
    ctap2_ble_authenticator: BlueZCtap2BleAuthenticator,
}

impl LocalAuthenticatorBackend {
    pub fn new() -> Self {
        Self {
            ctap1_hid_authenticator: MozillaCtap1HidAuthenticator::new(),
            ctap2_ble_authenticator: BlueZCtap2BleAuthenticator::new(),
        }
    }
}

impl AuthenticatorBackend for LocalAuthenticatorBackend {
    fn list_transports(&self) -> Vec<Transport> {
        vec![Transport::Ctap1Hid, Transport::Ctap2Ble]
    }

    fn get_ctap1_hid_authenticator(&self) -> Option<&dyn Ctap1HidAuthenticator> {
        Some(&self.ctap1_hid_authenticator)
    }

    fn get_ctap2_ble_authenticator(&self) -> Option<&dyn Ctap2BleAuthenticator> {
        Some(&self.ctap2_ble_authenticator)
    }
}
