pub mod ops;
pub mod proto;
pub mod transport;

use transport::ble::BLEManager;
use transport::usb::USBManager;

#[macro_use]
extern crate num_derive;

#[derive(Debug)]
pub enum Transport {
    Ctap1Hid,
    Ctap2Hid,
    Ctap2Ble,
    Ctap2Nfc,
}

pub struct Platform {}

impl Platform {
    pub fn new() -> Self {
        Platform {}
    }
    pub fn get_usb_manager(&self) -> Option<USBManager> {
        USBManager::new()
    }

    pub fn get_ble_manager(&self) -> Option<BLEManager> {
        BLEManager::new()
    }
}
