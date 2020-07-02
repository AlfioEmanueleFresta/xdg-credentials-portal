extern crate blurz;

use crate::transport::ble::device::{ConnectedDevice, KnownDevice};
use crate::transport::ble::BleDevicePath;
use crate::transport::error::TransportError;

use blurz::BluetoothSession;

pub struct DiscoverySession {
    session: BluetoothSession,
}

impl DiscoverySession {
    pub fn new() -> Self {
        Self {
            session: BluetoothSession::create_session(None).unwrap(),
        }
    }

    pub fn connect(&self, device: &BleDevicePath) -> Result<ConnectedDevice, TransportError> {
        let device = KnownDevice::new(device);
        device.connect(&self.session)
    }
}
