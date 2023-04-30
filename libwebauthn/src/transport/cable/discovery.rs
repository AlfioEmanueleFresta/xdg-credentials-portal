use crate::transport::error::Error;

use super::{
    known_devices::CableKnownDeviceInfoStore,
    qr_code_device::{CableAdvertisementData, CableQrCode, CableQrCodeDevice},
};

#[derive(Debug)]
pub struct CableDiscoveryManager {}

impl Default for CableDiscoveryManager {
    fn default() -> Self {
        Self {}
    }
}

impl CableDiscoveryManager {
    pub async fn generate_qr_code(&self) -> (CableQrCode, CableAdvertisementData) {
        todo!()
    }

    pub async fn await_advertisement<'d>(
        &self,
        _adv_data: &CableAdvertisementData,
        store: Option<&'d mut Box<dyn CableKnownDeviceInfoStore>>,
    ) -> Result<CableQrCodeDevice<'d>, Error> {
        todo!()
    }
}
