extern crate hidapi;

pub mod device;
pub mod framing;

use device::FidoDevice;

use hidapi::HidApi;

pub async fn list_devices() -> Vec<FidoDevice> {
    let api = HidApi::new().unwrap();
    api.device_list()
        .into_iter()
        .filter(|device| device.usage_page() == 0xF1D0)
        .filter(|device| device.usage() == 0x0001)
        .map(|device| device.into())
        .collect()
}
