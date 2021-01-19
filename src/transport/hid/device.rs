extern crate hidapi;

use hidapi::DeviceInfo;
use std::fmt;

#[derive(Debug, Clone)]
pub struct FidoDevice {
    pub hidapi_device: DeviceInfo,
}

impl From<&DeviceInfo> for FidoDevice {
    fn from(hidapi_device: &DeviceInfo) -> Self {
        Self {
            hidapi_device: hidapi_device.clone(),
        }
    }
}

impl Into<DeviceInfo> for &FidoDevice {
    fn into(self) -> DeviceInfo {
        self.hidapi_device.clone()
    }
}

impl fmt::Display for FidoDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:} {:} (r{:?})",
            self.hidapi_device.manufacturer_string().unwrap(),
            self.hidapi_device.product_string().unwrap(),
            self.hidapi_device.release_number()
        )
    }
}
