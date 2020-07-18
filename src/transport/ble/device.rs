use super::bluez::FidoDevice as BlueZFidoDevice;

#[derive(Debug, Clone)]
pub struct FidoDevice {
    bluez_device: BlueZFidoDevice,
}

impl FidoDevice {
    pub fn alias(&self) -> String {
        self.bluez_device.alias.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.bluez_device.is_connected
    }

    pub fn is_paired(&self) -> bool {
        self.bluez_device.is_paired
    }
}

impl From<&BlueZFidoDevice> for FidoDevice {
    fn from(bluez_device: &BlueZFidoDevice) -> Self {
        Self {
            bluez_device: bluez_device.clone(),
        }
    }
}

impl Into<BlueZFidoDevice> for &FidoDevice {
    fn into(self) -> BlueZFidoDevice {
        self.bluez_device.clone()
    }
}
