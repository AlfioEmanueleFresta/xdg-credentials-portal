use super::bluez::FidoDevice as BlueZFidoDevice;

#[derive(Debug, Clone)]
pub struct BleFidoDevice {
    bluez_device: BlueZFidoDevice,
}

impl BleFidoDevice {
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

impl From<&BlueZFidoDevice> for BleFidoDevice {
    fn from(bluez_device: &BlueZFidoDevice) -> Self {
        Self {
            bluez_device: bluez_device.clone(),
        }
    }
}

impl Into<BlueZFidoDevice> for &BleFidoDevice {
    fn into(self) -> BlueZFidoDevice {
        self.bluez_device.clone()
    }
}
