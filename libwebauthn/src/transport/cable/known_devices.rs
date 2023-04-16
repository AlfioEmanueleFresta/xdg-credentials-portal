use std::fmt::Display;

use crate::transport::error::{Error, TransportError};
use crate::transport::{device::SupportedProtocols, Device};

use async_trait::async_trait;
use tracing::instrument;

use super::channel::CableChannel;
use super::Cable;

#[async_trait]
trait CableKnownDeviceStore {
    /// Called whenever a known device should be added.
    async fn put_known_device(device: &CableKnownDevice);
    /// Called whenever a known device becomes permanently unavailable.
    async fn delete_known_device(device_id: String);
}

/// A no-op known-device store for ephemeral-only implementations.
#[derive(Debug, Clone, Copy)]
struct EphemeralDeviceStore {}

impl Default for EphemeralDeviceStore {
    fn default() -> Self {
        Self {}
    }
}

#[async_trait]
impl CableKnownDeviceStore for EphemeralDeviceStore {
    async fn put_known_device(device: &CableKnownDevice) {}
    async fn delete_known_device(device_id: String) {}
}

#[derive(Debug, Clone)]
struct CableKnownDevice {
    pub device_id: String,
    pub contact_id: Vec<u8>,
    pub link_id: [u8; 8],
    pub link_secret: [u8; 32],
    pub public_key: [u8; 65],
    pub name: String,
}

impl Display for CableKnownDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.device_id)
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableKnownDevice {
    async fn channel(&'d mut self) -> Result<CableChannel<'d>, Error> {
        todo!()
    }

    #[instrument(skip_all)]
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        todo!()
    }
}
