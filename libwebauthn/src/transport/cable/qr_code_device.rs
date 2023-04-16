use crate::transport::Device;

pub struct CableQrCode {
    pub expiry_time: DateTime,
    pub contents: Vec<u8>,
}

pub struct CableQrCodePayload {
    // Key 0: a 33-byte, P-256, X9.62, compressed public key.
    pub public_key: [u8; 33],
    // Key 1: a 16-byte random QR secret.
    pub qr_code: CableQrCode,
}

/// Represents a new device which will connect by scanning a QR code.
/// This could be a new device, or an ephmemeral device whose details were not stored.
#[derive(Debug, Clone)]
pub struct CableQrCodeDevice {}

impl Display for CableQrCodeDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableQrCodeDevice")
    }
}

impl<'d> Device<'d, Cable, CableChannel<'d>> for CableQrCodeDevice {
    async fn channel(&'d mut self) -> Result<CableChannel<'d>, Error> {
        todo!()
    }

    #[instrument(skip_all)]
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        todo!()
    }
}
