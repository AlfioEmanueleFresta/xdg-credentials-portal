use std::fmt::Debug;
use std::fmt::Display;

use async_trait::async_trait;
use p256::ecdh::EphemeralSecret;
use p256::AffinePoint as P256AffinePoint;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_indexed::SerializeIndexed;
use tracing::instrument;

use super::known_devices::CableKnownDeviceInfoStore;
use super::tunnel::KNOWN_TUNNEL_DOMAINS;
use super::{channel::CableChannel, Cable};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::Error;
use crate::transport::Device;

#[derive(Debug)]
pub struct CableAdvertisementData {}

#[derive(Debug, Clone, Copy)]

pub enum QrCodeOperationHint {
    GetAssertionRequest,
    MakeCredential,
}

impl Serialize for QrCodeOperationHint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            QrCodeOperationHint::GetAssertionRequest => serializer.serialize_str("ga"),
            QrCodeOperationHint::MakeCredential => serializer.serialize_str("mc"),
        }
    }
}

#[derive(Debug, SerializeIndexed)]
pub struct CableQrCode {
    // Key 0: a 33-byte, P-256, X9.62, compressed public key.
    pub public_key: P256AffinePoint,
    // Key 1: a 16-byte random QR secret.
    pub qr_secret: [u8; 16],
    /// Key 2: the number of assigned tunnel server domains known to this implementation.
    pub known_tunnel_domains_count: u8,
    /// Key 3: (optional) the current time in epoch seconds.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<u64>,
    /// Key 4: (optional) a boolean that is true if the device displaying the QR code can perform state-
    ///   assisted transactions.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_assisted: Option<bool>,
    /// Key 5: either the string “ga” to hint that a getAssertion will follow, or “mc” to hint that a
    ///   makeCredential will follow. Implementations SHOULD treat unknown values as if they were “ga”.
    ///   This ﬁeld exists so that guidance can be given to the user immediately upon scanning the QR code,
    ///   prior to the authenticator receiving any CTAP message. While this hint SHOULD be as accurate as
    ///   possible, it does not constrain the subsequent CTAP messages that the platform may send.
    pub operation_hint: QrCodeOperationHint,
}

impl ToString for CableQrCode {
    fn to_string(&self) -> String {
        todo!()
    }
}

/// Represents a new device which will connect by scanning a QR code.
/// This could be a new device, or an ephmemeral device whose details were not stored.
pub struct CableQrCodeDevice<'d> {
    /// The QR code to be scanned by the new authenticator.
    pub qr_code: CableQrCode,
    /// An ephemeral private, corresponding to the public key within the QR code.
    private_key: EphemeralSecret,
    /// An optional reference to the store. This may be None, if no persistence is desired.
    store: Option<&'d mut Box<dyn CableKnownDeviceInfoStore>>,
}

impl Debug for CableQrCodeDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CableQrCodeDevice")
            .field("qr_code", &self.qr_code)
            .field("store", &self.store)
            .finish()
    }
}

impl<'d> CableQrCodeDevice<'d> {
    /// Generates a QR code, linking the provided known-device store. A device scanning
    /// this QR code may be persisted to the store after a successful connection.
    pub fn new_persistent(
        hint: QrCodeOperationHint,
        store: &'d mut Box<dyn CableKnownDeviceInfoStore>,
    ) -> Self {
        Self::new(hint, true, Some(store))
    }

    fn new(
        hint: QrCodeOperationHint,
        state_assisted: bool,
        store: Option<&'d mut Box<dyn CableKnownDeviceInfoStore>>,
    ) -> Self {
        let private_key = EphemeralSecret::random(&mut OsRng);
        let public_key = private_key.public_key().as_affine().to_owned();
        let mut qr_secret = [0u8; 16];
        OsRng::default().fill_bytes(&mut qr_secret);

        Self {
            qr_code: CableQrCode {
                public_key,
                qr_secret,
                known_tunnel_domains_count: KNOWN_TUNNEL_DOMAINS.len() as u8,
                current_time: None,
                operation_hint: hint,
                state_assisted: Some(state_assisted),
            },
            private_key,
            store,
        }
    }
}

impl CableQrCodeDevice<'_> {
    /// Generates a QR code, without any known-device store. A device scanning this QR code
    /// will not be persisted.
    pub fn new_transient(hint: QrCodeOperationHint) -> Self {
        Self::new(hint, false, None)
    }
}

unsafe impl Send for CableQrCodeDevice<'_> {}
unsafe impl Sync for CableQrCodeDevice<'_> {}

impl Display for CableQrCodeDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableQrCodeDevice")
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableQrCodeDevice<'_> {
    async fn channel(&'d mut self) -> Result<CableChannel<'d>, Error> {
        todo!()
    }

    #[instrument(skip_all)]
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        todo!()
    }
}
