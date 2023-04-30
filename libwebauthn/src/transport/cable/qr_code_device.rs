use std::fmt::{Debug, Display};

use async_trait::async_trait;
use p256::ecdh::EphemeralSecret;
use p256::AffinePoint as P256AffinePoint;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_indexed::SerializeIndexed;
use tracing::{debug, instrument, trace};

use super::known_devices::CableKnownDeviceInfoStore;
use super::tunnel::KNOWN_TUNNEL_DOMAINS;
use super::{channel::CableChannel, Cable};
use crate::transport::ble::bluez::{self, FidoDevice};
use crate::transport::cable::crypto::{derive, trial_decrypt_advert, KeyPurpose};
use crate::transport::cable::digit_encode;
use crate::transport::device::SupportedProtocols;
use crate::transport::error::Error;
use crate::transport::Device;
use crate::webauthn::TransportError;

const CABLE_UUID: &str = "0000fff9-0000-1000-8000-00805f9b34fb";
const ADVERTISEMENT_WAIT_LOOP_MS: u64 = 2000;

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
        let serialized = serde_cbor::to_vec(self).unwrap();
        format!("FIDO:/{}", digit_encode(&serialized))
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

    async fn await_advertisement(&self) -> Result<(FidoDevice, Vec<u8>), Error> {
        loop {
            let devices_service_data = bluez::manager::devices_by_service(CABLE_UUID)
                .await
                .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;
            debug!({ ?devices_service_data }, "Found devices with service data");
    
            let device = devices_service_data.into_iter().map(|(device, data)| {
                let eid_key = derive(&self.qr_code.qr_secret, None, KeyPurpose::EIDKey);
                trace!(?device, ?data, ?eid_key);
                let decrypted = trial_decrypt_advert(&eid_key, &data);
                trace!(?decrypted);
                (device, decrypted)
            })
            .find(|(_, decrypted)| decrypted.is_some());
    
            if let Some((device, decrypted)) = device {
                debug!(?device, ?decrypted, "Successfully decrypted advertisement from device");
                return Ok((device, decrypted.unwrap()));
            }

            debug!("No devices found with matching advertisement, waiting for new advertisement");
            sleep(Duration::from_millis(ADVERTISEMENT_WAIT_LOOP_MS as u64));
        }
    }

    
}

unsafe impl Send for CableQrCodeDevice<'_> {}
unsafe impl Sync for CableQrCodeDevice<'_> {}

impl Display for CableQrCodeDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableQrCodeDevice")
    }
}

impl

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableQrCodeDevice<'_> {
    async fn channel(&'d mut self) -> Result<CableChannel<'d>, Error> {
        let (device, advert) = self.await_advertisement().await?;
    }

    #[instrument(skip_all)]
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        todo!()
    }
}
