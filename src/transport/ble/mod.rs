mod device;
mod discovery;
mod framing;
mod gatt;

extern crate log;

use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};
use crate::proto::CtapError;

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

use log::{debug, info, warn};
use std::convert::TryInto;

use crate::transport::ble::discovery::DiscoverySession;
use crate::transport::ble::framing::BleCommand;
use crate::transport::error::Error::{Ctap, Transport};
use crate::transport::error::{Error, TransportError};

use device::{ConnectedDevice, KnownDevice};
use framing::BleFrame;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(u8)]
pub enum FidoRevision {
    V2 = 0x20,
    U2fv12 = 0x40,
    U2fv11 = 0x80,
}

enum FidoProtocol {
    FIDO2,
    U2F,
}

impl From<FidoRevision> for FidoProtocol {
    fn from(revision: FidoRevision) -> Self {
        match revision {
            FidoRevision::V2 => FidoProtocol::FIDO2,
            FidoRevision::U2fv11 | FidoRevision::U2fv12 => FidoProtocol::U2F,
        }
    }
}

pub type BleDevicePath = String;

pub struct BLEManager {
    discovery_session: DiscoverySession,
}

impl BLEManager {
    pub fn new() -> Option<Self> {
        // TODO check if BLE is available
        let manager = Self {
            discovery_session: DiscoverySession::new(),
        };
        Some(manager)
    }

    pub fn connect(&self, device: &BleDevicePath) -> Result<ConnectedDevice, TransportError> {
        self.discovery_session.connect(device)
    }

    fn negotiate_protocol(
        &self,
        device: &ConnectedDevice<'_>,
        allow_fido2: bool,
        allow_u2f: bool,
    ) -> Result<Option<FidoProtocol>, Error> {
        info!(
            "Protocol negotiation requirements: allow_fido2={}, allow_u2f={}",
            allow_fido2, allow_u2f
        );
        let supported = device.supported_fido_revisions()?;

        return if allow_fido2 && supported.contains(&FidoRevision::V2) {
            device.select_fido_revision(FidoRevision::V2)?;
            Ok(Some(FidoProtocol::FIDO2))
        } else if allow_u2f && supported.contains(&FidoRevision::U2fv12) {
            device.select_fido_revision(FidoRevision::U2fv12)?;
            Ok(Some(FidoProtocol::U2F))
        } else if allow_u2f && supported.contains(&FidoRevision::U2fv11) {
            device.select_fido_revision(FidoRevision::U2fv11)?;
            Ok(Some(FidoProtocol::U2F))
        } else {
            warn!("Negotiation failed");
            Ok(None)
        };
    }

    pub async fn webauthn_make_credential(
        &self,
        device: &ConnectedDevice<'_>,
        op: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let downgradable = true; // FIXME check!
        let protocol = self.negotiate_protocol(device, true, downgradable)?;

        match protocol {
            Some(FidoProtocol::FIDO2) => self.ctap2_make_credential(device, op).await,
            Some(FidoProtocol::U2F) => {
                let register_request: RegisterRequest =
                    op.try_into().or(Err(TransportError::NegotiationFailed))?;
                self.ctap1_register(device, register_request)
                    .await?
                    .try_into()
                    .or(Err(Ctap(CtapError::UnsupportedOption)))
            }
            None => Err(Transport(TransportError::NegotiationFailed)),
        }
    }

    pub async fn webauthn_get_assertion(
        &self,
        device: &ConnectedDevice<'_>,
        op: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let downgradable = true; // FIXME check!
        let protocol = self.negotiate_protocol(device, true, downgradable)?;

        match protocol {
            Some(FidoProtocol::FIDO2) => self.ctap2_get_assertion(device, op).await,
            Some(FidoProtocol::U2F) => {
                let sign_request: SignRequest =
                    op.try_into().or(Err(TransportError::NegotiationFailed))?;
                self.ctap1_sign(device, sign_request)
                    .await?
                    .try_into()
                    .or(Err(Ctap(CtapError::UnsupportedOption)))
            }
            None => Err(Error::Transport(TransportError::NegotiationFailed)),
        }
    }

    pub async fn u2f_register(
        &self,
        device: &ConnectedDevice<'_>,
        op: RegisterRequest,
    ) -> Result<RegisterResponse, Error> {
        let protocol = self.negotiate_protocol(device, false, true)?;

        match protocol {
            Some(FidoProtocol::U2F) => self.ctap1_register(device, op).await,
            _ => Err(Transport(TransportError::NegotiationFailed)),
        }
    }

    pub async fn u2f_sign(
        &self,
        device: &ConnectedDevice<'_>,
        op: SignRequest,
    ) -> Result<SignResponse, Error> {
        let protocol = self.negotiate_protocol(device, false, true)?;

        match protocol {
            Some(FidoProtocol::U2F) => self.ctap1_sign(device, op).await,
            _ => Err(Transport(TransportError::NegotiationFailed)),
        }
    }

    async fn ctap2_make_credential(
        &self,
        _: &ConnectedDevice<'_>,
        _: Ctap2MakeCredentialRequest,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        unimplemented!()
    }

    async fn ctap2_get_assertion(
        &self,
        _: &ConnectedDevice<'_>,
        _: Ctap2GetAssertionRequest,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        unimplemented!()
    }

    async fn ctap1_register(
        &self,
        device: &ConnectedDevice<'_>,
        request: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error> {
        let timeout_ms = request.timeout_seconds * 1000;

        let apdu_request: ApduRequest = request.into();
        let apdu_response = self.send_apdu_request(device, apdu_request, timeout_ms)?;

        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
        info!("Register response: {:?}", response);

        Ok(response)
    }

    async fn ctap1_sign(
        &self,
        device: &ConnectedDevice<'_>,
        request: Ctap1SignRequest,
    ) -> Result<Ctap1SignResponse, Error> {
        let timeout_ms = request.timeout_seconds * 1000;

        let apdu_request: ApduRequest = request.into();
        let apdu_response = self.send_apdu_request(device, apdu_request, timeout_ms)?;

        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
        info!("Sign response: {:?}", response);

        Ok(response)
    }

    fn send_apdu_request(
        &self,
        device: &ConnectedDevice<'_>,
        request: ApduRequest,
        timeout_ms: u32,
    ) -> Result<ApduResponse, Error> {
        let max_fragment_length = device.control_point_length()?;

        debug!("Sending APDU request: {:?}", request);
        let request_apdu_packet = request.raw_long().or(Err(TransportError::InvalidFraming))?;
        let request_frame = BleFrame::new(
            Some(max_fragment_length),
            BleCommand::Msg,
            &request_apdu_packet,
        );

        let response_frame = device.send_frame_and_wait_for_response(request_frame, timeout_ms)?;
        match response_frame.cmd {
            BleCommand::Error => return Err(Error::Transport(TransportError::InvalidFraming)), // Encapsulation layer error
            BleCommand::Cancel => return Err(Error::Ctap(CtapError::KeepAliveCancel)),
            BleCommand::Keepalive | BleCommand::Ping => return Err(Error::Ctap(CtapError::Other)), // Unexpected
            BleCommand::Msg => {}
        }
        let response_apdu_packet = &response_frame.data;
        let response_apdu: ApduResponse = response_apdu_packet
            .try_into()
            .or(Err(TransportError::InvalidFraming))?;

        debug!("Received APDU response: {:?}", &response_apdu);
        Ok(response_apdu)
    }
}

#[cfg(tests)]
pub mod tests {
    use mockall::mock;

    use std::error::Error as StdError;

    mock! {
        BluetoothSession {}
        trait BluetoothSession {
            fn create_session(session: Option<&str>) -> Result<BluetoothSession, Box<StdError>>;
        }
    }

    #[test]
    fn test_connection_failed() {}
}
