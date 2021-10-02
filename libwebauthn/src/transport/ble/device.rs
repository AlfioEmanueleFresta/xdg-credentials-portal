extern crate async_trait;
extern crate log;

use async_trait::async_trait;
use log::debug;
use std::convert::TryInto;
use std::fmt;
use std::time::Duration;

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::CtapError;

use crate::fido::FidoProtocol;

use crate::transport::device::{FidoDevice, SupportedProtocols};
use crate::transport::error::Error::Transport;
use crate::transport::error::{Error, TransportError};

use super::bluez::manager::SupportedRevisions;
use super::bluez::{supported_fido_revisions, FidoDevice as BlueZFidoDevice};

use super::bluez;
use super::framing::{BleCommand, BleFrame};

pub async fn list_devices() -> Result<Vec<BleFidoDevice>, Error> {
    let devices = bluez::list_devices()
        .await
        .or(Err(Error::Transport(TransportError::TransportUnavailable)))?
        .iter()
        .map(|bluez_device| bluez_device.into())
        .collect();
    Ok(devices)
}
#[derive(Debug, Clone)]
pub struct BleFidoDevice {
    bluez_device: BlueZFidoDevice,
    revisions: Option<SupportedRevisions>,
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
            revisions: None,
        }
    }
}

impl Into<BlueZFidoDevice> for &BleFidoDevice {
    fn into(self) -> BlueZFidoDevice {
        self.bluez_device.clone()
    }
}

impl fmt::Display for BleFidoDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:} ({:}, {:}",
            self.alias(),
            if self.is_connected() {
                "connected"
            } else {
                "not connected"
            },
            if self.is_paired() {
                "paired"
            } else {
                "unpaired"
            }
        )
    }
}

#[async_trait]
impl FidoDevice for BleFidoDevice {
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        let revisions = match self.revisions {
            None => {
                let r = supported_fido_revisions(&self.bluez_device)
                    .await
                    .or(Err(Error::Transport(TransportError::NegotiationFailed)))?;
                self.revisions = Some(r);
                r
            }
            Some(r) => r,
        };

        let protocols = SupportedProtocols {
            u2f: revisions.u2fv11 || revisions.u2fv12,
            fido2: revisions.v2,
        };
        Ok(protocols)
    }

    async fn send_apdu_request(
        &mut self,
        request: &ApduRequest,
        timeout: Duration,
    ) -> Result<ApduResponse, Error> {
        self.supported_protocols().await?;
        assert!(self.revisions.is_some());
        let revision = self
            .revisions
            .unwrap()
            .select_protocol(FidoProtocol::U2F)
            .ok_or(Transport(TransportError::NegotiationFailed))?;

        debug!("Sending APDU request (rev.: {:?}): {:?}", revision, request);
        let request_apdu_packet = request.raw_long().or(Err(TransportError::InvalidFraming))?;
        let request_frame = BleFrame::new(BleCommand::Msg, &request_apdu_packet);
        let response_frame = bluez::request(&self.bluez_device, &revision, &request_frame, timeout)
            .await
            .or(Err(Transport(TransportError::ConnectionFailed)))?;
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

    async fn send_cbor_request(
        &mut self,
        _: &crate::proto::ctap2::cbor::CborRequest,
        _: std::time::Duration,
    ) -> Result<crate::proto::ctap2::cbor::CborResponse, crate::transport::error::Error> {
        todo!()
    }
}

impl BleFidoDevice {}
