use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use crate::fido::{FidoProtocol, FidoRevision};
use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::CtapError;
use crate::transport::ble::bluez;
use crate::transport::channel::{
    Channel, ChannelStatus, Ctap2AuthTokenIdentifier, Ctap2AuthTokenStore,
};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::{Error, TransportError};

use super::bluez::manager::SupportedRevisions;
use super::bluez::Connection;
use super::framing::{BleCommand, BleFrame};
use super::BleDevice;

use async_trait::async_trait;
use tracing::{debug, instrument, trace, warn, Level};

#[derive(Debug)]
pub struct BleChannel<'a> {
    status: ChannelStatus,
    device: &'a BleDevice,
    connection: Connection,
    revision: FidoRevision,
    auth_token_storage: Option<(Ctap2AuthTokenIdentifier, Vec<u8>)>,
}

impl<'a> BleChannel<'a> {
    pub async fn new(
        device: &'a BleDevice,
        revisions: &SupportedRevisions,
    ) -> Result<BleChannel<'a>, Error> {
        let revision = revisions
            .select_protocol(FidoProtocol::U2F)
            .ok_or(Error::Transport(TransportError::NegotiationFailed))?;
        let connection = bluez::connect(&device.bluez_device, &revision)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        let channel = BleChannel {
            status: ChannelStatus::Ready,
            device,
            connection,
            revision,
            auth_token_storage: None,
        };
        bluez::notify_start(&channel.connection)
            .await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;
        Ok(channel)
    }
}

impl<'a> Drop for BleChannel<'a> {
    #[instrument(skip_all, fields(dev = %self.device))]
    fn drop(&mut self) {
        if let Err(err) = bluez::notify_stop(&self.connection) {
            warn!(%err, "Failed to unsubscribe from channel notifications");
        }
    }
}

impl Display for BleChannel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.device.fmt(f)
    }
}

#[async_trait]
impl<'a> Channel for BleChannel<'a> {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(self.revision.into())
    }

    async fn status(&self) -> ChannelStatus {
        self.status
    }

    async fn close(&mut self) {
        let _x = self.device;
        todo!()
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error> {
        debug!({rev = ?self.revision}, "Sending APDU request");
        trace!(?request);

        let request_apdu_packet = request.raw_long().or(Err(TransportError::InvalidFraming))?;
        let request_frame = BleFrame::new(BleCommand::Msg, &request_apdu_packet);
        bluez::frame_send(&self.connection, &request_frame, timeout)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error> {
        let response_frame = bluez::frame_recv(&self.connection, timeout)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
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

        debug!("Received APDU response");
        trace!(?response_apdu);
        Ok(response_apdu)
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        timeout: std::time::Duration,
    ) -> Result<(), Error> {
        debug!("Sending CBOR request");
        trace!(?request);

        let cbor_request = request.raw_long().or(Err(TransportError::InvalidFraming))?;
        let request_frame = BleFrame::new(BleCommand::Msg, &cbor_request);
        bluez::frame_send(&self.connection, &request_frame, timeout)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_recv(&mut self, timeout: std::time::Duration) -> Result<CborResponse, Error> {
        let response_frame = bluez::frame_recv(&self.connection, timeout)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        match response_frame.cmd {
            BleCommand::Error => return Err(Error::Transport(TransportError::InvalidFraming)), // Encapsulation layer error
            BleCommand::Cancel => return Err(Error::Ctap(CtapError::KeepAliveCancel)),
            BleCommand::Keepalive | BleCommand::Ping => return Err(Error::Ctap(CtapError::Other)), // Unexpected
            BleCommand::Msg => {}
        }
        let cbor_response_packet = &response_frame.data;
        let cbor_response: CborResponse = cbor_response_packet
            .try_into()
            .or(Err(TransportError::InvalidFraming))?;

        debug!("Received CBOR response");
        trace!(?cbor_response);
        Ok(cbor_response)
    }
}

impl Ctap2AuthTokenStore for BleChannel<'_> {
    fn store_uv_auth_token(
        &mut self,
        identifier: Ctap2AuthTokenIdentifier,
        pin_uv_auth_token: &[u8],
    ) {
        self.auth_token_storage = Some((identifier, pin_uv_auth_token.to_vec()));
    }

    fn get_uv_auth_token(&self, identifier: &Ctap2AuthTokenIdentifier) -> Option<&[u8]> {
        if let Some((id, token)) = &self.auth_token_storage {
            if id.is_satisfied_by(identifier) {
                return Some(token);
            }
        }
        None
    }

    fn clear_uv_auth_token_store(&mut self) {
        self.auth_token_storage = None;
    }
}
