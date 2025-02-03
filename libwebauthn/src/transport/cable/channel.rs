use std::fmt::{Display, Formatter};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task;
use tracing::error;

use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::{Error, TransportError};
use crate::transport::{
    channel::ChannelStatus, device::SupportedProtocols, Channel, Ctap2AuthTokenPermission,
    Ctap2AuthTokenStore,
};

use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d CableQrCodeDevice<'d>),
    Known(&'d CableKnownDevice<'d>),
}

#[derive(Debug)]
pub struct CableChannel<'d> {
    /// The WebSocket stream used for communication.
    // pub(crate) ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,

    /// The noise state used for encryption over the WebSocket stream.
    // pub(crate) noise_state: TransportState,

    /// The device that this channel is connected to.
    pub device: CableChannelDevice<'d>,

    pub(crate) handle_connection: task::JoinHandle<()>,
    pub(crate) cbor_sender: mpsc::Sender<CborRequest>,
    pub(crate) cbor_receiver: mpsc::Receiver<CborResponse>,
}

impl Display for CableChannel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}

#[async_trait]
impl<'d> Channel for CableChannel<'d> {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(SupportedProtocols::fido2_only())
    }

    async fn status(&self) -> ChannelStatus {
        match self.handle_connection.is_finished() {
            true => ChannelStatus::Closed,
            false => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        // TODO Send CableTunnelMessageType#Shutdown and drop the connection
    }

    async fn apdu_send(&self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        error!("APDU send not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        error!("APDU recv not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn cbor_send(&mut self, request: &CborRequest, _timeout: Duration) -> Result<(), Error> {
        self.cbor_sender
            .send(request.clone())
            .await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))
    }

    async fn cbor_recv(&mut self, _timeout: Duration) -> Result<CborResponse, Error> {
        self.cbor_receiver
            .recv()
            .await
            .ok_or(Error::Transport(TransportError::TransportUnavailable))
    }
}

impl<'d> Ctap2AuthTokenStore for CableChannel<'d> {
    fn store_uv_auth_token(
        &mut self,
        _permission: Ctap2AuthTokenPermission,
        _pin_uv_auth_token: &[u8],
    ) {
    }

    fn get_uv_auth_token(&self, _requested_permission: &Ctap2AuthTokenPermission) -> Option<&[u8]> {
        None
    }

    fn clear_uv_auth_token_store(&mut self) {}
}
