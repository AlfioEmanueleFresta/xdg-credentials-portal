use core::error;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::FusedStream;
use futures::{SinkExt, StreamExt};
use snow::TransportState;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, instrument, trace, warn};
use tungstenite::protocol::Message;

use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::{Error, TransportError};
use crate::transport::{channel::ChannelStatus, device::SupportedProtocols, Channel};

use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

const PADDING_GRANULARITY: usize = 32;
const MAX_CBOR_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d CableQrCodeDevice<'d>),
    Known(&'d CableKnownDevice<'d>),
}

#[derive(Debug)]
pub struct CableChannel<'d> {
    pub ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub noise_state: TransportState,
    pub device: CableChannelDevice<'d>,
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
        match self.ws_stream.is_terminated() {
            true => ChannelStatus::Closed,
            false => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        if let Err(e) = self.ws_stream.close(None).await {
            warn!(?e, "Failed to close WebSocket connection");
        }
    }

    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error> {
        error!("APDU send not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error> {
        error!("APDU recv not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        debug!("Sending CBOR request");
        trace!(?request);

        let cbor_request = request.raw_long().or(Err(TransportError::InvalidFraming))?;

        if cbor_request.len() > MAX_CBOR_SIZE {
            error!(
                cbor_request_len = cbor_request.len(),
                "CBOR request too large"
            );
            return Err(Error::Transport(TransportError::InvalidFraming));
        }

        let extra_bytes = PADDING_GRANULARITY - (cbor_request.len() % PADDING_GRANULARITY);
        let padded_len = cbor_request.len() + extra_bytes;

        let mut padded_cbor_request = cbor_request.clone();
        padded_cbor_request.resize(padded_len, 0u8);
        padded_cbor_request[padded_len - 1] = extra_bytes as u8;

        let mut encrypted_cbor_request = vec![0u8; MAX_CBOR_SIZE];
        match self
            .noise_state
            .write_message(&padded_cbor_request, &mut encrypted_cbor_request)
        {
            Ok(size) => {
                encrypted_cbor_request.resize(size, 0u8);
            }
            Err(e) => {
                error!(?e, "Failed to encrypt CBOR request");
                return Err(Error::Transport(TransportError::ConnectionFailed));
            }
        }

        if let Err(e) = self.ws_stream.send(encrypted_cbor_request.into()).await {
            error!(?e, "Failed to send CBOR request");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }

        Ok(())
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        loop {
            let message = match self.ws_stream.next().await {
                Some(Err(e)) => {
                    error!(?e, "Failed to read encrypted CBOR message");
                    return Err(Error::Transport(TransportError::ConnectionFailed));
                }
                None => {
                    error!("Connection was closed before encrypted CBOR response was received");
                    return Err(Error::Transport(TransportError::ConnectionFailed));
                }
                Some(Ok(message)) => {
                    debug!("Received WSS message");
                    trace!(?message);
                    message
                }
            };

            let encrypted_frame = match message {
                Message::Ping(_) | Message::Pong(_) => {
                    debug!("Received keepalive message");
                    continue;
                }
                Message::Close(close_frame) => {
                    debug!(?close_frame, "Received close frame");
                    return Err(Error::Transport(TransportError::ConnectionFailed));
                }
                Message::Binary(encrypted_frame) => {
                    debug!(
                        frame_len = encrypted_frame.len(),
                        "Received encrypted CBOR response"
                    );
                    trace!(?encrypted_frame);
                    encrypted_frame
                }
                _ => {
                    error!(?message, "Unexpected message type received");
                    return Err(Error::Transport(TransportError::ConnectionFailed));
                }
            };

            let mut decrypted_frame = vec![0u8; MAX_CBOR_SIZE];
            match self
                .noise_state
                .read_message(&encrypted_frame, &mut decrypted_frame)
            {
                Ok(size) => {
                    debug!(decrypted_frame_len = size, "Decrypted CBOR response");
                    decrypted_frame.resize(size, 0u8);
                    trace!(?decrypted_frame);
                }
                Err(e) => {
                    error!(?e, "Failed to decrypt CBOR response");
                    return Err(Error::Transport(TransportError::ConnectionFailed));
                }
            }

            let padding_len = decrypted_frame[decrypted_frame.len() - 1] as usize;
            decrypted_frame.truncate(decrypted_frame.len() - (padding_len + 1));
            trace!(
                ?decrypted_frame,
                decrypted_frame_len = decrypted_frame.len(),
                "Trimmed padding"
            );

            // TODO: Unwrap CTAP message which may include a CBOR response
            // TODO: Async handling of CTAP incoming messages, including CTAP updates
            // TODO: Handle the unsolicited GetInfo response upon connection

            let cbor_response: CborResponse = (&decrypted_frame)
                .try_into()
                .or(Err(TransportError::InvalidFraming))?;

            debug!("Received CBOR response");
            trace!(?cbor_response);
            return Ok(cbor_response);
        }
    }
}
