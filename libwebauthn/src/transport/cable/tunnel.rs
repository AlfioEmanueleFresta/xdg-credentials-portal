use futures::{Sink, SinkExt, StreamExt};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::FieldBytes;
use p256::{NonZeroScalar, SecretKey};
use sha2::{Digest, Sha256};
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, WebSocketStream};
use tracing::{debug, error, trace};

use super::channel::{CableChannel, CableChannelDevice};
use super::qr_code_device::CableQrCodeDevice;
use crate::transport::error::Error;
use crate::webauthn::TransportError;

pub(crate) const KNOWN_TUNNEL_DOMAINS: &[&str] = &["cable.ua5v.com", "cable.auth.com"];
const SHA_INPUT: &[u8] = b"caBLEv2 tunnel server domain";
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const TLDS: &[&str] = &[".com", ".org", ".net", ".info"];
const P256_X962_LENGTH: usize = 65;

// const CABLE_PROLOGUE_STATE_ASSISTED = [0 as u8];
const CABLE_PROLOGUE_QR_INITIATED: &[u8] = &[1 as u8];

enum TransactionType {
    StateAssisted,
    QRInitiated,
}

pub fn decode_tunnel_server_domain(encoded: u16) -> Option<String> {
    if encoded < 256 {
        if encoded as usize >= KNOWN_TUNNEL_DOMAINS.len() {
            return None;
        }
        return Some(KNOWN_TUNNEL_DOMAINS[encoded as usize].to_string());
    }

    let mut sha_input = SHA_INPUT.to_vec();
    sha_input.push(encoded as u8);
    sha_input.push((encoded >> 8) as u8);
    sha_input.push(0);
    let mut hasher = Sha256::default();
    hasher.update(&sha_input);
    let digest = hasher.finalize();

    let mut v = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let tld_index = v & 3;
    v >>= 2;

    let mut ret = String::from("cable.");
    while v != 0 {
        ret.push(BASE32_CHARS[(v & 31) as usize] as char);
        v >>= 5;
    }

    ret.push_str(TLDS[tld_index as usize]);
    Some(ret)
}

pub async fn connect<'d>(
    device: &'d CableQrCodeDevice<'d>,
    tunnel_domain: &str,
    routing_id: &str,
    tunnel_id: &str,
    psk: &[u8; 32],
    private_key: &NonZeroScalar,
) -> Result<CableChannel<'d>, Error> {
    let connect_url = format!(
        "wss://{}/cable/connect/{}/{}",
        tunnel_domain, routing_id, tunnel_id
    );
    debug!(?connect_url, "Connecting to tunnel server");
    // TODO: set protocol: fido.cable

    let (mut ws_stream, response) = match connect_async(&connect_url).await {
        Ok((ws_stream, response)) => (ws_stream, response),
        Err(e) => {
            error!(?e, "Failed to connect to tunnel server");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };
    debug!(?response, "Connected to tunnel server");

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!(?response, "Failed to switch to websocket protocol");
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }
    debug!("Tunnel server returned success");

    let noise_state = do_handshake(
        &mut ws_stream,
        psk,
        private_key,
        TransactionType::QRInitiated,
    )
    .await?;
    // After this, the handshake should be complete and you can start sending/receiving encrypted messages.
    // ...

    Ok(CableChannel {
        ws_stream,
        noise_state,
        device: CableChannelDevice::QrCode(device),
    })
}

async fn do_handshake<T: AsyncRead + AsyncWrite + Unpin>(
    ws_stream: &mut WebSocketStream<T>,
    psk: &[u8; 32],
    private_key: &NonZeroScalar,
    transaction_type: TransactionType,
) -> Result<TransportState, Error> {
    let local_private_key = private_key.to_bytes();

    let noise_builder = match transaction_type {
        TransactionType::QRInitiated => Builder::new("Noise_KNpsk0_P256_AESGCM_SHA256".parse()?)
            .prologue(CABLE_PROLOGUE_QR_INITIATED)?
            .local_private_key(&local_private_key.as_slice())?
            .psk(0, psk)?,
        TransactionType::StateAssisted => {
            // Builder::new("Noise_NKpsk0_P256_AESGCM_SHA256".parse().unwrap())
            todo!()
        }
    };

    // Build the Noise handshake as the initiator
    let mut noise_handshake = match noise_builder.build_initiator() {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(?e, "Failed to build Noise handshake");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    let mut initial_msg_buffer = vec![0u8; 1024];
    let initial_msg_len = match noise_handshake.write_message(&[], &mut initial_msg_buffer) {
        Ok(msg_len) => msg_len,
        Err(e) => {
            error!(?e, "Failed to write initial handshake message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };
    trace!(
        { handshake = ?initial_msg_buffer[..initial_msg_len] },
        "Sending initial handshake message"
    );

    if let Err(e) = ws_stream
        .send(Message::Binary(
            initial_msg_buffer[..initial_msg_len].into(),
        ))
        .await
    {
        error!(?e, "Failed to send initial handshake message");
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }
    debug!("Sent initial handshake message");

    // Read the response from the server and process it
    let response = match ws_stream.next().await {
        Some(Ok(Message::Binary(response))) => {
            debug!(response_len = response.len(), "Received handshake response");
            trace!(?response);
            response
        }

        Some(Ok(msg)) => {
            error!(?msg, "Unexpected message type received");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
        Some(Err(e)) => {
            error!(?e, "Failed to read handshake response");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
        None => {
            error!("Connection was closed before handshake was complete");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    /* output:
       keys trafficKeys,
       handshakeHash [32]byte) {
    */
    if response.len() < P256_X962_LENGTH {
        error!(
            { len = response.len() },
            "Peer handshake message is too short"
        );
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }

    let mut payload = [0u8; 1024];
    let payload_len = noise_handshake
        .read_message(&response, &mut payload)
        .unwrap();

    debug!(
        { handshake = ?payload[..payload_len] },
        "Received handshake response"
    );

    if !noise_handshake.is_handshake_finished() {
        error!("Handshake did not complete");
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }

    Ok(noise_handshake.into_transport_mode()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_tunnel_server_domain_known() {
        assert_eq!(
            decode_tunnel_server_domain(0).unwrap(),
            "cable.ua5v.com".to_string()
        );
        assert_eq!(
            decode_tunnel_server_domain(1).unwrap(),
            "cable.auth.com".to_string()
        );
    }

    // TODO: test the non-known case
}
