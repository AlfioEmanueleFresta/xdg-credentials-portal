extern crate bitflags;
extern crate log;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::warn;

use std::io::{Cursor as IOCursor, Seek, SeekFrom};

use super::device::FidoDevice;
use super::framing::{HidCommand, HidMessage, HidMessageParser, HidMessageParserState};
use super::hid_transact;
use crate::transport::error::{Error, TransportError};

const INIT_NONCE_LEN: usize = 8;
const INIT_PAYLOAD_LEN: usize = 17;

bitflags! {
    pub struct Caps: u8 {
        const WINK = 0x01;
        const CBOR = 0x04;
        const NO_MSG = 0x08;
    }
}

#[derive(Debug, Clone)]
pub struct InitResponse {
    pub cid: u32,
    pub protocol_version: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub caps: Caps,
}

pub async fn init(device: &FidoDevice) -> Result<InitResponse, Error> {
    let nonce = vec![0x42, 0x41, 0x62, 0xA3, 0x04, 0x04, 0xBB, 0xFF]; // FIXME
    let request = HidMessage::broadcast(HidCommand::Init, &nonce);
    let response = hid_transact(device, &request).await?;

    if response.cmd != HidCommand::Init {
        warn!("Invalid response to INIT request: {:?}", response.cmd);
        return Err(Error::Transport(TransportError::InvalidEndpoint));
    }

    if response.payload.len() < INIT_PAYLOAD_LEN {
        warn!(
            "INIT payload is too small ({} bytes)",
            response.payload.len()
        );
        return Err(Error::Transport(TransportError::InvalidEndpoint));
    }

    if response.payload[0..INIT_NONCE_LEN] != nonce[0..INIT_NONCE_LEN] {
        warn!("INIT nonce mismatch. Terminating.");
        return Err(Error::Transport(TransportError::InvalidEndpoint));
    }

    let mut cursor = IOCursor::new(response.payload);
    cursor.seek(SeekFrom::Start(8)).unwrap();

    Ok(InitResponse {
        cid: cursor.read_u32::<BigEndian>().unwrap(),
        protocol_version: cursor.read_u8().unwrap(),
        version_major: cursor.read_u8().unwrap(),
        version_minor: cursor.read_u8().unwrap(),
        version_build: cursor.read_u8().unwrap(),
        caps: Caps::from_bits_truncate(cursor.read_u8().unwrap()),
    })
}
