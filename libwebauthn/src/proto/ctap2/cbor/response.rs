use crate::proto::error::CtapError;

use std::convert::{TryFrom, TryInto};
use std::io::{Error as IOError, ErrorKind as IOErrorKind};
use tracing::error;

#[derive(Debug)]
pub struct CborResponse {
    pub status_code: CtapError,
    pub data: Option<Vec<u8>>,
}

impl TryFrom<&Vec<u8>> for CborResponse {
    type Error = IOError;
    fn try_from(packet: &Vec<u8>) -> Result<Self, Self::Error> {
        if packet.len() < 1 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                "Cbor response packets must contain at least 1 byte.",
            ));
        }

        let Ok(status_code) = packet[0].try_into() else {
            error!({ code = ?packet[0] }, "Invalid CTAP error code");
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                format!("Invalid CTAP error code: {:x}", packet[0]),
            ));
        };

        let data = if packet.len() > 1 {
            Some(Vec::from(&packet[1..]))
        } else {
            None
        };
        Ok(CborResponse { status_code, data })
    }
}
