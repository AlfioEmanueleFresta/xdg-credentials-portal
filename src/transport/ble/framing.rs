use super::byteorder::{BigEndian, WriteBytesExt};
use crate::transport::ble::Ctap2BleCommand;

use std::cmp::min;
use std::error::Error as StdError;
use std::io::{Error as IOError, ErrorKind as IOErrorKind};

const MAX_FRAGMENT_LENGTH: usize = 0xFF_FF;

type BleFragment = Vec<u8>;

struct BleFrame {
    max_fragment_length: usize,
    data: Vec<u8>,
}

impl BleFrame {
    pub fn new(max_fragment_length: usize, data: &[u8]) -> Self {
        Self {
            max_fragment_length: min(max_fragment_length, MAX_FRAGMENT_LENGTH),
            data: Vec::from(data),
        }
    }

    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-framing-fragmentation
    pub fn fragments(&self) -> Result<Vec<Vec<u8>>, IOError> {
        if self.max_fragment_length < 4 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                format!(
                    "Desired maximum fragment length is unsupported: {}",
                    self.max_fragment_length
                ),
            ));
        }

        let length = self.data.len() as u16;
        let mut message = self.data.as_slice().into_iter().cloned().peekable();
        let mut fragments = vec![];

        // Initial fragment
        let mut fragment = vec![Ctap2BleCommand::Msg as u8];
        fragment.write_u16::<BigEndian>(length)?;
        let mut chunk: Vec<u8> = message
            .by_ref()
            .take(self.max_fragment_length - 3)
            .collect();
        fragment.append(&mut chunk);
        fragments.push(fragment);

        // Sequence fragments
        let mut seq: u8 = 0;
        while message.peek().is_some() {
            let mut fragment = vec![seq];
            let mut chunk: Vec<u8> = message
                .by_ref()
                .take(self.max_fragment_length - 1)
                .collect();
            fragment.append(&mut chunk);
            fragments.push(fragment);
            seq += 1;
        }

        Ok(fragments)
    }
}
