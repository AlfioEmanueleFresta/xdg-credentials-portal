use byteorder::{BigEndian, ReadBytesExt};
use std::convert::TryFrom;
use std::io::{Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind};

#[derive(Debug, PartialEq)]
pub struct ApduResponse {
    pub data: Option<Vec<u8>>,
    sw1: u8,
    sw2: u8,
}

impl ApduResponse {
    fn status(&self) -> u16 {
        let mut cursor = IOCursor::new(vec![self.sw1, self.sw2]);
        cursor.read_u16::<BigEndian>().unwrap() as u16
    }
}

impl TryFrom<&Vec<u8>> for ApduResponse {
    type Error = IOError;
    fn try_from(packet: &Vec<u8>) -> Result<Self, Self::Error> {
        if packet.len() < 2 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                "Apdu response packets must contain at least 2 bytes.",
            ));
        }

        let data = if packet.len() > 2 {
            Some(Vec::from(&packet[0..packet.len() - 2]))
        } else {
            None
        };
        let (sw1, sw2) = (packet[packet.len() - 2], packet[packet.len() - 1]);

        Ok(Self { data, sw1, sw2 })
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap1::apdu::ApduResponse;
    use std::convert::TryInto;
    use std::io::{Error as IOError, ErrorKind as IOErrorKind};

    #[test]
    fn apdu_from_status_only_packet() {
        let packet: &Vec<u8> = &vec![0xAA, 0xBB];
        let apdu: ApduResponse = packet.try_into().unwrap();
        assert_eq!(apdu.status(), 0xAABB);
        assert_eq!(apdu.data, None);
    }

    #[test]
    fn apdu_from_full_packet() {
        let packet: &Vec<u8> = &vec![0x01, 0x02, 0x03, 0xAA, 0xBB];
        let apdu: ApduResponse = packet.try_into().unwrap();
        assert_eq!(apdu.status(), 0xAABB);
        assert_eq!(apdu.data, Some(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn apdu_from_invalid_packet() {
        let packet: &Vec<u8> = &vec![0xB0];
        let apdu: Result<ApduResponse, IOErrorKind> =
            packet.try_into().map_err(|ioe: IOError| ioe.kind());
        assert_eq!(apdu, Err(IOErrorKind::InvalidData));
    }
}
