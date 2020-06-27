use std::io::{Error as IOError, ErrorKind as IOErrorKind};

use crate::proto::ctap1::Ctap1RegisterRequest;

const APDU_SHORT_MAX_DATA: usize = 256;

const U2F_REGISTER: u8 = 0x01;
const U2F_AUTHENTICATE: u8 = 0x02;

pub struct ApduRequest {
    ins: u8,
    p1: u8,
    p2: u8,
    data: Option<Vec<u8>>,
}

impl ApduRequest {
    pub fn new(ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: None,
        }
    }

    pub fn new_with_data(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: Some(Vec::from(data)),
        }
    }

    pub fn raw_short(&self) -> Result<Vec<u8>, IOError> {
        let mut raw: Vec<u8> = Vec::new();
        raw.push(0x00); // CLA
        raw.push(self.ins);
        raw.push(self.p1);
        raw.push(self.p2);

        if let Some(data) = &self.data {
            if data.len() > APDU_SHORT_MAX_DATA {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!(
                        "Unable to serialize {} bytes of data in APDU short form.",
                        data.len()
                    ),
                ));
            } else if data.len() == 0 {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    "Cannot serialize an empty payload.",
                ));
            };

            raw.push(if data.len() != APDU_SHORT_MAX_DATA {
                data.len() as u8
            } else {
                0
            });
            raw.extend(data);
        }
        Ok(raw)
    }
}

impl From<Ctap1RegisterRequest> for ApduRequest {
    fn from(request: Ctap1RegisterRequest) -> Self {
        let mut data = Vec::from(request.challenge);
        data.extend(request.app_id.as_bytes());
        Self::new_with_data(U2F_REGISTER, 0x00, 0x00, &data)
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap1::apdu::ApduRequest;

    #[test]
    fn apdu_raw_short_no_data() {
        let apdu = ApduRequest::new(0x01, 0x02, 0x03);
        assert_eq!(apdu.raw_short().unwrap(), [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn apdu_raw_short_with_data() {
        let data = &[0xAA, 0xBB, 0xCC];
        let apdu = ApduRequest::new_with_data(0x03, 0x02, 0x01, data);
        assert_eq!(
            apdu.raw_short().unwrap(),
            [0x00, 0x03, 0x02, 0x01, 0x03, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn apdu_raw_short_with_max_len_data() {
        let data: Vec<u8> = vec![0xF1; 256];
        let apdu = ApduRequest::new_with_data(0x0A, 0x0B, 0x0C, &data);
        let serialized = apdu.raw_short().unwrap();
        assert_eq!(&serialized[0..5], &[0x00, 0x0A, 0x0B, 0x0C, 0x00]);
        assert_eq!(&serialized[5..261], data.as_slice());
    }
}
