extern crate serde_cbor;

use serde_cbor::ser::to_vec;

use crate::proto::ctap2::model::Ctap2CommandCode;
use crate::proto::ctap2::model::Ctap2MakeCredentialRequest;

#[derive(Debug)]
pub struct CborRequest {
    pub command: Ctap2CommandCode,
    pub encoded_data: Vec<u8>,
}

impl CborRequest {
    pub fn ctap_hid_data(&self) -> Vec<u8> {
        let mut data = vec![self.command as u8];
        data.extend(&self.encoded_data);
        data
    }
}

impl From<&Ctap2MakeCredentialRequest> for CborRequest {
    fn from(request: &Ctap2MakeCredentialRequest) -> CborRequest {
        CborRequest {
            command: Ctap2CommandCode::AuthenticatorMakeCredential,
            encoded_data: to_vec(request).unwrap(),
        }
    }
}
