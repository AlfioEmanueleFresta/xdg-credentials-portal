extern crate serde;
extern crate serde_cbor;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_cbor::ser::to_vec;
use serde_cbor::Result as CBORResult;
use std::time::Duration;

#[derive(Debug)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
}

#[derive(Debug)]
pub struct Ctap2PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    // TODO(afresta): Validation as per https://www.w3.org/TR/webauthn/#sctn-user-credential-params
    pub display_name: String,
}

#[derive(Debug)]
pub enum Ctap2PublicKeyCredentialType {
    PublicKey,
}

#[derive(Debug)]
pub enum Ctap2Transport {
    BLE,
    NFC,
    USB,
    INTERNAL,
}

#[derive(Debug)]
pub struct Ctap2PublicKeyCredentialDescriptor {
    pub r#type: Ctap2PublicKeyCredentialType,
    pub id: Vec<u8>,
    pub transports: Option<Vec<Ctap2Transport>>,
}

#[repr(i32)]
#[derive(Debug, FromPrimitive)]
pub enum Ctap2COSEAlgorithmIdentifier {
    ES256 = -7,
}

#[derive(Debug)]
pub struct Ctap2CredentialType {
    pub public_key_type: Ctap2PublicKeyCredentialType,
    pub algorithm: Ctap2COSEAlgorithmIdentifier,
}

#[derive(Debug)]
pub enum Ctap2Operation {
    MakeCredential(Ctap2MakeCredentialRequest),
    GetAssertion(Ctap2GetAssertionRequest),
    // GetNextAssertion(Ctap2GetNextAssertinRequest),
    GetInfo,
    // ClientPin(Ctap2ClientPinRequest),
    Reset,
}

impl Ctap2Operation {
    pub fn command_value(&self) -> u8 {
        match self {
            Ctap2Operation::MakeCredential(_) => 0x01,
            Ctap2Operation::GetAssertion(_) => 0x02,
            // Ctap2Operation::GetNextAssertion => 0x08,
            Ctap2Operation::GetInfo => 0x04,
            // Ctap2Operation::ClientPin(_) => 0x06,
            Ctap2Operation::Reset => 0x07,
        }
    }

    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands
    pub fn serialize(&self) -> CBORResult<Vec<u8>> {
        let mut command = vec![self.command_value()];
        match self {
            Ctap2Operation::MakeCredential(request) => {
                let mut payload = to_vec(request)?;
                command.append(&mut payload);
            }
            Ctap2Operation::GetAssertion(request) => {
                let mut payload = to_vec(request)?;
                command.append(&mut payload);
            }
            // Ctap2Operation::GetNextAssertion(_) => 0x08,
            Ctap2Operation::GetInfo => {}
            // Ctap2Operation::ClientPin(_) => 0x06,
            Ctap2Operation::Reset => {}
        };
        Ok(command)
    }
}

pub type Ctap2AttestationStatement = Option<Ctap2AttestationStatementSome>;

#[derive(Debug)]
pub enum Ctap2AttestationStatementSome {
    Packed(Vec<u8>),
    TPM(Vec<u8>),
    AndroidKey(Vec<u8>),
    FidoU2F(Vec<u8>),
}

// https://www.w3.org/TR/webauthn/#authenticatormakecredential
#[derive(Debug)]
pub struct Ctap2MakeCredentialRequest {
    pub origin: String,
    pub hash: Vec<u8>,
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub require_resident_key: bool,
    pub require_user_presence: bool,
    pub require_user_verification: bool,
    pub algorithms: Vec<Ctap2CredentialType>,
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    pub extensions_cbor: Vec<u8>,
    pub timeout: Duration,
}

impl Serialize for Ctap2MakeCredentialRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let map = serializer.serialize_map(None)?;
        // TODO
        map.end()
    }
}

#[derive(Debug)]
pub struct Ctap2MakeCredentialResponse {
    pub authenticator_data: Vec<u8>,
    pub attestation_statement: Ctap2AttestationStatement,
}

// https://www.w3.org/TR/webauthn/#op-get-assertion
#[derive(Debug)]
pub struct Ctap2GetAssertionRequest {
    pub relying_party_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    pub require_user_presence: bool,
    pub require_user_verification: bool,
    pub extensions_cbor: Vec<u8>,
    pub timeout: Duration,
}

impl Serialize for Ctap2GetAssertionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let map = serializer.serialize_map(None)?;
        // TODO
        map.end()
    }
}

#[derive(Debug)]
pub struct Ctap2GetAssertionResponse {
    pub credential_id: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Option<Vec<u8>>,
}
