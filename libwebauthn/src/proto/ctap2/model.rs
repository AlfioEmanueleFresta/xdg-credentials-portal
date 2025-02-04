use crate::pin::PinUvAuthProtocol;
use crate::proto::ctap1::Ctap1Transport;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

mod get_info;
pub use get_info::Ctap2GetInfoResponse;
mod bio_enrollment;
pub use bio_enrollment::{
    Ctap2BioEnrollmentFingerprintKind, Ctap2BioEnrollmentModality, Ctap2BioEnrollmentRequest,
    Ctap2BioEnrollmentResponse, Ctap2BioEnrollmentTemplateId, Ctap2LastEnrollmentSampleStatus,
};
mod authenticator_config;
pub use authenticator_config::{
    Ctap2AuthenticatorConfigCommand, Ctap2AuthenticatorConfigParams,
    Ctap2AuthenticatorConfigRequest,
};
mod client_pin;
pub use client_pin::{
    Ctap2AuthTokenPermissionRole, Ctap2ClientPinRequest, Ctap2ClientPinResponse,
    Ctap2PinUvAuthProtocol,
};
mod make_credential;
pub use make_credential::{
    Ctap2MakeCredentialOptions, Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse,
};
mod get_assertion;
pub use get_assertion::{
    Ctap2AttestationStatement, Ctap2GetAssertionRequest, Ctap2GetAssertionResponse,
    FidoU2fAttestationStmt,
};

// 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid
const AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET: usize = 53;

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Ctap2CommandCode {
    AuthenticatorMakeCredential = 0x01,
    AuthenticatorGetAssertion = 0x02,
    AuthenticatorGetInfo = 0x04,
    AuthenticatorClientPin = 0x06,
    AuthenticatorGetNextAssertion = 0x08,
    AuthenticatorBioEnrollment = 0x09,
    AuthenticatorSelection = 0x0B,
    AuthenticatorConfig = 0x0D,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}

impl Ctap2PublicKeyCredentialRpEntity {
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self {
            id: String::from(".dummy"),
            name: String::from(".dummy"),
        }
    }
}

impl Ctap2PublicKeyCredentialRpEntity {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: String::from(id),
            name: String::from(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialUserEntity {
    pub id: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    // TODO(afresta): Validation as per https://www.w3.org/TR/webauthn/#sctn-user-credential-params
    #[serde(rename = "displayName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Ctap2PublicKeyCredentialUserEntity {
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self {
            id: ByteBuf::from([1]),
            name: Some(String::from("dummy")),
            display_name: None,
        }
    }
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn new(id: &[u8], name: &str, display_name: &str) -> Self {
        Self {
            id: ByteBuf::from(id),
            name: Some(String::from(name)),
            display_name: Some(String::from(display_name)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Ctap2PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ctap2Transport {
    BLE,
    NFC,
    USB,
    INTERNAL,
}

impl From<&Ctap1Transport> for Ctap2Transport {
    fn from(ctap1: &Ctap1Transport) -> Ctap2Transport {
        match ctap1 {
            Ctap1Transport::BT => Ctap2Transport::BLE,
            Ctap1Transport::BLE => Ctap2Transport::BLE,
            Ctap1Transport::USB => Ctap2Transport::USB,
            Ctap1Transport::NFC => Ctap2Transport::NFC,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialDescriptor {
    pub r#type: Ctap2PublicKeyCredentialType,
    pub id: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Ctap2Transport>>,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2COSEAlgorithmIdentifier {
    ES256 = -7,
    EDDSA = -8,
    TOPT = -9,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ctap2CredentialType {
    #[serde(rename = "type")]
    pub public_key_type: Ctap2PublicKeyCredentialType,

    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,
}

impl Default for Ctap2CredentialType {
    fn default() -> Self {
        Self {
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
        }
    }
}

impl Ctap2CredentialType {
    pub fn new(
        public_key_type: Ctap2PublicKeyCredentialType,
        algorithm: Ctap2COSEAlgorithmIdentifier,
    ) -> Self {
        Self {
            public_key_type,
            algorithm,
        }
    }
}

pub trait Ctap2UserVerifiableRequest {
    fn ensure_uv_set(&mut self);
    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    );
    fn client_data_hash(&self) -> &[u8];
    fn permissions(&self) -> Ctap2AuthTokenPermissionRole;
    fn permissions_rpid(&self) -> Option<&str>;
    fn can_use_uv(&self, info: &Ctap2GetInfoResponse) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub enum Ctap2UserVerificationOperation {
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetPinUvAuthTokenUsingPinWithPermissions,
    GetPinToken,
    None,
}
