extern crate num_enum;
extern crate serde;
extern crate serde_cbor;
extern crate serde_indexed;
extern crate serde_repr;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::ops::webauthn::MakeCredentialRequest;

use std::{collections::HashMap, time::Duration};

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Ctap2CommandCode {
    AuthenticatorMakeCredential = 0x01,
    AuthenticatorGetAssertion = 0x02,
    AuthenticatorGetInfo = 0x04,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
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
    pub name: String,

    // TODO(afresta): Validation as per https://www.w3.org/TR/webauthn/#sctn-user-credential-params
    #[serde(rename = "displayName")]
    pub display_name: String,
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn new(id: &[u8], name: &str, display_name: &str) -> Self {
        Self {
            id: ByteBuf::from(id),
            name: String::from(name),
            display_name: String::from(display_name),
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ctap2CredentialType {
    #[serde(rename = "type")]
    pub public_key_type: Ctap2PublicKeyCredentialType,

    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ctap2MakeCredentialOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,
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
#[derive(Debug, Clone, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2MakeCredentialRequest {
    /// clientDataHash (0x01)
    pub hash: ByteBuf,

    /// rp (0x02)
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,

    /// user (0x03)
    pub user: Ctap2PublicKeyCredentialUserEntity,

    /// pubKeyCredParams (0x04)
    pub algorithms: Vec<Ctap2CredentialType>,

    /// excludeList (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,

    /// extensions (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions_cbor: Option<Vec<u8>>,

    /// options (0x07)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Ctap2MakeCredentialOptions>,

    /// pinUvAuthParam (0x08)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_param: Option<Vec<u8>>,

    /// pinUvAuthProtocol (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,

    /// enterpriseAttestation (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<u32>,
}

impl From<&MakeCredentialRequest> for Ctap2MakeCredentialRequest {
    fn from(op: &MakeCredentialRequest) -> Ctap2MakeCredentialRequest {
        Ctap2MakeCredentialRequest {
            hash: ByteBuf::from(op.hash.clone()),
            relying_party: op.relying_party.clone(),
            user: op.user.clone(),
            algorithms: op.algorithms.clone(),
            exclude: op.exclude.clone(),
            extensions_cbor: if op.extensions_cbor.is_empty() {
                None
            } else {
                Some(op.extensions_cbor.clone())
            },
            options: Some(Ctap2MakeCredentialOptions {
                rk: if op.require_resident_key {
                    Some(true)
                } else {
                    None
                },
                up: if op.require_user_presence {
                    Some(true)
                } else {
                    None
                },
                uv: if op.require_user_verification {
                    Some(true)
                } else {
                    None
                },
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        }
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

#[derive(Debug)]
pub struct Ctap2GetAssertionResponse {
    pub credential_id: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetInfoResponse {
    /// versions (0x01)
    pub versions: Vec<String>,

    /// extensions (0x02)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,

    /// aaguid (0x03)
    pub aaguid: ByteBuf,

    /// options (0x04)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, bool>>,

    /// maxMsgSize (0x05)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msg_size: Option<u32>,

    /// pinUvAuthProtocols (0x06)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_protos: Option<Vec<u32>>,

    /// maxCredentialCountInList (0x07)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_credential_count: Option<u32>,

    /// maxCredentialIdLength (0x08)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_credential_id_length: Option<u32>,

    /// transports (0x09)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,

    /// algorithms (0x0A)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<Ctap2CredentialType>>,

    /// maxSerializedLargeBlobArray (0x0B)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_blob_array: Option<u32>,

    /// forcePINChange (0x0C)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_pin_change: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pin_length: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cred_blob_length: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rpids_for_setminpinlength: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_platform_uv_attempts: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_modality: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifications: Option<HashMap<String, u32>>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_discoverable_creds: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_proto_config_cmds: Option<Vec<u32>>,
}
