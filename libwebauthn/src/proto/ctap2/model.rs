extern crate byteorder;
extern crate cosey;
extern crate log;
extern crate num_enum;
extern crate serde;
extern crate serde_cbor;
extern crate serde_indexed;
extern crate serde_repr;

use crate::transport::error::CtapError;
use byteorder::{BigEndian, ReadBytesExt};
use cosey::P256PublicKey;
use log::warn;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Digest, Sha256};

use crate::ops::webauthn::GetAssertionRequest;
use crate::ops::webauthn::MakeCredentialRequest;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor as IOCursor;

// 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid)
const AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET: usize = 53;

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Ctap2CommandCode {
    AuthenticatorMakeCredential = 0x01,
    AuthenticatorGetAssertion = 0x02,
    AuthenticatorGetInfo = 0x04,
    AuthenticatorSelection = 0x0B,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}

impl Ctap2PublicKeyCredentialRpEntity {
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
    pub name: String,

    // TODO(afresta): Validation as per https://www.w3.org/TR/webauthn/#sctn-user-credential-params
    #[serde(rename = "displayName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn dummy() -> Self {
        Self {
            id: ByteBuf::from([1]),
            name: String::from("dummy"),
            display_name: None,
        }
    }
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn new(id: &[u8], name: &str, display_name: &str) -> Self {
        Self {
            id: ByteBuf::from(id),
            name: String::from(name),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialDescriptor {
    pub r#type: Ctap2PublicKeyCredentialType,
    pub id: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Ctap2Transport>>,
}

impl TryFrom<&Ctap2MakeCredentialResponse> for Ctap2PublicKeyCredentialDescriptor {
    type Error = CtapError;
    fn try_from(response: &Ctap2MakeCredentialResponse) -> Result<Self, Self::Error> {
        if response.authenticator_data.len() < AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET + 2 {
            warn!("Failed to parse credential ID: invalid authenticator data length");
            return Err(CtapError::InvalidCredential);
        }

        let mut cursor = IOCursor::new(response.authenticator_data.as_ref());
        cursor.set_position(AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET as u64);
        let len = cursor.read_u16::<BigEndian>().unwrap() as usize;
        let offset = AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET + 2;
        if response.authenticator_data.len() < offset + len {
            warn!("Failed to parse credential ID: not enough bytes");
            return Err(CtapError::InvalidCredential);
        }

        let credential_id = response.authenticator_data[offset..offset + len].to_vec();
        assert_eq!(len, credential_id.len());
        Ok(Ctap2PublicKeyCredentialDescriptor {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(credential_id),
            transports: None,
        })
    }
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

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Ctap2MakeCredentialOptions {
    #[serde(rename = "rk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,

    #[serde(rename = "uv")]
    #[serde(skip_serializing_if = "Self::skip_serializing_uv")]
    pub deprecated_require_user_verification: bool,
}

impl Ctap2MakeCredentialOptions {
    fn skip_serializing_uv(uv: &bool) -> bool {
        !uv
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Ctap2GetAssertionOptions {
    #[serde(rename = "up")]
    pub require_user_presence: bool,

    #[serde(rename = "uv")]
    #[serde(skip_serializing_if = "Self::skip_serializing_uv")]
    pub require_user_verification: bool,
}

impl Ctap2GetAssertionOptions {
    fn skip_serializing_uv(uv: &bool) -> bool {
        !uv
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackedAttestationStmt {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FidoU2fAttestationStmt {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpmAttestationStmt {
    #[serde(rename = "ver")]
    pub version: String,

    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,

    #[serde(rename = "certInfo")]
    pub certificate_info: ByteBuf,

    #[serde(rename = "pubArea")]
    pub public_area: ByteBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Ctap2AttestationStatement {
    PackedOrAndroid(PackedAttestationStmt),
    Tpm(TpmAttestationStmt),
    FidoU2F(FidoU2fAttestationStmt),
}

// https://www.w3.org/TR/webauthn/#authenticatormakecredential
#[derive(Debug, Clone, SerializeIndexed)]
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

impl Ctap2MakeCredentialRequest {
    pub fn dummy() -> Self {
        let hasher = Sha256::default();
        let hash = hasher.finalize().to_vec();
        Self {
            hash: ByteBuf::from(hash),
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions_cbor: None,
            options: None,
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        }
    }
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
                require_resident_key: if op.require_resident_key {
                    Some(true)
                } else {
                    None
                },
                deprecated_require_user_verification: false,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        }
    }
}

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2MakeCredentialResponse {
    pub format: String,
    pub authenticator_data: ByteBuf,
    pub attestation_statement: Ctap2AttestationStatement,
}

// https://www.w3.org/TR/webauthn/#op-get-assertion
#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetAssertionRequest {
    /// rpId (0x01)
    pub relying_party_id: String,

    /// clientDataHash (0x02)
    pub client_data_hash: ByteBuf,

    /// allowList (0x03)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,

    /// extensions (0x04)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions_cbor: Option<Vec<u8>>,

    /// options (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Ctap2GetAssertionOptions>,

    /// pinUvAuthParam (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x07)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,
}

impl From<&GetAssertionRequest> for Ctap2GetAssertionRequest {
    fn from(op: &GetAssertionRequest) -> Self {
        Self {
            relying_party_id: op.relying_party_id.clone(),
            client_data_hash: ByteBuf::from(op.hash.clone()),
            allow: op.allow.clone(),
            extensions_cbor: op.extensions_cbor.clone(),
            options: Some(Ctap2GetAssertionOptions {
                require_user_presence: op.require_user_presence,
                require_user_verification: op.require_user_verification,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
        }
    }
}

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetAssertionResponse {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,
    pub authenticator_data: ByteBuf,
    pub signature: ByteBuf,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_count: Option<u32>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_selected: Option<bool>,
}

#[derive(Debug, Clone, DeserializeIndexed)]
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

impl Ctap2GetInfoResponse {
    pub fn option_enabled(&self, name: &str) -> bool {
        if self.options.is_none() {
            return false;
        }
        let options = self.options.as_ref().unwrap();
        options.get(name) == Some(&true)
    }

    pub fn supports_fido_2_1(&self) -> bool {
        self.versions.iter().any(|v| v == "FIDO_2_1")
    }
}

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2ClientPinRequest {
    ///pinUvAuthProtocol (0x01)
    pub protocol: Ctap2PinUvAuthProtocol,

    /// subCommand (0x02)
    pub command: Ctap2PinUvAuthProtocolCommand,

    /// keyAgreement (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<P256PublicKey>,

    /// pinUvAuthParam (0x04):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_auth_param: Option<ByteBuf>,

    /// newPinEnc (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pin_encrypted: Option<ByteBuf>,

    /// pinHashEnc (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash_encrypted: Option<ByteBuf>,

    /// permissions (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u32>,

    /// permissions RPID (0x10)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_rpid: Option<String>,
}

bitflags! {
    pub struct ClientPinRequestPermissions: u32 {
        const MAKE_CREDENTIAL = 0x01;
        const GET_ASSERTION = 0x02;
        const CREDENTIAL_MANAGEMENT = 0x04;
        const BIO_ENROLLMENT = 0x08;
        const LARGE_BLOB_WRITE = 0x10;
        const AUTHENTICATOR_CONFIGURATION = 0x20;
    }
}

#[repr(u32)]
#[derive(Debug, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2PinUvAuthProtocol {
    One = 1,
    Two = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2PinUvAuthProtocolCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissinos = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2ClientPinResponse {
    /// keyAgreement (0x01)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<P256PublicKey>,

    /// pinUvAuthToken (0x02):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_auth_param: Option<ByteBuf>,

    /// pinRetries (0x03):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_retries: Option<u32>,

    /// pinRetries (0x04):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<bool>,

    /// uvRetries (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_retries: Option<u32>,
}
