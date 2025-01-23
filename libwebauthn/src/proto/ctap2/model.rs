use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor as IOCursor;

use byteorder::{BigEndian, ReadBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use serde_derive::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tracing::debug;
use tracing::warn;

use ctap_types::cose::PublicKey;

use crate::ops::webauthn::GetAssertionRequest;
use crate::ops::webauthn::MakeCredentialRequest;
use crate::pin::PinUvAuthProtocol;
use crate::proto::ctap1::Ctap1Transport;
use crate::transport::error::CtapError;

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

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Ctap2MakeCredentialOptions {
    #[serde(rename = "rk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,

    #[serde(rename = "uv")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_require_user_verification: Option<bool>,
}

impl Default for Ctap2MakeCredentialOptions {
    fn default() -> Self {
        Self {
            require_resident_key: None,
            deprecated_require_user_verification: None,
        }
    }
}

impl Ctap2MakeCredentialOptions {
    pub fn skip_serializing(&self) -> bool {
        self.require_resident_key.is_none() && self.deprecated_require_user_verification.is_none()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct Ctap2GetAssertionOptions {
    #[serde(rename = "up")]
    /// True for all requests; False for pre-flight only.
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

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
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
pub struct AppleAnonymousAttestationStmt {
    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Ctap2AttestationStatement {
    PackedOrAndroid(PackedAttestationStmt),
    Tpm(TpmAttestationStmt),
    FidoU2F(FidoU2fAttestationStmt),
    AppleAnonymous(AppleAnonymousAttestationStmt),
    None(BTreeMap<Value, Value>),
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
    #[serde(skip_serializing_if = "Self::skip_serializing_options")]
    pub options: Option<Ctap2MakeCredentialOptions>,

    /// pinUvAuthParam (0x08)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,

    /// enterpriseAttestation (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<u32>,
}

impl Ctap2MakeCredentialRequest {
    pub fn skip_serializing_options(options: &Option<Ctap2MakeCredentialOptions>) -> bool {
        options.map_or(true, |options| options.skip_serializing())
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
                deprecated_require_user_verification: None,
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_output: Option<BTreeMap<Value, Value>>,
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
                require_user_presence: true,
                require_user_verification: op.user_verification.is_required(),
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteBuf>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_outputs: Option<BTreeMap<Value, Value>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_statement: Option<Ctap2AttestationStatement>,
}

pub trait Ctap2UserVerifiableRequest {
    fn ensure_uv_set(&mut self);
    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    );
    fn client_data_hash(&self) -> &[u8];
    fn permissions(&self) -> ClientPinRequestPermissions;
    fn permissions_rpid(&self) -> Option<&str>;
}

impl Ctap2UserVerifiableRequest for Ctap2MakeCredentialRequest {
    fn ensure_uv_set(&mut self) {
        self.options = Some(Ctap2MakeCredentialOptions {
            deprecated_require_user_verification: Some(true),
            ..self
                .options
                .unwrap_or(Ctap2MakeCredentialOptions::default())
        });
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, self.client_data_hash());
        self.pin_auth_proto = Some(uv_proto.version() as u32);
        self.pin_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        self.hash.as_slice()
    }

    fn permissions(&self) -> ClientPinRequestPermissions {
        // GET_ASSERTION needed for pre-flight requests
        return ClientPinRequestPermissions::MAKE_CREDENTIAL
            | ClientPinRequestPermissions::GET_ASSERTION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party.id)
    }
}

impl Ctap2UserVerifiableRequest for Ctap2GetAssertionRequest {
    fn ensure_uv_set(&mut self) {
        self.options = Some(Ctap2GetAssertionOptions {
            require_user_verification: true,
            ..self.options.unwrap_or(Ctap2GetAssertionOptions::default())
        });
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, self.client_data_hash());
        self.pin_auth_proto = Some(uv_proto.version() as u32);
        self.pin_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        self.client_data_hash.as_slice()
    }

    fn permissions(&self) -> ClientPinRequestPermissions {
        return ClientPinRequestPermissions::GET_ASSERTION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party_id)
    }
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
    pub min_pin_length: Option<u32>,

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

#[derive(Debug, Clone, Copy)]
pub enum Ctap2UserVerificationOperation {
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetPinUvAuthTokenUsingPinWithPermissions,
    GetPinToken,
    None,
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

    /// Implements check for "Protected by some form of User Verification":
    ///   Either or both clientPin or built-in user verification methods are supported and enabled.
    ///   I.e., in the authenticatorGetInfo response the pinUvAuthToken option ID is present and set to true,
    ///   and either clientPin option ID is present and set to true or uv option ID is present and set to true or both.
    pub fn is_uv_protected(&self) -> bool {
        self.option_enabled("uv") || // Deprecated no-op UV
            self.option_enabled("clientPin") ||
            (self.option_enabled("pinUvAuthToken") && self.option_enabled("uv"))
    }

    pub fn uv_operation(&self, uv_blocked: bool) -> Option<Ctap2UserVerificationOperation> {
        if self.option_enabled("uv") && !uv_blocked {
            if self.option_enabled("pinUvAuthToken") {
                debug!("getPinUvAuthTokenUsingUvWithPermissions");
                return Some(
                    Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
                );
            } else {
                debug!("Deprecated FIDO 2.0 behaviour: populating 'uv' flag");
                return Some(Ctap2UserVerificationOperation::None);
            }
        } else {
            // !uv
            if self.option_enabled("pinUvAuthToken") {
                assert!(self.option_enabled("clientPin"));
                debug!("getPinUvAuthTokenUsingPinWithPermissions");
                return Some(
                    Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions,
                );
            } else if self.option_enabled("clientPin") {
                // !pinUvAuthToken
                debug!("getPinToken");
                return Some(Ctap2UserVerificationOperation::GetPinToken);
            } else {
                debug!("No UV and no PIN (e.g. maybe UV was blocked and no PIN available)");
                return None;
            }
        }
    }
}

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2ClientPinRequest {
    ///pinUvAuthProtocol (0x01)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    /// subCommand (0x02)
    pub command: Ctap2PinUvAuthProtocolCommand,

    /// keyAgreement (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<PublicKey>,

    /// pinUvAuthParam (0x04):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_auth_param: Option<ByteBuf>,

    /// newPinEnc (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pin_encrypted: Option<ByteBuf>,

    /// pinHashEnc (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash_encrypted: Option<ByteBuf>,

    #[serde(skip_serializing)]
    pub unused_07: (),

    #[serde(skip_serializing)]
    pub unused_08: (),

    /// permissions (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u32>,

    /// permissions RPID (0x10)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_rpid: Option<String>,
}

impl Ctap2ClientPinRequest {
    pub fn new_get_key_agreement(protocol: Ctap2PinUvAuthProtocol) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetKeyAgreement,
            key_agreement: None,
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            unused_07: (),
            unused_08: (),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_token(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        pin_hash_enc: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinToken,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: Some(ByteBuf::from(pin_hash_enc)),
            unused_07: (),
            unused_08: (),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_retries() -> Self {
        Self {
            protocol: None,
            command: Ctap2PinUvAuthProtocolCommand::GetPinRetries,
            key_agreement: None,
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            unused_07: (),
            unused_08: (),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_token_with_perm(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        pin_hash_enc: &[u8],
        permissions: ClientPinRequestPermissions,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: Some(ByteBuf::from(pin_hash_enc)),
            unused_07: (),
            unused_08: (),
            permissions: Some(permissions.bits()),
            permissions_rpid: permissions_rpid.map(str::to_owned),
        }
    }

    pub fn new_get_uv_token_with_perm(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        permissions: ClientPinRequestPermissions,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinUvAuthTokenUsingUvWithPermissions,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            unused_07: (),
            unused_08: (),
            permissions: Some(permissions.bits()),
            permissions_rpid: permissions_rpid.map(str::to_owned),
        }
    }

    pub fn new_change_pin(
        protocol: Ctap2PinUvAuthProtocol,
        new_pin_enc: &[u8],
        curr_pin_enc: &[u8],
        public_key: PublicKey,
        uv_auth_param: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::ChangePin,
            key_agreement: Some(public_key),
            uv_auth_param: Some(ByteBuf::from(uv_auth_param)),
            new_pin_encrypted: Some(ByteBuf::from(new_pin_enc)),
            pin_hash_encrypted: Some(ByteBuf::from(curr_pin_enc)),
            unused_07: (),
            unused_08: (),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_set_pin(
        protocol: Ctap2PinUvAuthProtocol,
        new_pin_enc: &[u8],
        public_key: PublicKey,
        uv_auth_param: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::SetPin,
            key_agreement: Some(public_key),
            uv_auth_param: Some(ByteBuf::from(uv_auth_param)),
            new_pin_encrypted: Some(ByteBuf::from(new_pin_enc)),
            pin_hash_encrypted: None,
            unused_07: (),
            unused_08: (),
            permissions: None,
            permissions_rpid: None,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, FromPrimitive, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
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
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

#[derive(Debug, Clone, Default, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2ClientPinResponse {
    /// keyAgreement (0x01)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<PublicKey>,

    /// pinUvAuthToken (0x02)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<ByteBuf>,

    /// pinRetries (0x03)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_retries: Option<u32>,

    /// powerCycleState (0x04)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<bool>,

    /// uvRetries (0x05)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_retries: Option<u32>,
}

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2AuthenticatorConfigRequest {
    // subCommand (0x01)
    pub subcommand: Ctap2AuthenticatorConfigCommand,

    // subCommandParams (0x02)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subcommand_params: Option<Ctap2AuthenticatorConfigParams>,

    ///pinUvAuthProtocol (0x03)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    /// pinUvAuthParam (0x04):
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_auth_param: Option<ByteBuf>,
}

impl Ctap2AuthenticatorConfigRequest {
    pub(crate) fn new_toggle_always_uv() -> Self {
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::ToggleAlwaysUv,
            subcommand_params: None,
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_enable_enterprise_attestation() -> Self {
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::EnableEnterpriseAttestation,
            subcommand_params: None,
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_force_change_pin(force_change_pin: bool) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLength(Ctap2SetMinPINLengthParams {
                new_min_pin_length: None,
                min_pin_length_rpids: None,
                force_change_pin: Some(force_change_pin),
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_set_min_pin_length(new_pin_length: u64) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLength(Ctap2SetMinPINLengthParams {
                new_min_pin_length: Some(new_pin_length),
                min_pin_length_rpids: None,
                force_change_pin: None,
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_set_min_pin_length_rpids(rpids: Vec<String>) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLengthRPIDs(Ctap2SetMinPINLengthParams {
                new_min_pin_length: None,
                min_pin_length_rpids: Some(rpids),
                force_change_pin: None,
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2AuthenticatorConfigCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPINLength = 0x03,
    VendorPrototype = 0xFF,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Ctap2AuthenticatorConfigParams {
    SetMinPINLength(Ctap2SetMinPINLengthParams),
    SetMinPINLengthRPIDs(Ctap2SetMinPINLengthParams),
}

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2SetMinPINLengthParams {
    // newMinPINLength (0x01)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_min_pin_length: Option<u64>,

    // minPinLengthRPIDs (0x02)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length_rpids: Option<Vec<String>>,

    // forceChangePin (0x03)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_change_pin: Option<bool>,
}
