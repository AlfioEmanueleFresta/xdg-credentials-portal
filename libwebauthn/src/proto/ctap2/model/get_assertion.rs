use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        GetAssertionRequest, GetAssertionRequestExtensions, GetAssertionResponseExtensions,
    },
    pin::PinUvAuthProtocol,
};

use super::{
    Ctap2AuthTokenPermissionRole, Ctap2COSEAlgorithmIdentifier, Ctap2GetInfoResponse,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity,
    Ctap2UserVerifiableRequest,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use std::collections::BTreeMap;

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
    #[serde(skip_serializing_if = "Self::skip_serializing_extensions")]
    pub extensions: Option<GetAssertionRequestExtensions>,

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

impl Ctap2GetAssertionRequest {
    pub fn skip_serializing_extensions(extensions: &Option<GetAssertionRequestExtensions>) -> bool {
        extensions
            .as_ref()
            .map_or(true, |extensions| extensions.skip_serializing())
    }
}

impl From<&GetAssertionRequest> for Ctap2GetAssertionRequest {
    fn from(op: &GetAssertionRequest) -> Self {
        Self {
            relying_party_id: op.relying_party_id.clone(),
            client_data_hash: ByteBuf::from(op.hash.clone()),
            allow: op.allow.clone(),
            extensions: op.extensions.clone(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,

    pub authenticator_data: AuthenticatorData<GetAssertionResponseExtensions>,

    pub signature: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_count: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_selected: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_outputs: Option<BTreeMap<Value, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_statement: Option<Ctap2AttestationStatement>,
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

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        return Ctap2AuthTokenPermissionRole::GET_ASSERTION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party_id)
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }

    fn handle_legacy_preview(&mut self, _info: &Ctap2GetInfoResponse) {
        // No-op
    }
}
