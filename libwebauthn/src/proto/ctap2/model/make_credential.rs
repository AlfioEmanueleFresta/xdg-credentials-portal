use super::{
    Ctap2AttestationStatement, Ctap2AuthTokenPermissionRole, Ctap2CredentialType,
    Ctap2GetInfoResponse, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity, Ctap2UserVerifiableRequest,
};
use crate::{
    ops::webauthn::MakeCredentialRequest,
    pin::PinUvAuthProtocol,
    proto::{
        ctap2::{model::AUTHENTICATOR_DATA_PUBLIC_KEY_OFFSET, Ctap2PublicKeyCredentialType},
        CtapError,
    },
};
use byteorder::{BigEndian, ReadBytesExt};
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use std::collections::BTreeMap;
use std::io::Cursor as IOCursor;
use tracing::warn;

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

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        // GET_ASSERTION needed for pre-flight requests
        return Ctap2AuthTokenPermissionRole::MAKE_CREDENTIAL
            | Ctap2AuthTokenPermissionRole::GET_ASSERTION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party.id)
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }
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
