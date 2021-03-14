use std::time::Duration;

use crate::proto::ctap2::{
    Ctap2CredentialType, Ctap2MakeCredentialResponse, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
};
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};

// FIDO2 operations can be mapped by default to their respective CTAP2 requests.

pub type MakeCredentialResponse = Ctap2MakeCredentialResponse;

#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    pub hash: Vec<u8>,
    pub origin: String,
    /// rpEntity
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,
    /// userEntity
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub require_resident_key: bool,
    pub require_user_presence: bool,
    pub require_user_verification: bool,
    /// credTypesAndPubKeyAlgs
    pub algorithms: Vec<Ctap2CredentialType>,
    /// excludeCredentialDescriptorList
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    /// extensions
    pub extensions_cbor: Vec<u8>,
    pub timeout: Duration,
}

pub type GetAssertionRequest = Ctap2GetAssertionRequest;
pub type GetAssertionResponse = Ctap2GetAssertionResponse;
