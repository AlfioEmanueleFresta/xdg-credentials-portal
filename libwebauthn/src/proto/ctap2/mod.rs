extern crate async_trait;

pub mod cbor;

mod model;
mod protocol;

pub use model::Ctap2GetInfoResponse;
pub use model::{
    Ctap2AuthTokenPermissionRole, Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier,
    Ctap2ClientPinRequest, Ctap2CommandCode, Ctap2CredentialType, Ctap2MakeCredentialOptions,
    Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity, Ctap2Transport,
    Ctap2UserVerifiableRequest, Ctap2UserVerificationOperation, FidoU2fAttestationStmt,
};
pub use model::{
    Ctap2AuthenticatorConfigCommand, Ctap2AuthenticatorConfigParams,
    Ctap2AuthenticatorConfigRequest,
};
pub use model::{
    Ctap2BioEnrollmentFingerprintKind, Ctap2BioEnrollmentModality, Ctap2BioEnrollmentRequest,
    Ctap2BioEnrollmentResponse, Ctap2BioEnrollmentTemplateId, Ctap2LastEnrollmentSampleStatus,
};
pub use model::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use model::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
pub use protocol::Ctap2;
