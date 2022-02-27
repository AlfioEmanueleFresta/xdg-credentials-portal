extern crate async_trait;

pub mod cbor;

mod downgrade;
mod model;
mod protocol;

pub use downgrade::Ctap2DowngradeCheck;
pub use model::Ctap2GetInfoResponse;
pub use model::{
    ClientPinRequestPermissions, Ctap2COSEAlgorithmIdentifier, Ctap2ClientPinRequest,
    Ctap2CommandCode, Ctap2CredentialType, Ctap2MakeCredentialOptions, Ctap2PinUvAuthProtocol,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity, Ctap2Transport,
    Ctap2UserVerifiableRequest, Ctap2UserVerificationOperation,
};
pub use model::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use model::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
pub use protocol::Ctap2;
