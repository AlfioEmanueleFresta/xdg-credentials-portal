extern crate async_trait;

pub mod cbor;

mod downgrade;
mod model;
mod protocol;

pub use downgrade::Ctap2DowngradeCheck;
pub use model::Ctap2GetInfoResponse;
pub use model::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CommandCode, Ctap2CredentialType,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity, Ctap2Transport,
};
pub use model::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use model::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
pub use protocol::Ctap2;
