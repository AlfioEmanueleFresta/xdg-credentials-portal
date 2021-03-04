extern crate async_trait;

pub mod cbor;

mod downgrade;
mod protocol;

pub use downgrade::Ctap2DowngradeCheck;
pub use protocol::Ctap2GetInfoResponse;
pub use protocol::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CommandCode, Ctap2CredentialType,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity, Ctap2Transport,
};
pub use protocol::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use protocol::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
