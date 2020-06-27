extern crate async_trait;

mod protocol;

pub use protocol::Ctap2Error;
pub use protocol::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialType,
    Ctap2PublicKeyCredentialUserEntity,
};
pub use protocol::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use protocol::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
