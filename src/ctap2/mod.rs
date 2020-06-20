extern crate async_trait;

mod ble;
mod protocol;

use async_trait::async_trait;

pub use ble::BlueZCtap2BleAuthenticator;
pub use ble::{Ctap2BleDevicePath, CTAP2_BLE_UUID};
pub use protocol::Ctap2Error;
pub use protocol::{
    Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialType,
    Ctap2PublicKeyCredentialUserEntity,
};
pub use protocol::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
pub use protocol::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};

#[async_trait]
pub trait Ctap2BleAuthenticator {
    async fn make_credentials(
        &self,
        device: Ctap2BleDevicePath,
        request: Ctap2MakeCredentialRequest,
    ) -> Result<Ctap2MakeCredentialResponse, Ctap2Error>;

    async fn get_assertion(
        &self,
        device: Ctap2BleDevicePath,
        request: Ctap2GetAssertionRequest,
    ) -> Result<Ctap2GetAssertionResponse, Ctap2Error>;
}
