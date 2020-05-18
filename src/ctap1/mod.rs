mod protocol;
mod usb;

extern crate async_trait;

use async_trait::async_trait;
pub use protocol::Ctap1Error;
pub use protocol::{Ctap1RegisterRequest, Ctap1RegisterResponse};
pub use protocol::{Ctap1SignRequest, Ctap1SignResponse};
pub use usb::MozillaCtap1HidAuthenticator;

#[async_trait]
pub trait Ctap1HidAuthenticator {
    async fn register(
        &self,
        request: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Ctap1Error>;

    async fn sign(&self, request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error>;
}
