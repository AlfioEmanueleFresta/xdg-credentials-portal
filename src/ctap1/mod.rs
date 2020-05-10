pub mod protocol;
pub mod usb;

use async_trait::async_trait;
use protocol::Ctap1Error;
use protocol::{Ctap1RegisterRequest, Ctap1RegisterResponse};
use protocol::{Ctap1SignRequest, Ctap1SignResponse};

#[async_trait]
pub trait Ctap1HidAuthenticator {
    async fn register(
        &self,
        request: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Ctap1Error>;

    async fn sign(&self, request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error>;
}
