pub mod protocol;
pub mod usb;

use protocol::Ctap1Error;
use protocol::{Ctap1RegisterRequest, Ctap1RegisterResponse};
use protocol::{Ctap1SignRequest, Ctap1SignResponse};

pub trait Ctap1HidAuthenticator {
    fn register(&self, request: Ctap1RegisterRequest) -> Result<Ctap1RegisterResponse, Ctap1Error>;
    fn sign(&self, request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error>;
}
