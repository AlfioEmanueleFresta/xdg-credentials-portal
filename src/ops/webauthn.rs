use crate::proto::ctap1::Ctap1Error;
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};
use crate::proto::ctap2::Ctap2Error;
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};

use std::convert::{TryFrom, TryInto};

// FIDO2 operations can be mapped by default to their respective CTAP2 requests.

pub type MakeCredentialRequest = Ctap2MakeCredentialRequest;
pub type MakeCredentialResponse = Ctap2MakeCredentialResponse;
pub type GetAssertionRequest = Ctap2GetAssertionRequest;
pub type GetAssertionResponse = Ctap2GetAssertionResponse;

#[derive(Debug)]
pub enum Error {
    Unknown,
    InvalidState,
    NotAllowed,
    Constraint,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<Ctap2Error> for Error {
    fn from(error: Ctap2Error) -> Self {
        match error {
            Ctap2Error::OTHER => Error::Unknown,
        }
    }
}

impl From<Ctap1Error> for Error {
    fn from(_: Ctap1Error) -> Self {
        Error::Unknown // FIXME
    }
}

// FIDO2 operations can *sometimes* be downgrade to FIDO U2F operations.
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-interoperability

impl TryInto<Ctap1RegisterRequest> for MakeCredentialRequest {
    type Error = ();
    fn try_into(self) -> Result<Ctap1RegisterRequest, Self::Error> {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-authenticatorMakeCredential-interoperability
        unimplemented!()
    }
}

impl TryFrom<Ctap1RegisterResponse> for MakeCredentialResponse {
    type Error = ();
    fn try_from(_: Ctap1RegisterResponse) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl TryInto<Ctap1SignRequest> for GetAssertionRequest {
    type Error = ();
    fn try_into(self) -> Result<Ctap1SignRequest, Self::Error> {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-authenticatorGetAssertion-interoperability
        unimplemented!()
    }
}

impl TryFrom<Ctap1SignResponse> for GetAssertionResponse {
    type Error = ();

    fn try_from(_: Ctap1SignResponse) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}
