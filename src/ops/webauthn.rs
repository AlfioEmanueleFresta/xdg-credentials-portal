use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};

use std::convert::{TryFrom, TryInto};

// FIDO2 operations can be mapped by default to their respective CTAP2 requests.

pub type MakeCredentialRequest = Ctap2MakeCredentialRequest;
pub type MakeCredentialResponse = Ctap2MakeCredentialResponse;
pub type GetAssertionRequest = Ctap2GetAssertionRequest;
pub type GetAssertionResponse = Ctap2GetAssertionResponse;
