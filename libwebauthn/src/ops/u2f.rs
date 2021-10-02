use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

// FIDO U2F operations can be aliased to CTAP1 requests, as they have no other representation.
pub type RegisterRequest = Ctap1RegisterRequest;
pub type RegisterResponse = Ctap1RegisterResponse;
pub type SignRequest = Ctap1SignRequest;
pub type SignResponse = Ctap1SignResponse;
