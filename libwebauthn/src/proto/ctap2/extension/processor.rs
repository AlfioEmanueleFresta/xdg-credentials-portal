use serde_cbor::Value;

use crate::proto::ctap2::{
    Ctap2GetAssertionRequest, Ctap2GetAssertionResponse, Ctap2MakeCredentialRequest,
    Ctap2MakeCredentialResponse,
};
use crate::webauthn::CtapError;

pub enum Ctap2ExtensionProcessorRequestAction {
    Passthrough,
    Deny(CtapError),
}

pub enum Ctap2ExtensionProcessorResponseAction {
    Passthrough,
    Deny(CtapError),
}

pub trait Ctap2MakeCredentialExtensionProcessor {
    const KEY: &'static str;

    fn process_request(
        &self,
        request: &Ctap2MakeCredentialRequest,
        request_value: &Value,
    ) -> Result<Ctap2ExtensionProcessorRequestAction, CtapError>;

    fn process_response(
        &self,
        response: &Ctap2MakeCredentialResponse,
        response_value: &Value,
    ) -> Result<Ctap2ExtensionProcessorResponseAction, CtapError>;
}

pub trait Ctap2GetAssertionExtensionProcessor {
    const KEY: &'static str;

    fn process_request(
        request: &Ctap2GetAssertionRequest,
        request_value: &Value,
    ) -> Result<Ctap2ExtensionProcessorRequestAction, CtapError>;

    fn process_response(
        &self,
        response: &Ctap2GetAssertionResponse,
        response_value: &Value,
    ) -> Result<Ctap2ExtensionProcessorResponseAction, CtapError>;
}
