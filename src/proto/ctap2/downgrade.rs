use std::convert::{TryFrom, TryInto};

use crate::proto::error::CtapError;

use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1RegisterResponse, Ctap1Transport};
use crate::proto::ctap1::{Ctap1RegisteredKey, Ctap1Version};
use crate::proto::ctap1::{Ctap1SignRequest, Ctap1SignResponse};

use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
use crate::proto::ctap2::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
use crate::proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport};

// FIDO2 operations can *sometimes* be downgrade to FIDO U2F operations.
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-interoperability

pub trait Ctap2DowngradeCheck<T> {
    fn is_downgradable(&self) -> bool;
}

impl TryFrom<&Ctap2Transport> for Ctap1Transport {
    type Error = CtapError;
    fn try_from(ctap2: &Ctap2Transport) -> Result<Ctap1Transport, Self::Error> {
        match ctap2 {
            Ctap2Transport::BLE => Ok(Ctap1Transport::BLE),
            Ctap2Transport::USB => Ok(Ctap1Transport::USB),
            Ctap2Transport::NFC => Ok(Ctap1Transport::NFC),
            Ctap2Transport::INTERNAL => Err(CtapError::UnsupportedOption),
        }
    }
}

impl From<&Ctap1Transport> for Ctap2Transport {
    fn from(ctap1: &Ctap1Transport) -> Ctap2Transport {
        match ctap1 {
            Ctap1Transport::BT => Ctap2Transport::BLE,
            Ctap1Transport::BLE => Ctap2Transport::BLE,
            Ctap1Transport::USB => Ctap2Transport::USB,
            Ctap1Transport::NFC => Ctap2Transport::NFC,
        }
    }
}

impl TryFrom<&Ctap2MakeCredentialRequest> for Ctap1RegisterRequest {
    type Error = CtapError;
    fn try_from(ctap2: &Ctap2MakeCredentialRequest) -> Result<Ctap1RegisterRequest, CtapError> {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-authenticatorMakeCredential-interoperability

        // TODO checks

        Ok(Ctap1RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id: ctap2.relying_party.id.clone(),
            challenge: ctap2.hash.clone(),
            registered_keys: ctap2
                .exclude
                .as_ref()
                .unwrap_or(&vec![])
                .into_iter()
                .map(|exclude| Ctap1RegisteredKey {
                    version: Ctap1Version::U2fV2,
                    key_handle: exclude.id.clone(),
                    transports: {
                        match &exclude.transports {
                            None => None,
                            Some(ctap2_transports) => {
                                let transports: Result<Vec<_>, _> =
                                    ctap2_transports.into_iter().map(|t| t.try_into()).collect();
                                transports.ok()
                            }
                        }
                    },
                    app_id: Some(ctap2.relying_party.id.clone()),
                })
                .collect(),
            require_user_presence: ctap2.require_user_presence,
            timeout: ctap2.timeout,
        })
    }
}

impl Ctap2DowngradeCheck<Ctap1RegisterRequest> for Ctap2MakeCredentialRequest {
    fn is_downgradable(&self) -> bool {
        true // FIXME
    }
}

impl TryFrom<Ctap1RegisterResponse> for Ctap2MakeCredentialResponse {
    type Error = ();
    fn try_from(_: Ctap1RegisterResponse) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl Ctap2DowngradeCheck<Ctap1SignRequest> for Ctap2GetAssertionRequest {
    fn is_downgradable(&self) -> bool {
        true // FIXME
    }
}

impl TryFrom<&Ctap2GetAssertionRequest> for Ctap1SignRequest {
    type Error = ();
    fn try_from(_: &Ctap2GetAssertionRequest) -> Result<Ctap1SignRequest, Self::Error> {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-authenticatorGetAssertion-interoperability
        unimplemented!()
    }
}

impl TryFrom<Ctap1SignResponse> for Ctap2GetAssertionResponse {
    type Error = ();

    fn try_from(_: Ctap1SignResponse) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}
