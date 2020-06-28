extern crate authenticator;
extern crate base64_url;
extern crate sha2;
extern crate tokio;

use crate::proto::ctap1::Ctap1Error;
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1RegisterResponse};
use crate::proto::ctap1::{Ctap1RegisteredKey, Ctap1Version};
use crate::proto::ctap1::{Ctap1SignRequest, Ctap1SignResponse};

use crate::ops::webauthn::Error as WebauthnError;
use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::Error as U2FError;
use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::proto::ctap1::apdu::ApduResponse;
use authenticator::{
    AuthenticatorTransports, Error as MozillaU2FError, KeyHandle, RegisterFlags, SignFlags,
    U2FManager,
};
use std::convert::TryInto;

impl Ctap1RegisteredKey {
    fn to_key_handle(&self) -> KeyHandle {
        KeyHandle {
            credential: self.key_handle.clone(),
            transports: AuthenticatorTransports::USB,
        }
    }
    // fn from_key_handle(key_handle: KeyHandle) -> Ctap1RegisteredKey;
}

pub struct USBManager {}

impl USBManager {
    pub fn new() -> Option<USBManager> {
        Some(USBManager {})
    }

    pub async fn webauthn_make_credential(
        &self,
        _: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, WebauthnError> {
        // TODO no ability to negotiate FIDO2 yet - should attempt to downgrade request to U2F.
        unimplemented!()
    }

    pub async fn webauthn_get_assertion(
        &self,
        _: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, WebauthnError> {
        // TODO no ability to negotiate FIDO2 yet - should attempt to downgrade request to U2F.
        unimplemented!()
    }

    pub async fn u2f_register(&self, op: RegisterRequest) -> Result<RegisterResponse, U2FError> {
        _u2f_register(op.into()).await.map_err(|e| e.into())
    }

    pub async fn u2f_sign(&self, op: SignRequest) -> Result<SignResponse, U2FError> {
        _u2f_sign(op.into()).await.map_err(|e| e.into())
    }
}

async fn _u2f_register(request: Ctap1RegisterRequest) -> Result<Ctap1RegisterResponse, Ctap1Error> {
    let manager = U2FManager::new().unwrap();
    let flags = RegisterFlags::empty();
    let app_id_hash = request.app_id_hash();

    let key_handles = request
        .registered_keys
        .iter()
        .map(|registered_key| registered_key.to_key_handle())
        .collect();

    let (tx, rx): (
        Sender<Result<Ctap1RegisterResponse, Ctap1Error>>,
        Receiver<Result<Ctap1RegisterResponse, Ctap1Error>>,
    ) = channel();
    if let Err(u2f_error) = manager.register(
        flags,
        (request.timeout_seconds * 1000).into(),
        request.challenge,
        app_id_hash,
        key_handles,
        move |rv| {
            if let Err(_) = rv {
                tx.send(Err(Ctap1Error::Timeout)).unwrap();
                return;
            };

            let registration_data = &rv.unwrap();
            let apdu: ApduResponse = ApduResponse::new_success(&registration_data);
            let response: Ctap1RegisterResponse = apdu.try_into().unwrap();

            tx.send(Ok(response)).unwrap();
        },
    ) {
        return match u2f_error {
            MozillaU2FError::NotAllowed => Err(Ctap1Error::BadRequest),
            _ => Err(Ctap1Error::OtherError),
        };
    }

    rx.await.unwrap()
}

async fn _u2f_sign(request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error> {
    let manager = U2FManager::new().unwrap();
    let flags = SignFlags::empty();
    let app_id_hash = request.app_id_hash();
    let key_handles = request
        .registered_keys
        .iter()
        .map(|registered_key| registered_key.to_key_handle())
        .collect();

    let (tx, rx): (
        Sender<Result<Ctap1SignResponse, Ctap1Error>>,
        Receiver<Result<Ctap1SignResponse, Ctap1Error>>,
    ) = channel();
    if let Err(u2f_error) = manager.sign(
        flags,
        (request.timeout_seconds * 1000).into(),
        request.challenge,
        vec![app_id_hash],
        key_handles,
        move |rv| {
            if let Err(_) = rv {
                tx.send(Err(Ctap1Error::Timeout)).unwrap();
                return;
            };

            let (_, key_handle, signature_data) = rv.unwrap();
            let response = Ctap1SignResponse {
                key_handle,
                signature_data,
            };

            tx.send(Ok(response)).unwrap();
        },
    ) {
        match u2f_error {
            MozillaU2FError::NotAllowed => return Err(Ctap1Error::BadRequest),
            _ => return Err(Ctap1Error::OtherError),
        }
    }

    rx.await.unwrap()
}
