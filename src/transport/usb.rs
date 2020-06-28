extern crate authenticator;
extern crate base64_url;
extern crate sha2;
extern crate tokio;

use crate::proto::ctap1::Ctap1RegisteredKey;
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1RegisterResponse};
use crate::proto::ctap1::{Ctap1SignRequest, Ctap1SignResponse};

use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::proto::ctap1::apdu::ApduResponse;
use crate::proto::CtapError;
use crate::transport::error::Error;

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
    ) -> Result<MakeCredentialResponse, Error> {
        // TODO no ability to negotiate FIDO2 yet - should attempt to downgrade request to U2F.
        unimplemented!()
    }

    pub async fn webauthn_get_assertion(
        &self,
        _: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        // TODO no ability to negotiate FIDO2 yet - should attempt to downgrade request to U2F.
        unimplemented!()
    }

    pub async fn u2f_register(&self, op: RegisterRequest) -> Result<RegisterResponse, Error> {
        _u2f_register(op.into()).await.map_err(|e| e.into())
    }

    pub async fn u2f_sign(&self, op: SignRequest) -> Result<SignResponse, Error> {
        _u2f_sign(op.into()).await.map_err(|e| e.into())
    }
}

async fn _u2f_register(request: Ctap1RegisterRequest) -> Result<Ctap1RegisterResponse, Error> {
    let manager = U2FManager::new().unwrap();
    let flags = RegisterFlags::empty();
    let app_id_hash = request.app_id_hash();

    let key_handles = request
        .registered_keys
        .iter()
        .map(|registered_key| registered_key.to_key_handle())
        .collect();

    let (tx, rx): (
        Sender<Result<Ctap1RegisterResponse, Error>>,
        Receiver<Result<Ctap1RegisterResponse, Error>>,
    ) = channel();
    if let Err(u2f_error) = manager.register(
        flags,
        (request.timeout_seconds * 1000).into(),
        request.challenge,
        app_id_hash,
        key_handles,
        move |rv| {
            if let Err(_) = rv {
                tx.send(Err(Error::Ctap(CtapError::Timeout))).unwrap();
                return;
            };

            let registration_data = &rv.unwrap();
            let apdu: ApduResponse = ApduResponse::new_success(&registration_data);
            let response: Ctap1RegisterResponse = apdu.try_into().unwrap();

            tx.send(Ok(response)).unwrap();
        },
    ) {
        return match u2f_error {
            MozillaU2FError::NotAllowed => Err(Error::Ctap(CtapError::NotAllowed)),
            MozillaU2FError::NotSupported => Err(Error::Ctap(CtapError::InvalidCommand)),
            _ => Err(Error::Ctap(CtapError::Other)),
        };
    }

    rx.await.unwrap()
}

async fn _u2f_sign(request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Error> {
    let manager = U2FManager::new().unwrap();
    let flags = SignFlags::empty();
    let app_id_hash = request.app_id_hash();
    let key_handle = KeyHandle {
        credential: request.key_handle.clone(),
        transports: AuthenticatorTransports::USB,
    };

    let (tx, rx): (
        Sender<Result<Ctap1SignResponse, Error>>,
        Receiver<Result<Ctap1SignResponse, Error>>,
    ) = channel();
    if let Err(u2f_error) = manager.sign(
        flags,
        (request.timeout_seconds * 1000).into(),
        request.challenge,
        vec![app_id_hash],
        vec![key_handle],
        move |rv| {
            if let Err(_) = rv {
                tx.send(Err(Error::Ctap(CtapError::Timeout))).unwrap();
                return;
            };

            let (_, _, signature) = rv.unwrap();
            let response = Ctap1SignResponse {
                user_presence_verified: true,
                signature,
            };

            tx.send(Ok(response)).unwrap();
        },
    ) {
        match u2f_error {
            MozillaU2FError::NotAllowed => return Err(Error::Ctap(CtapError::NotAllowed)),
            MozillaU2FError::NotSupported => return Err(Error::Ctap(CtapError::InvalidCommand)),
            _ => return Err(Error::Ctap(CtapError::Other)),
        }
    }

    rx.await.unwrap()
}
