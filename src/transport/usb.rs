extern crate async_trait;
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

use async_trait::async_trait;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use authenticator::{
    AuthenticatorTransports, Error as MozillaU2FError, KeyHandle, RegisterFlags, SignFlags,
    U2FManager,
};

use sha2::{Digest, Sha256};

fn build_client_data(challenge: &Vec<u8>, app_id: &String) -> (String, Vec<u8>) {
    let challenge_base64url = base64_url::encode(&challenge);
    let version_string = "U2F_V2";

    let client_data = format!(
        "{{\"challenge\": \"{}\", \"version:\": \"{}\", \"appId\": \"{}\"}}",
        challenge_base64url, version_string, app_id
    );

    let mut hasher = Sha256::default();
    hasher.input(client_data.as_bytes());
    let client_data_hash = hasher.result().to_vec();

    (client_data, client_data_hash)
}

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

    async fn webauthn_make_credential(
        &self,
        op: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, WebauthnError> {
        unimplemented!()
    }

    async fn webauthn_get_assertion(
        &self,
        op: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, WebauthnError> {
        unimplemented!()
    }

    async fn u2f_register(&self, op: RegisterRequest) -> Result<RegisterResponse, U2FError> {
        _u2f_register(op.into()).await.map_err(|e| e.into())
    }

    async fn u2f_sign(&self, op: SignRequest) -> Result<SignResponse, U2FError> {
        _u2f_sign(op.into()).await.map_err(|e| e.into())
    }
}

async fn _u2f_register(request: Ctap1RegisterRequest) -> Result<Ctap1RegisterResponse, Ctap1Error> {
    let manager = U2FManager::new().unwrap();
    let flags = RegisterFlags::empty();
    let (client_data, client_data_hash) = build_client_data(&request.challenge, &request.app_id);

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
        client_data_hash,
        key_handles,
        move |rv| {
            if let Err(_) = rv {
                tx.send(Err(Ctap1Error::Timeout)).unwrap();
                return;
            };

            let registration_data = rv.unwrap();

            let response = Ctap1RegisterResponse {
                version: Ctap1Version::U2fV2,
                registration_data,
                client_data: Vec::from(client_data.as_bytes()),
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

async fn _u2f_sign(request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error> {
    let manager = U2FManager::new().unwrap();
    let flags = SignFlags::empty();
    let (client_data, client_data_hash) = build_client_data(&request.challenge, &request.app_id);
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
        vec![client_data_hash],
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
                client_data: Vec::from(client_data.as_bytes()),
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
