extern crate async_trait;
extern crate authenticator;
extern crate base64_url;
extern crate sha2;
extern crate tokio;

use super::protocol::Ctap1Error;
use super::protocol::{Ctap1RegisterRequest, Ctap1RegisterResponse};
use super::protocol::{Ctap1RegisteredKey, Ctap1Version};
use super::protocol::{Ctap1SignRequest, Ctap1SignResponse};

use super::Ctap1HidAuthenticator;

use async_trait::async_trait;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use authenticator::{
    AuthenticatorTransports, Error as U2FError, KeyHandle, RegisterFlags, SignFlags, U2FManager,
};

use sha2::{Digest, Sha256};

pub struct MozillaCtap1HidAuthenticator {}

impl MozillaCtap1HidAuthenticator {
    pub fn new() -> Self {
        Self {}
    }

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

#[async_trait]
impl Ctap1HidAuthenticator for MozillaCtap1HidAuthenticator {
    async fn register(
        &self,
        request: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Ctap1Error> {
        let manager = U2FManager::new().unwrap();
        let flags = RegisterFlags::empty();
        let (client_data, client_data_hash) =
            Self::build_client_data(&request.challenge, &request.app_id);

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
                U2FError::NotAllowed => return Err(Ctap1Error::BadRequest),
                _ => return Err(Ctap1Error::OtherError),
            }
        }

        rx.await.unwrap()
    }

    async fn sign(&self, request: Ctap1SignRequest) -> Result<Ctap1SignResponse, Ctap1Error> {
        let manager = U2FManager::new().unwrap();
        let flags = SignFlags::empty();
        let (client_data, client_data_hash) =
            Self::build_client_data(&request.challenge, &request.app_id);
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
                U2FError::NotAllowed => return Err(Ctap1Error::BadRequest),
                _ => return Err(Ctap1Error::OtherError),
            }
        }

        rx.await.unwrap()
    }
}
