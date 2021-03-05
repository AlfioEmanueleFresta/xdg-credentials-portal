extern crate async_trait;
extern crate hidapi;
extern crate log;
extern crate serde;
extern crate serde_cbor;

use async_trait::async_trait;
use log::{debug, info, warn};
use std::convert::TryInto;
use std::marker::PhantomData;

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::webauthn::{GetAssertionRequest, GetAssertionResponse};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};

use crate::proto::ctap1::{Ctap1, Ctap1Protocol};
use crate::proto::ctap2::Ctap2DowngradeCheck;
use crate::proto::ctap2::{Ctap2, Ctap2MakeCredentialRequest, Ctap2Protocol};

use crate::fido::FidoProtocol;

use crate::transport::device::FidoDevice;
use crate::transport::error::{CtapError, Error, TransportError};

#[async_trait]
pub trait WebAuthn<T> {
    async fn make_credential(
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn get_assertion(
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
}

pub struct WebAuthnManager<T> {
    device_type: PhantomData<T>,
}

#[async_trait]
impl<T> WebAuthn<T> for WebAuthnManager<T>
where
    T: FidoDevice + Send,
{
    async fn make_credential(
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        debug!("WebAuthn MakeCredential request: {:?}", op);
        let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
        let protocol =
            WebAuthnManager::negotiate_protocol(device, ctap2_request.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => {
                Ctap2Protocol::make_credential(device, ctap2_request, op.timeout).await
            }
            FidoProtocol::U2F => {
                let register_request: RegisterRequest = ctap2_request
                    .try_into()
                    .or(Err(TransportError::NegotiationFailed))?;
                Ctap1Protocol::register(device, &register_request)
                    .await?
                    .try_into()
                    .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
            }
        }
    }

    async fn get_assertion(
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let protocol = WebAuthnManager::negotiate_protocol(device, op.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => Ctap2Protocol::get_assertion(device, op, op.timeout).await,
            FidoProtocol::U2F => {
                let sign_request: SignRequest =
                    op.try_into().or(Err(TransportError::NegotiationFailed))?;
                Ctap1Protocol::sign(device, &sign_request)
                    .await?
                    .try_into()
                    .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
            }
        }
    }
}

impl<T> WebAuthnManager<T>
where
    T: FidoDevice + Send,
{
    async fn negotiate_protocol(device: &mut T, allow_u2f: bool) -> Result<FidoProtocol, Error> {
        let supported = device.supported_protocols().await?;
        if !supported.u2f && !supported.fido2 {
            return Err(Error::Transport(TransportError::NegotiationFailed));
        }

        if !allow_u2f && !supported.fido2 {
            return Err(Error::Transport(TransportError::NegotiationFailed));
        }

        let fido_protocol = if supported.fido2 {
            FidoProtocol::FIDO2
        } else {
            // Ensure CTAP1 version is reported correctly.
            Ctap1Protocol::version(device).await?;
            FidoProtocol::U2F
        };

        if fido_protocol == FidoProtocol::U2F {
            warn!("Negotiated protocol downgrade from FIDO2 to FIDO U2F");
        } else {
            info!("Selected protocol: {:?}", fido_protocol);
        }
        Ok(fido_protocol)
    }
}
