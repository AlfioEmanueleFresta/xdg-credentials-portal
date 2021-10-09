extern crate async_trait;
extern crate hidapi;
extern crate log;
extern crate serde;
extern crate serde_cbor;

use async_trait::async_trait;
use log::{debug, info, warn};
use std::convert::TryInto;
use std::marker::PhantomData;

use crate::ops::webauthn::{GetAssertionRequest, GetAssertionResponse};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::pin::PinProvider;
use crate::pin::PinUvAuthToken;
use crate::{
    ops::u2f::{RegisterRequest, SignRequest},
    proto::ctap2::Ctap2GetInfoResponse,
};

use crate::proto::ctap1::{Ctap1, Ctap1Protocol};
use crate::proto::ctap2::Ctap2DowngradeCheck;
use crate::proto::ctap2::{
    Ctap2, Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest, Ctap2Protocol,
};

use crate::fido::FidoProtocol;

use crate::transport::device::FidoDevice;
use crate::transport::error::{CtapError, Error, TransportError};

#[async_trait]
pub trait WebAuthn<T> {
    async fn make_credential(
        &self,
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn get_assertion(
        &self,
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
}

pub struct WebAuthnManager<'a, T, P: 'a> {
    device_type: PhantomData<T>,
    pin_provider: &'a P,
}

#[async_trait]
impl<'a, T, P: 'a> WebAuthn<T> for WebAuthnManager<'a, T, P>
where
    T: FidoDevice + Send + Sync,
    P: PinProvider + Send + Sync,
{
    async fn make_credential(
        &self,
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        debug!("WebAuthn MakeCredential request: {:?}", op);
        let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
        let protocol = self
            .negotiate_protocol(device, ctap2_request.is_downgradable())
            .await?;
        match protocol {
            FidoProtocol::FIDO2 => self.make_credential_fido2(device, op).await,
            FidoProtocol::U2F => self.make_credential_u2f(device, op).await,
        }
    }

    async fn get_assertion(
        &self,
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let ctap2_request: &Ctap2GetAssertionRequest = &op.into();
        let protocol = self
            .negotiate_protocol(device, ctap2_request.is_downgradable())
            .await?;
        match protocol {
            FidoProtocol::FIDO2 => self.get_assertion_fido2(device, op).await,
            FidoProtocol::U2F => self.get_assertion_u2f(device, op).await,
        }
    }
}

impl<'a, T, P: 'a> WebAuthnManager<'a, T, P>
where
    T: FidoDevice + Send + Sync,
    P: PinProvider + Send + Sync,
{
    pub fn new(pin_provider: &'a P) -> Self {
        Self {
            pin_provider: pin_provider,
            device_type: PhantomData::<T>::default(),
        }
    }

    async fn make_credential_fido2(
        &self,
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let ctap2_request: Ctap2MakeCredentialRequest = op.into();

        //self.make_credential_pin_auth(device, &mut ctap2_request, &get_info)
        //    .await?;

        Ctap2Protocol::make_credential(device, &ctap2_request, op.timeout).await
    }

    async fn make_credential_u2f(
        &self,
        device: &mut T,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
        let register_request: RegisterRequest = ctap2_request
            .try_into()
            .or(Err(TransportError::NegotiationFailed))?;
        Ctap1Protocol::register(device, &register_request)
            .await?
            .try_into()
            .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
    }

    async fn get_assertion_fido2(
        &self,
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let ctap2_request: Ctap2GetAssertionRequest = op.into();
        Ctap2Protocol::get_assertion(device, &ctap2_request, op.timeout).await
    }

    async fn get_assertion_u2f(
        &self,
        device: &mut T,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let ctap2_request: &Ctap2GetAssertionRequest = &op.into();
        let sign_request: SignRequest = ctap2_request
            .try_into()
            .or(Err(TransportError::NegotiationFailed))?;
        Ctap1Protocol::sign(device, &sign_request)
            .await?
            .try_into()
            .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
    }

    async fn _make_credential_pin_auth(
        &self,
        _device: &mut T,
        request: &mut Ctap2MakeCredentialRequest,
        get_info_response: &Ctap2GetInfoResponse,
    ) -> Result<(), Error> {
        if get_info_response.option_enabled("uv") {
            if get_info_response.option_enabled("pinUvAuthToken") {
                todo!("getPinUvAuthTokenUsingUvWithPermissions")
            } else {
                debug!("Deprecated FIDO 2.0 behaviour: populating 'uv' flag");
                request
                    .options
                    .unwrap()
                    .deprecated_require_user_verification = true;
                Ok(())
            }
        } else {
            // !uv
            if get_info_response.option_enabled("pinUvAuthToken") {
                assert!(get_info_response.option_enabled("clientPin"));
                todo!("getPinUvAuthTokenUsingPinWithPermissions")
            } else {
                // !pinUvAuthToken
                assert!(get_info_response.option_enabled("clientPin"));
                //let _token = self.get_pin_token(device).await?;
                // TODO sesett pinUvAuthToken
                Ok(())
            }
        }
    }

    async fn _get_pin_token(&self, _device: &mut T) -> Result<PinUvAuthToken, Error> {
        let _pin = self.pin_provider.provide_pin(None).await;
        todo!()
    }

    async fn negotiate_protocol(
        &self,
        device: &mut T,
        allow_u2f: bool,
    ) -> Result<FidoProtocol, Error> {
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
