use std::convert::TryInto;

use async_trait::async_trait;
use tracing::{debug, info, instrument, trace, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::webauthn::{GetAssertionRequest, GetAssertionResponse};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::{
    Ctap2, Ctap2DowngradeCheck, Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest,
};
use crate::transport::error::{CtapError, Error, TransportError};
use crate::transport::Channel;

#[async_trait]
pub trait WebAuthn {
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
    async fn _webauthn_make_credential_fido2(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn _webauthn_make_credential_u2f(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;

    async fn _webauthn_get_assertion_fido2(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
    async fn _webauthn_get_assertion_u2f(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;

    async fn _negotiate_protocol(&mut self, allow_u2f: bool) -> Result<FidoProtocol, Error>;
}

#[async_trait]
impl<C> WebAuthn for C
where
    C: Channel,
{
    #[instrument(skip_all, fields(dev = %self))]
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        trace!(?op, "WebAuthn MakeCredential request");
        let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
        let protocol = self
            ._negotiate_protocol(ctap2_request.is_downgradable())
            .await?;
        match protocol {
            FidoProtocol::FIDO2 => self._webauthn_make_credential_fido2(op).await,
            FidoProtocol::U2F => self._webauthn_make_credential_u2f(op).await,
        }
    }

    #[instrument(skip_all, fields(dev = %self))]
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        trace!(?op, "WebAuthn GetAssertion request");
        let ctap2_request: &Ctap2GetAssertionRequest = &op.into();
        let protocol = self
            ._negotiate_protocol(ctap2_request.is_downgradable())
            .await?;
        match protocol {
            FidoProtocol::FIDO2 => self._webauthn_get_assertion_fido2(op).await,
            FidoProtocol::U2F => self._webauthn_get_assertion_u2f(op).await,
        }
    }

    async fn _webauthn_make_credential_fido2(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let ctap2_request: Ctap2MakeCredentialRequest = op.into();

        let get_info_response = self.ctap2_get_info().await?;

        let rp_uv_preferred = ctap2_request.is_uv_preferred();
        let dev_uv_protected = get_info_response.is_uv_protected();
        let uv = rp_uv_preferred || dev_uv_protected;
        debug!(%rp_uv_preferred, %dev_uv_protected, %uv, "Checking if user verification is required");

        /*
        if get_info_response.option_enabled("uv") {
            if get_info_response.option_enabled("pinUvAuthToken") {
                todo!("getPinUvAuthTokenUsingUvWithPermissions")
            } else {
                debug!("Deprecated FIDO 2.0 behaviour: populating 'uv' flag");
                ctap2_request.options = Some(Ctap2MakeCredentialOptions {
                    deprecated_require_user_verification: true,
                    ..ctap2_request.options.unwrap()
                });
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
            }
        }
        */

        if uv {
            unimplemented!("user verification");
        } else {
            // No user-verification.
            // ctap2_request.set_no_uv();
            // Don't do this - Yubikeys will fail if value is explicitly set to false.
        }

        self.ctap2_make_credential(&ctap2_request, op.timeout).await
    }

    async fn _webauthn_make_credential_u2f(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
        let register_request: RegisterRequest = ctap2_request
            .try_into()
            .or(Err(TransportError::NegotiationFailed))?;
        self.ctap1_register(&register_request)
            .await?
            .try_into()
            .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
    }

    async fn _webauthn_get_assertion_fido2(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let ctap2_request: Ctap2GetAssertionRequest = op.into();
        self.ctap2_get_assertion(&ctap2_request, op.timeout).await
    }

    async fn _webauthn_get_assertion_u2f(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let ctap2_request: &Ctap2GetAssertionRequest = &op.into();
        let sign_request: SignRequest = ctap2_request
            .try_into()
            .or(Err(TransportError::NegotiationFailed))?;
        self.ctap1_sign(&sign_request)
            .await?
            .try_into()
            .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
    }

    #[instrument(skip_all)]
    async fn _negotiate_protocol(&mut self, allow_u2f: bool) -> Result<FidoProtocol, Error> {
        let supported = self.supported_protocols().await?;
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
            self.ctap1_version().await?;
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
