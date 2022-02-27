use std::convert::TryInto;

use async_trait::async_trait;
use serde_bytes::ByteBuf;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::webauthn::{GetAssertionRequest, GetAssertionResponse};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::pin::{pin_hash, PinUvAuthProtocol, PinUvAuthProtocolOne};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2DowngradeCheck, Ctap2GetAssertionRequest,
    Ctap2GetInfoResponse, Ctap2MakeCredentialRequest, Ctap2UserVerificationOperation,
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

async fn select_pin_proto(
    get_info_response: &Ctap2GetInfoResponse,
) -> Result<Box<dyn PinUvAuthProtocol + Send>, Error> {
    for &protocol in get_info_response.pin_auth_protos.iter().flatten() {
        match protocol {
            1 => return Ok(Box::new(PinUvAuthProtocolOne::new())),
            _ => (),
        };
    }

    error!("No supported PIN/UV auth protocols found");
    return Err(Error::Ctap(CtapError::Other));
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
        let mut ctap2_request: Ctap2MakeCredentialRequest = op.into();

        let get_info_response = self.ctap2_get_info().await?;

        let rp_uv_preferred = ctap2_request.is_uv_preferred();
        let dev_uv_protected = get_info_response.is_uv_protected();
        let uv = rp_uv_preferred || dev_uv_protected;
        debug!(%rp_uv_preferred, %dev_uv_protected, %uv, "Checking if user verification is required");

        if uv {
            let uv_operation = get_info_response.uv_operation();
            if let Ctap2UserVerificationOperation::None = uv_operation {
                debug!("No client operation. Setting deprecated request options.uv flag to true.");
                ctap2_request.ensure_uv_set();
            } else {
                // In preparation for obtaining pinUvAuthToken, the platform:
                // * Obtains a shared secret.
                let pin_proto = select_pin_proto(&get_info_response).await?;
                let client_pin_request =
                    Ctap2ClientPinRequest::new_get_key_agreement(pin_proto.version());
                let client_pin_response = self
                    .ctap2_client_pin(&client_pin_request, op.timeout)
                    .await?;
                let Some(public_key) = client_pin_response.key_agreement else {
                    error!("Missing public key from Client PIN response");
                    return Err(Error::Ctap(CtapError::Other));
                };
                let (public_key, shared_secret) = pin_proto.encapsulate(&public_key)?;

                // * Sets the pinUvAuthProtocol parameter to the value as selected when it obtained the shared secret.
                ctap2_request.pin_auth_proto = Some(pin_proto.version() as u32);

                // Then the platform obtains a pinUvAuthToken from the authenticator, with the mc (and likely also with the ga)
                // permission (see "pre-flight", mentioned above), using the selected operation. If successful, the platform
                // creates the pinUvAuthParam parameter by calling authenticate(pinUvAuthToken, clientDataHash), and goes
                // to Step 1.1.1.
                let encrypted_pin_uv_auth_token = match uv_operation {
                    Ctap2UserVerificationOperation::GetPinToken => {
                        let raw_pin = "0000".as_bytes(); // TODO pin input
                        let token_request = Ctap2ClientPinRequest::new_get_pin_token(
                            pin_proto.version(),
                            public_key,
                            &pin_proto.encrypt(&shared_secret, &pin_hash(raw_pin))?,
                        );
                        let token_response =
                            self.ctap2_client_pin(&token_request, op.timeout).await?;
                        let Some(pin_uv_auth_token) = token_response.pin_uv_auth_token else {
                            error!("Client PIN response did not include a PIN UV auth token");
                            return Err(Error::Ctap(CtapError::Other));
                        };
                        pin_uv_auth_token
                    }
                    _ => unimplemented!(), // TODO
                };

                // The spec don't say this very explicitly... but the token comes encrypted.
                let pin_uv_auth_token =
                    pin_proto.decrypt(&shared_secret, &encrypted_pin_uv_auth_token)?;

                let pin_auth_param = pin_proto
                    .authenticate(pin_uv_auth_token.as_slice(), ctap2_request.hash.as_slice());
                ctap2_request.pin_auth_param = Some(ByteBuf::from(pin_auth_param.as_slice()));
            }
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
