use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, info, instrument, trace, warn};

use ctap_types::cose::PublicKey;

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest, UpgradableResponse};
use crate::ops::webauthn::{
    DowngradableRequest, GetAssertionRequest, GetAssertionResponse, UserVerificationRequirement,
};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::pin::{
    pin_hash, PinProvider, PinUvAuthProtocol, PinUvAuthProtocolOne, PinUvAuthProtocolTwo,
};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2GetAssertionRequest, Ctap2GetInfoResponse,
    Ctap2MakeCredentialRequest, Ctap2UserVerifiableRequest, Ctap2UserVerificationOperation,
};
pub use crate::transport::error::{CtapError, Error, TransportError};
use crate::transport::Channel;

#[async_trait]
pub trait WebAuthn {
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<GetAssertionResponse, Error>;
    async fn _webauthn_make_credential_fido2(
        &mut self,
        op: &MakeCredentialRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn _webauthn_make_credential_u2f(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;

    async fn _webauthn_get_assertion_fido2(
        &mut self,
        op: &GetAssertionRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<GetAssertionResponse, Error>;
    async fn _webauthn_get_assertion_u2f(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
    async fn webauthn_change_pin(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        new_pin: String,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn _negotiate_protocol(&mut self, allow_u2f: bool) -> Result<FidoProtocol, Error>;
}

async fn select_uv_proto(
    get_info_response: &Ctap2GetInfoResponse,
) -> Result<Box<dyn PinUvAuthProtocol>, Error> {
    for &protocol in get_info_response.pin_auth_protos.iter().flatten() {
        match protocol {
            1 => return Ok(Box::new(PinUvAuthProtocolOne::new())),
            2 => return Ok(Box::new(PinUvAuthProtocolTwo::new())),
            _ => (),
        };
    }

    error!(?get_info_response.pin_auth_protos, "No supported PIN/UV auth protocols found");
    return Err(Error::Ctap(CtapError::Other));
}

#[async_trait]
impl<C> WebAuthn for C
where
    C: Channel,
{
    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<MakeCredentialResponse, Error> {
        trace!(?op, "WebAuthn MakeCredential request");
        let protocol = self._negotiate_protocol(op.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => self._webauthn_make_credential_fido2(op, pin_provider).await,
            FidoProtocol::U2F => self._webauthn_make_credential_u2f(op).await,
        }
    }

    async fn _webauthn_make_credential_fido2(
        &mut self,
        op: &MakeCredentialRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<MakeCredentialResponse, Error> {
        let mut ctap2_request: Ctap2MakeCredentialRequest = op.into();
        user_verification(
            self,
            op.user_verification,
            &mut ctap2_request,
            pin_provider,
            op.timeout,
        )
        .await?;
        self.ctap2_make_credential(&ctap2_request, op.timeout).await
    }

    async fn _webauthn_make_credential_u2f(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let register_request: RegisterRequest = op.try_downgrade()?;
        self.ctap1_register(&register_request)
            .await?
            .try_upgrade(op)
    }

    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<GetAssertionResponse, Error> {
        trace!(?op, "WebAuthn GetAssertion request");
        let protocol = self._negotiate_protocol(op.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => self._webauthn_get_assertion_fido2(op, pin_provider).await,
            FidoProtocol::U2F => self._webauthn_get_assertion_u2f(op).await,
        }
    }

    async fn _webauthn_get_assertion_fido2(
        &mut self,
        op: &GetAssertionRequest,
        pin_provider: &Box<dyn PinProvider>,
    ) -> Result<GetAssertionResponse, Error> {
        let mut ctap2_request: Ctap2GetAssertionRequest = op.into();
        user_verification(
            self,
            op.user_verification,
            &mut ctap2_request,
            pin_provider,
            op.timeout,
        )
        .await?;

        let response = self.ctap2_get_assertion(&ctap2_request, op.timeout).await?;
        let count = response.credentials_count.unwrap_or(1);
        let mut assertions = vec![response];
        for i in 1..count {
            debug!({ i }, "Fetching additional credential");
            assertions.push(self.ctap2_get_next_assertion(op.timeout).await?);
        }
        Ok(assertions.as_slice().into())
    }

    async fn _webauthn_get_assertion_u2f(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let sign_requests: Vec<SignRequest> = op.try_downgrade()?;

        for sign_request in sign_requests {
            match self.ctap1_sign(&sign_request).await {
                Ok(response) => {
                    debug!("Found successful candidate in allowList");
                    return response.try_upgrade(&sign_request);
                }
                Err(Error::Ctap(CtapError::NoCredentials)) => {
                    debug!("No credentials found, trying with the next.");
                }
                Err(err) => {
                    error!(
                        ?err,
                        "Unexpected error whilst trying each credential in allowList."
                    );
                    return Err(err);
                }
            }
        }
        warn!("None of the credentials in the original request's allowList were found.");
        Err(Error::Ctap(CtapError::NoCredentials))
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
            debug!("Selected protocol: {:?}", fido_protocol);
        }
        Ok(fido_protocol)
    }

    async fn webauthn_change_pin(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        new_pin: String,
        timeout: Duration,
    ) -> Result<(), Error> {
        let get_info_response = self.ctap2_get_info().await?;

        // If the minPINLength member of the authenticatorGetInfo response is absent, then let platformMinPINLengthInCodePoints be 4.
        if new_pin.as_bytes().len() < get_info_response.min_pin_length.unwrap_or(4) as usize {
            // If platformCollectedPinLengthInCodePoints is less than platformMinPINLengthInCodePoints then the platform SHOULD display a "PIN too short" error message to the user.
            // TODO: New error for "PIN too short" vs. "PIN too long"?
            return Err(Error::Ctap(CtapError::PINPolicyViolation));
        }

        // If the byte length of "newPin" is greater than the max UTF-8 representation limit of 63 bytes, then the platform SHOULD display a "PIN too long" error message to the user.
        if new_pin.as_bytes().len() >= 64 {
            // TODO: New error for "PIN too short" vs. "PIN too long"?
            return Err(Error::Ctap(CtapError::PINPolicyViolation));
        }

        let current_pin = match get_info_response.options.as_ref().unwrap().get("clientPin") {
            // Obtaining the current PIN, if one is set
            Some(true) => Some(obtain_pin(self, pin_provider, timeout).await?),

            // No PIN set yet
            Some(false) => None,

            // Device does not support PIN
            None => {
                // TODO: What's the correct error here? Spec is unclear. Maybe just not early-return and let the device error out for us.
                return Err(Error::Ctap(CtapError::UnsupportedOption));
            }
        };

        // In preparation for obtaining pinUvAuthToken, the platform:
        // * Obtains a shared secret.
        let uv_proto = select_uv_proto(&get_info_response).await?;
        let (public_key, shared_secret) = obtain_shared_secret(self, &uv_proto, timeout).await?;

        // paddedPin is newPin padded on the right with 0x00 bytes to make it 64 bytes long. (Since the maximum length of newPin is 63 bytes, there is always at least one byte of padding.)
        let mut padded_new_pin = new_pin.as_bytes().to_vec();
        padded_new_pin.resize(64, 0x00);

        // newPinEnc: the result of calling encrypt(shared secret, paddedPin) where
        let new_pin_enc = uv_proto.encrypt(&shared_secret, &padded_new_pin)?;

        let req = match current_pin {
            Some(curr_pin) => {
                // pinHashEnc: The result of calling encrypt(shared secret, LEFT(SHA-256(curPin), 16)).
                let pin_hash = pin_hash(&curr_pin);
                let pin_hash_enc = uv_proto.encrypt(&shared_secret, &pin_hash)?;

                // pinUvAuthParam: the result of calling authenticate(shared secret, newPinEnc || pinHashEnc)
                let uv_auth_param = uv_proto.authenticate(
                    &shared_secret,
                    &[new_pin_enc.as_slice(), pin_hash_enc.as_slice()].concat(),
                );

                Ctap2ClientPinRequest::new_change_pin(
                    uv_proto.version(),
                    &new_pin_enc,
                    &pin_hash_enc,
                    public_key,
                    &uv_auth_param,
                )
            }
            None => {
                // pinUvAuthParam: the result of calling authenticate(shared secret, newPinEnc).
                let uv_auth_param = uv_proto.authenticate(&shared_secret, &new_pin_enc);

                Ctap2ClientPinRequest::new_set_pin(
                    uv_proto.version(),
                    &new_pin_enc,
                    public_key,
                    &uv_auth_param,
                )
            }
        };

        // On success, this is an all-empty Ctap2ClientPinResponse
        let _ = self.ctap2_client_pin(&req, timeout).await?;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn user_verification<R, C>(
    channel: &mut C,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    pin_provider: &Box<dyn PinProvider>,
    timeout: Duration,
) -> Result<(), Error>
where
    C: Channel,
    R: Ctap2UserVerifiableRequest,
{
    let get_info_response = channel.ctap2_get_info().await?;

    let rp_uv_preferred = user_verification.is_preferred();
    let dev_uv_protected = get_info_response.is_uv_protected();
    let uv = rp_uv_preferred || dev_uv_protected;
    debug!(%rp_uv_preferred, %dev_uv_protected, %uv, "Checking if user verification is required");

    if !uv {
        debug!("User verification not requested by either RP nor authenticator. Ignoring.");
        return Ok(());
    }

    if !dev_uv_protected && user_verification.is_required() {
        error!(
            "Request requires user verification, but device user verification is not available."
        );
        return Err(Error::Ctap(CtapError::PINNotSet));
    };

    if !dev_uv_protected && user_verification.is_preferred() {
        warn!("User verification is preferred, but not device user verification is not available. Ignoring.");
        return Ok(());
    }

    let uv_operation = get_info_response.uv_operation();
    if let Ctap2UserVerificationOperation::None = uv_operation {
        debug!("No client operation. Setting deprecated request options.uv flag to true.");
        ctap2_request.ensure_uv_set();
        return Ok(());
    }

    // For operations that include a PIN, we want to fetch one before obtaining a shared secret.
    // This prevents the shared secret from expiring whilst we wait for the user to enter a PIN.
    let pin = match uv_operation {
        Ctap2UserVerificationOperation::None => unreachable!(),
        Ctap2UserVerificationOperation::GetPinToken
        | Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => {
            Some(obtain_pin(channel, pin_provider, timeout).await?)
        }
        Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
            None // TODO probably?
        }
    };

    // In preparation for obtaining pinUvAuthToken, the platform:
    // * Obtains a shared secret.
    let uv_proto = select_uv_proto(&get_info_response).await?;
    let (public_key, shared_secret) = obtain_shared_secret(channel, &uv_proto, timeout).await?;

    // Then the platform obtains a pinUvAuthToken from the authenticator, with the mc (and likely also with the ga)
    // permission (see "pre-flight", mentioned above), using the selected operation.
    let token_request = match uv_operation {
        Ctap2UserVerificationOperation::None => unreachable!(),
        Ctap2UserVerificationOperation::GetPinToken => Ctap2ClientPinRequest::new_get_pin_token(
            uv_proto.version(),
            public_key,
            &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
        ),
        Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => {
            Ctap2ClientPinRequest::new_get_pin_token_with_perm(
                uv_proto.version(),
                public_key,
                &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
                ctap2_request.permissions(),
                ctap2_request.permissions_rpid(),
            )
        }
        Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
            Ctap2ClientPinRequest::new_get_uv_token_with_perm(
                uv_proto.version(),
                public_key,
                ctap2_request.permissions(),
                ctap2_request.permissions_rpid(),
            )
        }
    };

    let token_response = channel.ctap2_client_pin(&token_request, timeout).await?;
    let Some(encrypted_pin_uv_auth_token) = token_response.pin_uv_auth_token else {
        error!("Client PIN response did not include a PIN UV auth token");
        return Err(Error::Ctap(CtapError::Other));
    };

    // If successful, the platform creates the pinUvAuthParam parameter by calling
    // authenticate(pinUvAuthToken, clientDataHash), and goes to Step 1.1.1.
    let uv_auth_token = uv_proto.decrypt(&shared_secret, &encrypted_pin_uv_auth_token)?;
    let uv_auth_param =
        uv_proto.authenticate(uv_auth_token.as_slice(), ctap2_request.client_data_hash());

    // Sets the pinUvAuthProtocol parameter to the value as selected when it obtained the shared secret.
    ctap2_request.set_uv_auth(uv_proto.version(), uv_auth_param.as_slice());

    Ok(())
}

async fn obtain_shared_secret<C>(
    channel: &mut C,
    pin_proto: &Box<dyn PinUvAuthProtocol>,
    timeout: Duration,
) -> Result<(PublicKey, Vec<u8>), Error>
where
    C: Channel,
{
    let client_pin_request = Ctap2ClientPinRequest::new_get_key_agreement(pin_proto.version());
    let client_pin_response = channel
        .ctap2_client_pin(&client_pin_request, timeout)
        .await?;
    let Some(public_key) = client_pin_response.key_agreement else {
        error!("Missing public key from Client PIN response");
        return Err(Error::Ctap(CtapError::Other));
    };
    pin_proto.encapsulate(&public_key)
}

async fn obtain_pin<C>(
    channel: &mut C,
    pin_provider: &Box<dyn PinProvider>,
    timeout: Duration,
) -> Result<Vec<u8>, Error>
where
    C: Channel,
{
    let attempts_left = channel
        .ctap2_client_pin(&Ctap2ClientPinRequest::new_get_pin_retries(), timeout)
        .await?
        .pin_retries;
    let Some(raw_pin) = pin_provider.provide_pin(attempts_left).await else {
        info!("User cancelled operation: no PIN provided");
        return Err(Error::Ctap(CtapError::PINRequired));
    };
    Ok(raw_pin.as_bytes().to_owned())
}
