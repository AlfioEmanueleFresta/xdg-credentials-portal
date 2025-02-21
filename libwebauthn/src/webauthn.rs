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
    Ctap2MakeCredentialRequest, Ctap2PinUvAuthProtocol, Ctap2UserVerifiableRequest,
    Ctap2UserVerificationOperation,
};
pub use crate::transport::error::{CtapError, Error, PlatformError, TransportError};
use crate::transport::{AuthTokenData, Channel, Ctap2AuthTokenPermission};

macro_rules! handle_errors {
    ($channel: expr, $resp: expr, $uv_auth_used: expr) => {
        match $resp {
            Err(Error::Ctap(CtapError::PINAuthInvalid))
                if $uv_auth_used == UsedPinUvAuthToken::FromStorage =>
            {
                info!("PINAuthInvalid: Clearing auth token storage and trying again.");
                $channel.clear_uv_auth_token_store();
                continue;
            }
            x => {
                break x;
            }
        }
    };
}
pub(crate) use handle_errors;

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
    async fn _negotiate_protocol(&mut self, allow_u2f: bool) -> Result<FidoProtocol, Error>;
}

pub(crate) async fn select_uv_proto(
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
        loop {
            let uv_auth_used = user_verification(
                self,
                op.user_verification,
                &mut ctap2_request,
                pin_provider,
                op.timeout,
            )
            .await?;
            handle_errors!(
                self,
                self.ctap2_make_credential(&ctap2_request, op.timeout).await,
                uv_auth_used
            )
        }
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
        let mut response = loop {
            let uv_auth_used = user_verification(
                self,
                op.user_verification,
                &mut ctap2_request,
                pin_provider,
                op.timeout,
            )
            .await?;

            if let Some(auth_data) = self.get_auth_data() {
                ctap2_request
                    .extensions
                    .as_mut()
                    .map(|e| e.calculate_hmac(auth_data));
            }

            handle_errors!(
                self,
                self.ctap2_get_assertion(&ctap2_request, op.timeout).await,
                uv_auth_used
            )
        }?;
        let count = response.credentials_count.unwrap_or(1);
        if let Some(auth_data) = self.get_auth_data() {
            response
                .authenticator_data
                .extensions
                .as_mut()
                .map(|x| x.decrypt_hmac_output(&auth_data));
        }
        let mut assertions = vec![response];
        for i in 1..count {
            debug!({ i }, "Fetching additional credential");
            // GetNextAssertion doesn't use PinUVAuthToken, so we don't need to check uv_auth_used here
            let mut response = self.ctap2_get_next_assertion(op.timeout).await?;
            if let Some(auth_data) = self.get_auth_data() {
                response
                    .authenticator_data
                    .extensions
                    .as_mut()
                    .map(|x| x.decrypt_hmac_output(&auth_data));
            }
            assertions.push(response);
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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum UsedPinUvAuthToken {
    FromStorage,
    NewlyCalculated,
    LegacyUV,
    None,
}

#[instrument(skip_all)]
pub(crate) async fn user_verification<R, C>(
    channel: &mut C,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    pin_provider: &Box<dyn PinProvider>,
    timeout: Duration,
) -> Result<UsedPinUvAuthToken, Error>
where
    C: Channel,
    R: Ctap2UserVerifiableRequest,
{
    let get_info_response = channel.ctap2_get_info().await?;
    ctap2_request.handle_legacy_preview(&get_info_response);
    let uv_proto = select_uv_proto(&get_info_response).await?;
    let token_identifier = Ctap2AuthTokenPermission::new(
        uv_proto.version(),
        ctap2_request.permissions(),
        ctap2_request.permissions_rpid(),
    );
    if let Some(uv_auth_token) = channel.get_uv_auth_token(&token_identifier) {
        ctap2_request.calculate_and_set_uv_auth(&uv_proto, uv_auth_token);
        Ok(UsedPinUvAuthToken::FromStorage)
    } else {
        user_verification_helper(
            channel,
            user_verification,
            ctap2_request,
            pin_provider,
            timeout,
        )
        .await
    }
}

#[instrument(skip_all)]
async fn user_verification_helper<R, C>(
    channel: &mut C,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    pin_provider: &Box<dyn PinProvider>,
    timeout: Duration,
) -> Result<UsedPinUvAuthToken, Error>
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
        return Ok(UsedPinUvAuthToken::None);
    }

    if !dev_uv_protected && user_verification.is_required() {
        error!(
            "Request requires user verification, but device user verification is not available."
        );
        return Err(Error::Ctap(CtapError::PINNotSet));
    };

    if !dev_uv_protected && user_verification.is_preferred() {
        warn!("User verification is preferred, but not device user verification is not available. Ignoring.");
        return Ok(UsedPinUvAuthToken::None);
    }

    let skip_uv = !ctap2_request.can_use_uv(&get_info_response);

    let mut uv_blocked = false;
    let (uv_proto, token_response, shared_secret, public_key) = loop {
        let uv_operation = get_info_response
            .uv_operation(uv_blocked || skip_uv)
            .ok_or_else(|| {
                if uv_blocked {
                    Error::Ctap(CtapError::UvBlocked)
                } else {
                    Error::Platform(PlatformError::NoUvAvailable)
                }
            })?;
        if let Ctap2UserVerificationOperation::None = uv_operation {
            debug!("No client operation. Setting deprecated request options.uv flag to true.");
            ctap2_request.ensure_uv_set();
            return Ok(UsedPinUvAuthToken::LegacyUV);
        }

        let uv_proto = select_uv_proto(&get_info_response).await?;
        // For operations that include a PIN, we want to fetch one before obtaining a shared secret.
        // This prevents the shared secret from expiring whilst we wait for the user to enter a PIN.
        let pin = match uv_operation {
            Ctap2UserVerificationOperation::None => unreachable!(),
            Ctap2UserVerificationOperation::GetPinToken
            | Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => Some(
                obtain_pin(
                    channel,
                    &get_info_response,
                    uv_proto.version(),
                    pin_provider,
                    timeout,
                )
                .await?,
            ),
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
                None // TODO probably?
            }
        };

        // In preparation for obtaining pinUvAuthToken, the platform:
        // * Obtains a shared secret.
        let (public_key, shared_secret) = obtain_shared_secret(channel, &uv_proto, timeout).await?;

        // Then the platform obtains a pinUvAuthToken from the authenticator, with the mc (and likely also with the ga)
        // permission (see "pre-flight", mentioned above), using the selected operation.
        let token_request = match uv_operation {
            Ctap2UserVerificationOperation::None => unreachable!(),
            Ctap2UserVerificationOperation::GetPinToken => {
                Ctap2ClientPinRequest::new_get_pin_token(
                    uv_proto.version(),
                    public_key.clone(),
                    &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
                )
            }
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => {
                Ctap2ClientPinRequest::new_get_pin_token_with_perm(
                    uv_proto.version(),
                    public_key.clone(),
                    &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
                    ctap2_request.permissions(),
                    ctap2_request.permissions_rpid(),
                )
            }
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
                Ctap2ClientPinRequest::new_get_uv_token_with_perm(
                    uv_proto.version(),
                    public_key.clone(),
                    ctap2_request.permissions(),
                    ctap2_request.permissions_rpid(),
                )
            }
        };

        match channel.ctap2_client_pin(&token_request, timeout).await {
            Ok(t) => {
                break (uv_proto, t, shared_secret, public_key);
            }
            // Internal retry, because we otherwise can't fall back to PIN, if the UV is blocked
            Err(Error::Ctap(CtapError::UvBlocked)) => {
                warn!("UV failed too many times and is now blocked. Trying to fall back to PIN.");
                uv_blocked = true;
                continue;
            }
            Err(x) => {
                return Err(x);
            }
        }
    };

    let Some(encrypted_pin_uv_auth_token) = token_response.pin_uv_auth_token else {
        error!("Client PIN response did not include a PIN UV auth token");
        return Err(Error::Ctap(CtapError::Other));
    };

    let uv_auth_token = uv_proto.decrypt(&shared_secret, &encrypted_pin_uv_auth_token)?;

    let token_identifier = Ctap2AuthTokenPermission::new(
        uv_proto.version(),
        ctap2_request.permissions(),
        ctap2_request.permissions_rpid(),
    );

    // Storing auth token for later (re)use, or for calculating HMAC secrects, etc.
    let auth_token_data = AuthTokenData {
        shared_secret: shared_secret.to_vec(),
        permission: token_identifier,
        pin_uv_auth_token: uv_auth_token.clone(),
        protocol_version: uv_proto.version(),
        key_agreement: public_key,
    };
    channel.store_auth_data(auth_token_data);

    // If successful, the platform creates the pinUvAuthParam parameter by calling
    // authenticate(pinUvAuthToken, clientDataHash), and goes to Step 1.1.1.
    // Sets the pinUvAuthProtocol parameter to the value as selected when it obtained the shared secret.
    ctap2_request.calculate_and_set_uv_auth(&uv_proto, uv_auth_token.as_slice());

    Ok(UsedPinUvAuthToken::NewlyCalculated)
}

pub(crate) async fn obtain_shared_secret<C>(
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

pub(crate) async fn obtain_pin<C>(
    channel: &mut C,
    info: &Ctap2GetInfoResponse,
    pin_proto: Ctap2PinUvAuthProtocol,
    pin_provider: &Box<dyn PinProvider>,
    timeout: Duration,
) -> Result<Vec<u8>, Error>
where
    C: Channel,
{
    // FIDO 2.0 requires PIN protocol, 2.1 does not anymore
    let pin_protocol = if info.supports_fido_2_1() {
        None
    } else {
        Some(pin_proto)
    };

    let attempts_left = channel
        .ctap2_client_pin(
            &Ctap2ClientPinRequest::new_get_pin_retries(pin_protocol),
            timeout,
        )
        .await
        .map(|x| x.pin_retries)
        .ok() // It's optional, so soft-error here
        .flatten();
    let Some(raw_pin) = pin_provider.provide_pin(attempts_left).await else {
        info!("User cancelled operation: no PIN provided");
        return Err(Error::Ctap(CtapError::PINRequired));
    };
    Ok(raw_pin.as_bytes().to_owned())
}
