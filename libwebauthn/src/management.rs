use serde_cbor::ser::to_vec;
use std::time::Duration;
use tracing::info;

use crate::pin::{PinProvider, PinUvAuthProtocol};
use crate::proto::ctap2::Ctap2AuthenticatorConfigCommand;
pub use crate::transport::error::{CtapError, Error, TransportError};
use crate::transport::Channel;
use crate::webauthn::handle_errors;
use crate::webauthn::{user_verification, UsedPinUvAuthToken};
use crate::{
    ops::webauthn::UserVerificationRequirement,
    proto::ctap2::{
        Ctap2, Ctap2AuthTokenPermissionRole, Ctap2AuthenticatorConfigRequest,
        Ctap2UserVerifiableRequest,
    },
};
use async_trait::async_trait;
use serde_bytes::ByteBuf;

#[async_trait]
pub trait AuthenticatorConfig {
    async fn toggle_always_uv(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn enable_enterprise_attestation(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn set_min_pin_length(
        &mut self,
        new_pin_length: u64,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn force_change_pin(
        &mut self,
        force: bool,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn set_min_pin_length_rpids(
        &mut self,
        rpids: Vec<String>,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<C> AuthenticatorConfig for C
where
    C: Channel,
{
    async fn toggle_always_uv(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2AuthenticatorConfigRequest::new_toggle_always_uv();

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used
            )
        }
    }

    async fn enable_enterprise_attestation(
        &mut self,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2AuthenticatorConfigRequest::new_enable_enterprise_attestation();

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used
            )
        }
    }

    async fn set_min_pin_length(
        &mut self,
        new_pin_length: u64,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2AuthenticatorConfigRequest::new_set_min_pin_length(new_pin_length);

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used
            )
        }
    }

    async fn force_change_pin(
        &mut self,
        force: bool,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2AuthenticatorConfigRequest::new_force_change_pin(force);

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used
            )
        }
    }

    async fn set_min_pin_length_rpids(
        &mut self,
        rpids: Vec<String>,
        pin_provider: &Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2AuthenticatorConfigRequest::new_set_min_pin_length_rpids(rpids);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used
            )
        }
    }
}

impl Ctap2UserVerifiableRequest for Ctap2AuthenticatorConfigRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        // pinUvAuthParam (0x04): the result of calling
        // authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
        let mut data = vec![0xff; 32];
        data.push(0x0D);
        data.push(self.subcommand as u8);
        if self.subcommand == Ctap2AuthenticatorConfigCommand::SetMinPINLength {
            data.extend(to_vec(&self.subcommand_params).unwrap());
        }
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data);
        self.protocol = Some(uv_proto.version());
        self.uv_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        unreachable!()
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        return Ctap2AuthTokenPermissionRole::AUTHENTICATOR_CONFIGURATION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }
}
