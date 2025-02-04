use crate::{
    ops::webauthn::UserVerificationRequirement,
    pin::{PinProvider, PinUvAuthProtocol},
    proto::ctap2::{
        Ctap2, Ctap2AuthTokenPermissionRole, Ctap2CredentialData,
        Ctap2CredentialManagementMetadata, Ctap2CredentialManagementRequest, Ctap2GetInfoResponse,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
        Ctap2PublicKeyCredentialUserEntity, Ctap2UserVerifiableRequest,
    },
    transport::{
        error::{CtapError, Error},
        Channel,
    },
    webauthn::{handle_errors, user_verification, UsedPinUvAuthToken},
};
use async_trait::async_trait;
use serde_bytes::ByteBuf;
use serde_cbor::ser::to_vec;
use std::time::Duration;
use tracing::info;

#[async_trait]
pub trait CredentialManagement {
    async fn get_credential_metadata(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementMetadata, Error>;
    async fn enumerate_rps_begin(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(Ctap2PublicKeyCredentialRpEntity, ByteBuf, u64), Error>;
    async fn enumerate_rps_next_rp(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(Ctap2PublicKeyCredentialRpEntity, ByteBuf), Error>;
    async fn enumerate_credentials_begin(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        rpid_hash: ByteBuf,
        timeout: Duration,
    ) -> Result<(Ctap2CredentialData, u64), Error>;
    async fn enumerate_credentials_next(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<Ctap2CredentialData, Error>;
    async fn delete_credential(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn update_user_info(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        user: &Ctap2PublicKeyCredentialUserEntity,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<C> CredentialManagement for C
where
    C: Channel,
{
    async fn get_credential_metadata(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementMetadata, Error> {
        let mut req = Ctap2CredentialManagementRequest::new_get_credential_metadata();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        let metadata = Ctap2CredentialManagementMetadata::new(
            resp.existing_resident_credentials_count.unwrap(),
            resp.max_possible_remaining_resident_credentials_count
                .unwrap(),
        );
        Ok(metadata)
    }

    async fn enumerate_rps_begin(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(Ctap2PublicKeyCredentialRpEntity, ByteBuf, u64), Error> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_rps_begin();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        Ok((
            resp.rp.unwrap(),
            resp.rp_id_hash.unwrap(),
            resp.total_rps.unwrap(),
        ))
    }

    async fn enumerate_rps_next_rp(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(Ctap2PublicKeyCredentialRpEntity, ByteBuf), Error> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_rps_next_rp();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        Ok((resp.rp.unwrap(), resp.rp_id_hash.unwrap()))
    }

    async fn enumerate_credentials_begin(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        rpid_hash: ByteBuf,
        timeout: Duration,
    ) -> Result<(Ctap2CredentialData, u64), Error> {
        let mut req =
            Ctap2CredentialManagementRequest::new_enumerate_credentials_begin(rpid_hash.as_slice());
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        let cred = Ctap2CredentialData::new(
            resp.user.unwrap(),
            resp.credential_id.unwrap(),
            resp.public_key.unwrap(),
            resp.cred_protect.unwrap(),
            resp.large_blob_key.unwrap(),
        );
        let total_creds = resp.total_credentials.unwrap();
        Ok((cred, total_creds))
    }

    async fn enumerate_credentials_next(
        &mut self,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<Ctap2CredentialData, Error> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_credentials_next();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        let cred = Ctap2CredentialData::new(
            resp.user.unwrap(),
            resp.credential_id.unwrap(),
            resp.public_key.unwrap(),
            resp.cred_protect.unwrap(),
            resp.large_blob_key.unwrap(),
        );
        Ok(cred)
    }

    async fn delete_credential(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2CredentialManagementRequest::new_delete_credential(credential_id);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        Ok(())
    }

    async fn update_user_info(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        user: &Ctap2PublicKeyCredentialUserEntity,
        pin_provider: &mut Box<dyn PinProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req =
            Ctap2CredentialManagementRequest::new_update_user_information(credential_id, user);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used
            )
        }?;
        Ok(())
    }
}

impl Ctap2UserVerifiableRequest for Ctap2CredentialManagementRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        let mut data = vec![self.subcommand.unwrap() as u8];

        // e.g. pinUvAuthParam (0x04): authenticate(pinUvAuthToken, enumerateCredentialsBegin (0x04) || subCommandParams).
        if let Some(params) = &self.subcommand_params {
            data.extend(to_vec(params).unwrap());
        }
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data);
        self.protocol = Some(uv_proto.version());
        self.uv_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        unreachable!()
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        return Ctap2AuthTokenPermissionRole::CREDENTIAL_MANAGEMENT;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }
}
