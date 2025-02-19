use std::time::Duration;

use ctap_types::ctap2::credential_management::CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, trace};

use crate::{
    proto::{
        ctap1::{Ctap1RegisteredKey, Ctap1Version},
        ctap2::{
            Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2GetAssertionResponse,
            Ctap2MakeCredentialResponse, Ctap2PublicKeyCredentialDescriptor,
            Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
        },
    },
    webauthn::CtapError,
};

use super::u2f::{RegisterRequest, SignRequest};

// FIDO2 operations can be mapped by default to their respective CTAP2 requests.

pub type MakeCredentialResponse = Ctap2MakeCredentialResponse;

#[derive(Debug, Clone, Copy)]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

impl UserVerificationRequirement {
    /// Check if user verification is preferred or required for this request
    pub fn is_preferred(&self) -> bool {
        match self {
            Self::Required | Self::Preferred => true,
            Self::Discouraged => false,
        }
    }

    /// Check if user verification is strictly required for this request
    pub fn is_required(&self) -> bool {
        match self {
            Self::Required => true,
            Self::Preferred | Self::Discouraged => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    pub hash: Vec<u8>,
    pub origin: String,
    /// rpEntity
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,
    /// userEntity
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub require_resident_key: bool,
    pub user_verification: UserVerificationRequirement,
    /// credTypesAndPubKeyAlgs
    pub algorithms: Vec<Ctap2CredentialType>,
    /// excludeCredentialDescriptorList
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    /// extensions
    pub extensions: Option<MakeCredentialsRequestExtensions>,
    pub timeout: Duration,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialsRequestExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub cred_blob: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
}

impl MakeCredentialsRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.cred_protect.is_none()
            && self.cred_blob.is_none()
            && self.large_blob_key.is_none()
            && self.min_pin_length.is_none()
            && self.hmac_secret.is_none()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialsResponseExtensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    // If storing credBlob was successful
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,
    // No output provided for largeBlobKey in MakeCredential requests
    // pub large_blob_key: Option<bool>,

    // Current min PIN lenght
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,

    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<bool>,
}

impl MakeCredentialRequest {
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self {
            hash: vec![0; 32],
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            origin: "example.org".to_owned(),
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    pub relying_party_id: String,
    pub hash: Vec<u8>,
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
    pub extensions: Option<GetAssertionRequestExtensions>,
    pub user_verification: UserVerificationRequirement,
    pub timeout: Duration,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssertionRequestExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,
    // Thanks, FIDO-spec for this consistent naming scheme...
    // #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    // TODO: Do this properly with the salts
    // pub hmac_secret: Option<Vec<u8>>,
}

impl GetAssertionRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.cred_blob.is_none() /* && self.hmac_secret.is_none() */
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssertionResponseExtensions {
    // Stored credBlob
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub cred_blob: Option<Vec<u8>>,

    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub hmac_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct GetAssertionResponse {
    pub assertions: Vec<Ctap2GetAssertionResponse>,
}

impl From<&[Ctap2GetAssertionResponse]> for GetAssertionResponse {
    fn from(assertions: &[Ctap2GetAssertionResponse]) -> Self {
        Self {
            assertions: assertions.to_owned(),
        }
    }
}

impl From<Ctap2GetAssertionResponse> for GetAssertionResponse {
    fn from(assertion: Ctap2GetAssertionResponse) -> Self {
        Self {
            assertions: vec![assertion],
        }
    }
}

pub trait DowngradableRequest<T> {
    fn is_downgradable(&self) -> bool;
    fn try_downgrade(&self) -> Result<T, CtapError>;
}

impl DowngradableRequest<RegisterRequest> for MakeCredentialRequest {
    #[instrument(skip_all)]
    fn is_downgradable(&self) -> bool {
        // All of the below conditions must be true for the platform to proceed to next step.
        // If any of the below conditions is not true, platform errors out with CTAP2_ERR_UNSUPPORTED_OPTION

        // pubKeyCredParams must use the ES256 algorithm (-7).
        if !self
            .algorithms
            .iter()
            .any(|a| a.algorithm == Ctap2COSEAlgorithmIdentifier::ES256)
        {
            debug!("Not downgradable: request doesn't support ES256 algorithm");
            return false;
        }

        // Options must not include "rk" set to true.
        if self.require_resident_key {
            debug!("Not downgradable: request requires resident key");
            return false;
        }

        // Options must not include "uv" set to true.
        if let UserVerificationRequirement::Required = self.user_verification {
            debug!("Not downgradable: relying party (RP) requires user verification");
            return false;
        }

        true
    }

    fn try_downgrade(&self) -> Result<RegisterRequest, crate::webauthn::CtapError> {
        trace!(?self);
        let mut hasher = Sha256::default();
        hasher.update(self.relying_party.id.as_bytes());
        let rp_id_hash = hasher.finalize().to_vec();

        let downgraded = RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id_hash: rp_id_hash,
            challenge: self.hash.clone(),
            registered_keys: self
                .exclude
                .as_ref()
                .unwrap_or(&vec![])
                .into_iter()
                .map(|exclude| Ctap1RegisteredKey {
                    version: Ctap1Version::U2fV2,
                    key_handle: exclude.id.to_vec(),
                    transports: {
                        match &exclude.transports {
                            None => None,
                            Some(ctap2_transports) => {
                                let transports: Result<Vec<_>, _> =
                                    ctap2_transports.into_iter().map(|t| t.try_into()).collect();
                                transports.ok()
                            }
                        }
                    },
                    app_id: Some(self.relying_party.id.clone()),
                })
                .collect(),
            require_user_presence: true,
            timeout: self.timeout,
        };
        trace!(?downgraded);
        Ok(downgraded)
    }
}

impl DowngradableRequest<Vec<SignRequest>> for GetAssertionRequest {
    fn is_downgradable(&self) -> bool {
        // Options must not include "uv" set to true.
        if let UserVerificationRequirement::Required = self.user_verification {
            debug!("Not downgradable: relying party (RP) requires user verification");
            return false;
        }

        // allowList must have at least one credential.
        if self.allow.is_empty() {
            debug!("Not downgradable: allowList is empty.");
            return false;
        }

        true
    }

    fn try_downgrade(&self) -> Result<Vec<SignRequest>, CtapError> {
        trace!(?self);
        let downgraded_requests: Vec<SignRequest> = self
            .allow
            .iter()
            .map(|credential| {
                // Let controlByte be a byte initialized as follows:
                // * If "up" is set to false, set it to 0x08 (dont-enforce-user-presence-and-sign).
                // * For USB, set it to 0x07 (check-only). This should prevent call getting blocked on waiting for user
                //   input. If response returns success, then call again setting the enforce-user-presence-and-sign.
                // * For NFC, set it to 0x03 (enforce-user-presence-and-sign). The tap has already provided the presence
                //   and won’t block.
                // --> This is already set to 0x08 in trait: From<&Ctap1RegisterRequest> for ApduRequest

                // Use clientDataHash parameter of CTAP2 request as CTAP1/U2F challenge parameter (32 bytes).
                let challenge = &self.hash;

                // Let rpIdHash be a byte string of size 32 initialized with SHA-256 hash of rp.id parameter as
                // CTAP1/U2F application parameter (32 bytes).
                let mut hasher = Sha256::default();
                hasher.update(self.relying_party_id.as_bytes());
                let rp_id_hash = hasher.finalize().to_vec();

                // Let credentialId is the byte string initialized with the id for this PublicKeyCredentialDescriptor.
                let credential_id = &credential.id;

                // Let u2fAuthenticateRequest be a byte string with the following structure: [...]
                SignRequest::new_upgraded(&rp_id_hash, challenge, credential_id, self.timeout)
            })
            .collect();
        trace!(?downgraded_requests);
        Ok(downgraded_requests)
    }
}

#[cfg(test)]
mod tests {
    use crate::ops::webauthn::{
        DowngradableRequest, MakeCredentialRequest, UserVerificationRequirement,
    };
    use crate::proto::ctap2::{
        Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialType,
    };

    #[test]
    fn ctap2_make_credential_downgradable() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.require_resident_key = false;
        assert!(request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_rk() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.require_resident_key = true;
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_uv() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.user_verification = UserVerificationRequirement::Required;
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_algorithm() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::new(
            Ctap2PublicKeyCredentialType::PublicKey,
            Ctap2COSEAlgorithmIdentifier::EDDSA,
        )];
        assert!(!request.is_downgradable());
    }
}
