use std::collections::HashMap;

use serde_bytes::ByteBuf;
use serde_indexed::DeserializeIndexed;
use tracing::debug;

use super::{Ctap2CredentialType, Ctap2UserVerificationOperation};

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetInfoResponse {
    /// versions (0x01)
    pub versions: Vec<String>,

    /// extensions (0x02)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,

    /// aaguid (0x03)
    pub aaguid: ByteBuf,

    /// options (0x04)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, bool>>,

    /// maxMsgSize (0x05)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msg_size: Option<u32>,

    /// pinUvAuthProtocols (0x06)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_protos: Option<Vec<u32>>,

    /// maxCredentialCountInList (0x07)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_credential_count: Option<u32>,

    /// maxCredentialIdLength (0x08)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_credential_id_length: Option<u32>,

    /// transports (0x09)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,

    /// algorithms (0x0A)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<Ctap2CredentialType>>,

    /// maxSerializedLargeBlobArray (0x0B)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_blob_array: Option<u32>,

    /// forcePINChange (0x0C)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_pin_change: Option<bool>,

    /// minPINLength (0x0D)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,

    /// firmwareVersion (0x0E)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<u32>,

    /// maxCredBlobLength (0x0F)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cred_blob_length: Option<u32>,

    /// maxRPIDsForSetMinPINLength (0x10)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rpids_for_setminpinlength: Option<u32>,

    /// preferredPlatformUvAttempts (0x11)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_platform_uv_attempts: Option<u32>,

    /// uvModality (0x12)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_modality: Option<u32>,

    /// certifications (0x13)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifications: Option<HashMap<String, u32>>,

    /// remainingDiscoverableCredentials (0x14)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_discoverable_creds: Option<u32>,

    /// vendorPrototypeConfigCommands (0x15)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_proto_config_cmds: Option<Vec<u32>>,

    /// attestationFormats (0x16)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<String>>,

    /// uvCountSinceLastPinEntry (0x17)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_count_since_last_pin_entry: Option<u32>,

    /// longTouchForReset (0x18)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_touch_for_reset: Option<bool>,

    /// encIdentifier (0x19)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_identifier: Option<ByteBuf>,

    /// transportsForReset (0x1A)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports_for_reset: Option<Vec<String>>,

    /// pinComplexityPolicy (0x1B)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_complexity_policy: Option<bool>,

    /// pinComplexityPolicyURL (0x1C)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_complexity_policy_url: Option<ByteBuf>,

    /// maxPINLength (0x1D)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pin_length: Option<u32>,
}

impl Ctap2GetInfoResponse {
    pub fn option_enabled(&self, name: &str) -> bool {
        if self.options.is_none() {
            return false;
        }
        let options = self.options.as_ref().unwrap();
        options.get(name) == Some(&true)
    }

    pub fn supports_fido_2_1(&self) -> bool {
        self.versions.iter().any(|v| v == "FIDO_2_1")
    }

    pub fn supports_credential_management(&self) -> bool {
        self.option_enabled("credMgmt") || self.option_enabled("credentialMgmtPreview")
    }

    pub fn supports_bio_enrollment(&self) -> bool {
        if let Some(options) = &self.options {
            return options.get("bioEnroll").is_some()
                || options.get("userVerificationMgmtPreview").is_some();
        }
        false
    }

    pub fn has_bio_enrollments(&self) -> bool {
        if let Some(options) = &self.options {
            return options.get("bioEnroll") == Some(&true)
                || options.get("userVerificationMgmtPreview") == Some(&true);
        }
        false
    }

    /// Implements check for "Protected by some form of User Verification":
    ///   Either or both clientPin or built-in user verification methods are supported and enabled.
    ///   I.e., in the authenticatorGetInfo response the pinUvAuthToken option ID is present and set to true,
    ///   and either clientPin option ID is present and set to true or uv option ID is present and set to true or both.
    pub fn is_uv_protected(&self) -> bool {
        self.option_enabled("uv") || // Deprecated no-op UV
            self.option_enabled("clientPin") ||
            (self.option_enabled("pinUvAuthToken") && self.option_enabled("uv"))
    }

    pub fn uv_operation(&self, uv_blocked: bool) -> Option<Ctap2UserVerificationOperation> {
        if self.option_enabled("uv") && !uv_blocked {
            if self.option_enabled("pinUvAuthToken") {
                debug!("getPinUvAuthTokenUsingUvWithPermissions");
                return Some(
                    Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
                );
            } else {
                debug!("Deprecated FIDO 2.0 behaviour: populating 'uv' flag");
                return Some(Ctap2UserVerificationOperation::None);
            }
        } else {
            // !uv
            if self.option_enabled("pinUvAuthToken") {
                assert!(self.option_enabled("clientPin"));
                debug!("getPinUvAuthTokenUsingPinWithPermissions");
                return Some(
                    Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions,
                );
            } else if self.option_enabled("clientPin") {
                // !pinUvAuthToken
                debug!("getPinToken");
                return Some(Ctap2UserVerificationOperation::GetPinToken);
            } else {
                debug!("No UV and no PIN (e.g. maybe UV was blocked and no PIN available)");
                return None;
            }
        }
    }
}
