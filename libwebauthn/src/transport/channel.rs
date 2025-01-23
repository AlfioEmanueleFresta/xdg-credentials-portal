use std::fmt::{Debug, Display};
use std::time::Duration;

use crate::proto::ctap2::{ClientPinRequestPermissions, Ctap2PinUvAuthProtocol};
use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::Error;

use async_trait::async_trait;

use super::device::SupportedProtocols;

#[derive(Debug, Copy, Clone)]
pub enum ChannelStatus {
    Ready, // Channels are created asynchrounously, and are always ready.
    Processing,
    Closed,
}

#[async_trait]
pub trait Channel: Send + Sync + Display + Ctap2AuthTokenStore {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error>;
    async fn status(&self) -> ChannelStatus;
    async fn close(&mut self);

    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error>;
    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error>;

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error>;
    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctap2AuthTokenIdentifier {
    pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
    permissions: ClientPinRequestPermissions,
    permissions_rpid: Option<String>,
}

impl Ctap2AuthTokenIdentifier {
    pub fn new(
        pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
        permissions: ClientPinRequestPermissions,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            pin_uv_auth_protocol,
            permissions,
            permissions_rpid: permissions_rpid.map(str::to_string),
        }
    }

    pub fn is_satisfied_by(&self, other: &Ctap2AuthTokenIdentifier) -> bool {
        if self.pin_uv_auth_protocol != other.pin_uv_auth_protocol {
            return false;
        }
        if self.permissions_rpid != other.permissions_rpid {
            return false;
        }
        self.permissions.contains(other.permissions)
    }
}

#[async_trait]
pub trait Ctap2AuthTokenStore {
    fn store_uv_auth_token(
        &mut self,
        identifier: Ctap2AuthTokenIdentifier,
        pin_uv_auth_token: &[u8],
    );
    fn get_uv_auth_token(&self, identifier: &Ctap2AuthTokenIdentifier) -> Option<&[u8]>;
    fn clear_uv_auth_token_store(&mut self);
}
