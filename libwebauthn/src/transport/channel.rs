use std::fmt::{Debug, Display};
use std::time::Duration;

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
pub trait Channel: Send + Sync + Display {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error>;
    async fn status(&self) -> ChannelStatus;
    async fn close(&mut self);

    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error>;
    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error>;

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error>;
    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error>;
}
