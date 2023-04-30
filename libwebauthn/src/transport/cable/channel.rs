use std::{
    fmt::{Display, Formatter},
    time::Duration,
};

use async_trait::async_trait;
use tracing::instrument;

use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::Error;
use crate::transport::{channel::ChannelStatus, device::SupportedProtocols, Channel};

use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d mut CableQrCodeDevice<'d>),
    Known(&'d mut CableKnownDevice<'d>),
}

#[derive(Debug)]
pub struct CableChannel<'d> {
    // pub ws_stream: ??
    pub device: CableChannelDevice<'d>,
}

impl Drop for CableChannel<'_> {
    #[instrument(skip_all)]
    fn drop(&mut self) {
        todo!()
    }
}

impl Display for CableChannel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}

#[async_trait]
impl<'d> Channel for CableChannel<'d> {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        todo!()
    }

    async fn status(&self) -> ChannelStatus {
        todo!()
    }

    async fn close(&self) {
        todo!()
    }

    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error> {
        todo!()
    }

    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error> {
        todo!()
    }

    async fn cbor_send(&self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        todo!()
    }

    async fn cbor_recv(&self, timeout: Duration) -> Result<CborResponse, Error> {
        todo!()
    }
}
