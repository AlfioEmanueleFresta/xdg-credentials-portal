extern crate async_trait;

use std::time::Duration;

use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::Error;

use async_trait::async_trait;

#[derive(Debug, Copy, Clone)]
pub struct SupportedProtocols {
    pub u2f: bool, // Can be split into U2F revisions, if needed.
    pub fido2: bool,
}

#[async_trait]
pub trait FidoDevice {
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error>;

    async fn send_apdu_request(
        &mut self,
        _: &ApduRequest,
        _: Duration,
    ) -> Result<ApduResponse, Error>;

    async fn send_cbor_request(
        &mut self,
        _: &CborRequest,
        _: Duration,
    ) -> Result<CborResponse, Error>;
}
