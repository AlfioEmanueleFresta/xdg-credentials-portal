extern crate async_trait;
extern crate bitflags;
extern crate hidapi;
extern crate log;
extern crate rand;
extern crate tokio;

use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use hidapi::DeviceInfo;
use hidapi::HidApi;
use log::{debug, warn};
use tokio::time::{sleep, timeout as tokio_timeout};

use core::time;
use rand::{thread_rng, Rng};
use serde_cbor::{from_slice, ser::to_vec_packed, to_vec};
use std::{
    convert::TryFrom,
    io::{Cursor as IOCursor, Seek, SeekFrom},
};
use std::{fmt, time::Duration};

use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};
use crate::proto::ctap1::{Ctap1VersionRequest, Ctap1VersionResponse};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::ctap2::Ctap2GetInfoResponse;
use crate::proto::ctap2::{Ctap2CommandCode, Ctap2DowngradeCheck};
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
use crate::proto::ctap2::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
use crate::{
    ops::u2f,
    proto::ctap1::apdu::{ApduRequest, ApduResponse, ApduResponseStatus},
};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};
use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::fido::FidoProtocol;

use super::framing::{HidCommand, HidMessage, HidMessageParser, HidMessageParserState};

use crate::transport::device::{FidoDevice, SupportedProtocols};
use crate::transport::error::{CtapError, Error, TransportError};

const INIT_NONCE_LEN: usize = 8;
const INIT_PAYLOAD_LEN: usize = 17;
const INIT_TIMEOUT: Duration = Duration::from_millis(200);

const UP_SLEEP: Duration = Duration::from_millis(150);
const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0x00;

#[derive(Debug, Clone)]
pub struct HidFidoDevice {
    hidapi_device: DeviceInfo,
    init: Option<InitResponse>,
}

#[derive(Debug, Clone, Copy)]
pub struct InitResponse {
    pub cid: u32,
    pub protocol_version: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub caps: Caps,
}

bitflags! {
    pub struct Caps: u8 {
        const WINK = 0x01;
        const CBOR = 0x04;
        const NO_MSG = 0x08;
    }
}

impl From<&DeviceInfo> for HidFidoDevice {
    fn from(hidapi_device: &DeviceInfo) -> Self {
        Self {
            hidapi_device: hidapi_device.clone(),
            init: None,
        }
    }
}

impl Into<DeviceInfo> for &HidFidoDevice {
    fn into(self) -> DeviceInfo {
        self.hidapi_device.clone()
    }
}

impl fmt::Display for HidFidoDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:} {:} (r{:?})",
            self.hidapi_device.manufacturer_string().unwrap(),
            self.hidapi_device.product_string().unwrap(),
            self.hidapi_device.release_number()
        )
    }
}

fn get_hidapi() -> Result<HidApi, Error> {
    HidApi::new().or(Err(Error::Transport(TransportError::TransportUnavailable)))
}

pub async fn list_devices() -> Result<Vec<HidFidoDevice>, Error> {
    Ok(get_hidapi()?
        .device_list()
        .into_iter()
        .filter(|device| device.usage_page() == 0xF1D0)
        .filter(|device| device.usage() == 0x0001)
        .map(|device| device.into())
        .collect())
}

impl HidFidoDevice {
    pub async fn wink(&mut self, timeout: Duration) -> Result<bool, Error> {
        self.init(timeout).await?;

        if !self.init.unwrap().caps.contains(Caps::WINK) {
            warn!("WINK capability is not supported by device: {}", self);
            return Ok(false);
        }

        self.hid_transact(
            &HidMessage::new(self.init.unwrap().cid, HidCommand::Wink, &[]),
            timeout,
        )
        .await?;
        Ok(true)
    }

    async fn init(&mut self, timeout: Duration) -> Result<(), Error> {
        if self.init.is_some() {
            // FIXME does the channel expire?
            debug!("Device {:} already init.", self);
            return Ok(());
        }

        let nonce: [u8; 8] = thread_rng().gen();
        let request = HidMessage::broadcast(HidCommand::Init, &nonce);
        let response = self.hid_transact(&request, timeout).await?;

        if response.cmd != HidCommand::Init {
            warn!("Invalid response to INIT request: {:?}", response.cmd);
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        if response.payload.len() < INIT_PAYLOAD_LEN {
            warn!(
                "INIT payload is too small ({} bytes)",
                response.payload.len()
            );
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        if response.payload[0..INIT_NONCE_LEN] != nonce[0..INIT_NONCE_LEN] {
            warn!("INIT nonce mismatch. Terminating.");
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        let mut cursor = IOCursor::new(response.payload);
        cursor.seek(SeekFrom::Start(8)).unwrap();

        let init = InitResponse {
            cid: cursor.read_u32::<BigEndian>().unwrap(),
            protocol_version: cursor.read_u8().unwrap(),
            version_major: cursor.read_u8().unwrap(),
            version_minor: cursor.read_u8().unwrap(),
            version_build: cursor.read_u8().unwrap(),
            caps: Caps::from_bits_truncate(cursor.read_u8().unwrap()),
        };
        debug!("Device {:} INIT response: {:?}", self, &init);
        self.init = Some(init);

        Ok(())
    }

    async fn hid_transact(&self, msg: &HidMessage, timeout: Duration) -> Result<HidMessage, Error> {
        let hidapi = get_hidapi()?;
        let hidapi_device = self
            .hidapi_device
            .open_device(&hidapi)
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;

        debug!("U2F HID request to {:}: {:?}", self, msg);
        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for packet in packets {
            let mut report: Vec<u8> = vec![REPORT_ID];
            report.extend(&packet);
            report.extend(vec![0; PACKET_SIZE - packet.len()]);
            debug!(
                "Sending HID report to {:} ({:} bytes): {:?}",
                self,
                report.len(),
                report
            );
            hidapi_device.write(&report).unwrap();
        }

        let mut parser = HidMessageParser::new();
        loop {
            let mut report = [0; PACKET_SIZE];
            hidapi_device
                .read_timeout(&mut report, timeout.as_millis() as i32)
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
            debug!("Received HID report from {:}: {:?}", self, report);
            if let HidMessageParserState::Done = parser
                .update(&report)
                .or(Err(Error::Transport(TransportError::InvalidFraming)))?
            {
                break;
            }
        }

        let response = parser
            .message()
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        debug!("U2F HID response from {:}: {:?}", self, response);
        Ok(response)
    }
}

#[async_trait]
impl FidoDevice for HidFidoDevice {
    async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
        self.init(INIT_TIMEOUT).await?;

        let init = self.init.unwrap();
        let cbor_supported = init.caps.contains(Caps::CBOR);
        let apdu_supported = !init.caps.contains(Caps::NO_MSG);
        Ok(SupportedProtocols {
            u2f: apdu_supported,
            fido2: cbor_supported,
        })
    }

    async fn send_apdu_request(
        &mut self,
        request: &crate::proto::ctap1::apdu::ApduRequest,
        timeout: std::time::Duration,
    ) -> Result<crate::proto::ctap1::apdu::ApduResponse, Error> {
        self.init(INIT_TIMEOUT).await?;

        let cid = self.init.unwrap().cid;
        debug!(
            "Sending APDU request to {} (cid: {}): {:?}",
            self, cid, request
        );
        let apdu_raw = request.raw_long().unwrap();
        let hid_response = self
            .hid_transact(&HidMessage::new(cid, HidCommand::Msg, &apdu_raw), timeout)
            .await?;
        let apdu_response = ApduResponse::try_from(&hid_response.payload)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;

        debug!("Received APDU response: {:?}", apdu_response);
        Ok(apdu_response)
    }

    //     if let None = self.init {
    //         self.init().await?;
    //         assert!(self.init.is_some());
    //     }

    //     tokio_timeout(timeout, async {
    //         loop {
    //             let apdu_response = self.send_ctap1_request_single(request).await?;
    //             let apdu_status = apdu_response
    //                 .status()
    //                 .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
    //             let ctap_error: CtapError = apdu_status.into();
    //             match ctap_error {
    //                 CtapError::Ok => return Ok(apdu_response),
    //                 CtapError::UserPresenceRequired => (), // Sleep some more.
    //                 _ => return Err(Error::Ctap(ctap_error)),
    //             };
    //             debug!("UP required. Sleeping for {:?}.", UP_SLEEP);
    //             sleep(UP_SLEEP).await;
    //         }
    //     })
    //     .await
    //     .or(Err(Error::Ctap(CtapError::UserActionTimeout)))?
    // }

    async fn send_cbor_request(
        &mut self,
        request: &CborRequest,
        timeout: Duration,
    ) -> Result<CborResponse, Error> {
        self.init(INIT_TIMEOUT).await?;

        let cid = self.init.unwrap().cid;
        debug!(
            "Sending CBOR request to {} (cid: {}): {:?}",
            self, cid, request
        );
        let hid_response = self
            .hid_transact(
                &HidMessage::new(cid, HidCommand::Cbor, &request.ctap_hid_data()),
                timeout,
            )
            .await?;
        let cbor_response = CborResponse::try_from(&hid_response.payload)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;

        debug!("Received CBOR response: {:?}", cbor_response);
        Ok(cbor_response)
    }
}
