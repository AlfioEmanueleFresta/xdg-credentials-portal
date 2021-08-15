extern crate async_std;
extern crate async_trait;
extern crate bitflags;
extern crate hidapi;
extern crate log;
extern crate rand;
extern crate tokio;

use async_std::net::UdpSocket;
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use hidapi::DeviceInfo;
use hidapi::HidApi;
use hidapi::HidDevice;
use log::{debug, warn};
use tokio::time::sleep;

use rand::{thread_rng, Rng};
use std::fmt;
use std::time::Duration;
use std::{
    convert::TryFrom,
    io::{Cursor as IOCursor, Seek, SeekFrom},
};

use crate::proto::ctap1::apdu::ApduResponse;
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};

use super::framing::{HidCommand, HidMessage, HidMessageParser, HidMessageParserState};

use crate::transport::device::{FidoDevice, SupportedProtocols};
use crate::transport::error::{Error, TransportError};

const INIT_NONCE_LEN: usize = 8;
const INIT_PAYLOAD_LEN: usize = 17;
const INIT_TIMEOUT: Duration = Duration::from_millis(200);

// Some devices fail when sending a WINK command followed immediately
// by a CBOR command, so we want to ensure we wait some time after winking.
const WINK_MIN_WAIT: Duration = Duration::from_secs(2);

const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0x00;

#[derive(Debug, Clone)]
pub struct HidFidoDevice {
    device: HidBackendDevice,
    init: Option<InitResponse>,
}

#[derive(Debug, Clone)]
enum HidBackendDevice {
    HidApiDevice(DeviceInfo),
    VirtualDevice
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
            device: HidBackendDevice::HidApiDevice(hidapi_device.clone()),
            init: None,
        }
    }
}

impl fmt::Display for HidFidoDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.device {
            HidBackendDevice::HidApiDevice(dev) =>write!(
                f,
                "{:} {:} (r{:?})",
                dev.manufacturer_string().unwrap(),
                dev.product_string().unwrap(),
                dev.release_number()
            ),
            HidBackendDevice::VirtualDevice => write!(
                f,
                "Virtual device" // TBC details
            ),
        }
    }
}

fn get_hidapi() -> Result<HidApi, Error> {
    HidApi::new().or(Err(Error::Transport(TransportError::TransportUnavailable)))
}

pub async fn list_devices(include_virtual: bool) -> Result<Vec<HidFidoDevice>, Error> {
    let mut devices: Vec<HidFidoDevice> = get_hidapi()?
        .device_list()
        .into_iter()
        .filter(|device| device.usage_page() == 0xF1D0)
        .filter(|device| device.usage() == 0x0001)
        .map(|device| device.into())
        .collect();
    if include_virtual {
        devices.push(HidFidoDevice::new_virtual());
    }
    Ok(devices)
}

impl HidFidoDevice {
    pub fn new_virtual() -> Self {
        Self {
            device: HidBackendDevice::VirtualDevice,
            init: None
        }
    }

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

        sleep(WINK_MIN_WAIT).await;
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

    fn hid_cancel(&self, cid: u32, hidapi_device: &HidDevice) -> Result<(), Error> {
        self.hid_send(
            &HidMessage::new(cid, HidCommand::Cancel, &[]),
            &hidapi_device,
        )
    }

    async fn hid_transact(&self, msg: &HidMessage, timeout: Duration) -> Result<HidMessage, Error> {
        match self.device {
            HidBackendDevice::HidApiDevice(_) => self.hid_transact_hidapi(msg, timeout).await,
            HidBackendDevice::VirtualDevice => self.hid_transact_virtual(msg, timeout).await
        }
    }

    async fn hid_transact_virtual(&self, msg: &HidMessage, timeout: Duration) -> Result<HidMessage, Error> {
        // https://github.com/solokeys/python-fido2/commit/4964d98ca6d0cfc24cd49926521282b8e92c598d
        let socket = UdpSocket::bind("127.0.0.1:7112").await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;

        debug!("U2F HID request to UDP virtual device: {:?}", msg);
        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for packet in packets {
            let mut report: Vec<u8> = vec![];
            report.extend(&packet);
            report.extend(vec![0; PACKET_SIZE - packet.len()]);
            debug!(
                "Sending HID report to {:} ({:} bytes): {:?}",
                self,
                report.len(),
                report
            );
            socket.send_to(&report, "127.0.0.1:8111").await
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
        }
        
        let mut parser = HidMessageParser::new();
        loop {
            let mut report = [0; PACKET_SIZE];
            socket.recv_from(&mut report).await
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
            debug!("Received HID report from UDP virtual device: {:?}", report);
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
        debug!("U2F HID response from UDP virtual device: {:?}", response);
        Ok(response)
    }

    async fn hid_transact_hidapi(&self, msg: &HidMessage, timeout: Duration) -> Result<HidMessage, Error> {
        let hidapi_device = self.hid_open()?;

        self.hid_cancel(msg.cid, &hidapi_device)?;
        self.hid_send(msg, &hidapi_device)?;

        let response = loop {
            let response = self.hid_receive(&hidapi_device, timeout)?;
            match response.cmd {
                HidCommand::KeepAlive => {
                    debug!("HID keep-alive received. Ignoring: {:?}", response);
                    continue;
                },
                _ => break response,
            }
        };
        Ok(response)
    }

    fn hid_open(&self) -> Result<HidDevice, Error> {
        let hidapi = get_hidapi()?;
        match &self.device {
            HidBackendDevice::HidApiDevice(device) => Ok(device
                .open_device(&hidapi)
                .or(Err(Error::Transport(TransportError::ConnectionFailed)))?),
            HidBackendDevice::VirtualDevice => unimplemented!()
        }
    }

    fn hid_send(&self, msg: &HidMessage, hidapi_device: &HidDevice) -> Result<(), Error> {
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

        Ok(())
    }

    fn hid_receive(
        &self,
        hidapi_device: &HidDevice,
        timeout: Duration,
    ) -> Result<HidMessage, Error> {
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
