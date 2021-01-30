extern crate hidapi;
extern crate log;

pub mod device;
pub mod framing;
pub mod init;

use init::{init, Caps, InitResponse};
use log::{debug, info, warn};
use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use tokio::time::{sleep, timeout as tokio_timeout};

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

use crate::transport::error::{CtapError, Error, TransportError};

use device::FidoDevice;
use framing::{HidCommand, HidMessage, HidMessageParser, HidMessageParserState};
use hidapi::HidApi;

const UP_SLEEP: Duration = Duration::from_millis(150);
const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0x00;

fn get_hidapi() -> Result<HidApi, Error> {
    HidApi::new().or(Err(Error::Transport(TransportError::TransportUnavailable)))
}

pub async fn list_devices() -> Result<Vec<FidoDevice>, Error> {
    Ok(get_hidapi()?
        .device_list()
        .into_iter()
        .filter(|device| device.usage_page() == 0xF1D0)
        .filter(|device| device.usage() == 0x0001)
        .map(|device| device.into())
        .collect())
}

async fn hid_transact(device: &FidoDevice, msg: &HidMessage) -> Result<HidMessage, Error> {
    let hidapi = get_hidapi()?;
    let hidapi_device = device
        .hidapi_device
        .open_device(&hidapi)
        .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;

    debug!("U2F HID request to {:}: {:?}", device, msg);
    let packets = msg
        .packets(PACKET_SIZE)
        .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
    for packet in packets {
        let mut report: Vec<u8> = vec![REPORT_ID];
        report.extend(&packet);
        report.extend(vec![0; PACKET_SIZE - packet.len()]);
        debug!(
            "Sending HID report to {:} ({:} bytes): {:?}",
            device,
            report.len(),
            report
        );
        hidapi_device.write(&report).unwrap();
    }

    let mut parser = HidMessageParser::new();
    loop {
        let mut report = [0; PACKET_SIZE];
        hidapi_device
            .read(&mut report)
            .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
        debug!("Received HID report from {:}: {:?}", device, report);
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
    debug!("U2F HID response from {:}: {:?}", device, response);
    Ok(response)
}

async fn send_apdu_request(
    device: &FidoDevice,
    cid: u32,
    request: &ApduRequest,
) -> Result<ApduResponse, Error> {
    debug!(
        "Sending APDU request to {} (cid: {}): {:?}",
        device, cid, request
    );
    let apdu_raw = request.raw_long().unwrap();
    let hid_response =
        hid_transact(device, &HidMessage::new(cid, HidCommand::Msg, &apdu_raw)).await?;
    let apdu_response = ApduResponse::try_from(&hid_response.payload)
        .or(Err(Error::Transport(TransportError::InvalidFraming)))?;

    debug!("Received APDU response: {:?}", apdu_response);
    Ok(apdu_response)
}

async fn send_apdu_request_wait_uv(
    device: &FidoDevice,
    cid: u32,
    request: &ApduRequest,
    timeout: Duration,
) -> Result<ApduResponse, Error> {
    tokio_timeout(timeout, async {
        loop {
            let apdu_response = send_apdu_request(device, cid, request).await?;
            let apdu_status = apdu_response
                .status()
                .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
            let ctap_error: CtapError = apdu_status.into();
            match ctap_error {
                CtapError::Ok => return Ok(apdu_response),
                CtapError::UserPresenceRequired => (), // Sleep some more.
                _ => return Err(Error::Ctap(ctap_error)),
            };
            debug!("UP required. Sleeping for {:?}.", UP_SLEEP);
            sleep(UP_SLEEP).await;
        }
    })
    .await
    .or(Err(Error::Ctap(CtapError::UserActionTimeout)))?
}

async fn handshake(
    device: &FidoDevice,
    required_caps: Option<Caps>,
    is_apdu: bool,
) -> Result<InitResponse, Error> {
    let init_response = init(&device).await?;
    if let Some(required_caps) = required_caps {
        if !init_response.caps.contains(required_caps) {
            warn!(
                "Capabilities {:?} are not supported by device {}.",
                required_caps, device
            );
            return Err(Error::Ctap(CtapError::InvalidCommand));
        }
    }

    if is_apdu && init_response.caps.contains(Caps::NO_MSG) {
        warn!("Device {} does not support APDU (MSG command).", device);
        return Err(Error::Ctap(CtapError::InvalidCommand));
    }

    Ok(init_response)
}

pub async fn wink(device: &FidoDevice) -> Result<(), Error> {
    let cid = handshake(device, Some(Caps::WINK), false).await?.cid;
    hid_transact(device, &HidMessage::new(cid, HidCommand::Wink, &[])).await?;
    Ok(())
}

pub async fn ctap1_register(
    device: &FidoDevice,
    request: &Ctap1RegisterRequest,
) -> Result<Ctap1RegisterResponse, Error> {
    let cid = handshake(device, None, true).await?.cid;

    // TODO iterate over exclude list

    let apdu_request: ApduRequest = request.into();
    let apdu_response =
        send_apdu_request_wait_uv(device, cid, &apdu_request, request.timeout).await?;
    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
    info!("Register response: {:?}", response);

    Ok(response)
}

pub async fn ctap1_sign(
    device: &FidoDevice,
    request: &Ctap1SignRequest,
) -> Result<Ctap1SignResponse, Error> {
    let cid = handshake(device, None, true).await?.cid;

    // TODO iterate over exclude list

    let apdu_request: ApduRequest = request.into();
    let apdu_response =
        send_apdu_request_wait_uv(device, cid, &apdu_request, request.timeout).await?;
    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
    info!("Sign response: {:?}", response);

    Ok(response)
}
