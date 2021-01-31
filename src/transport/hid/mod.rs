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
use crate::proto::ctap1::{Ctap1VersionRequest, Ctap1VersionResponse};
use crate::proto::ctap2::Ctap2DowngradeCheck;
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
use crate::proto::ctap2::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};
use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::fido::FidoProtocol;
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

async fn ctap1_version(device: &FidoDevice, cid: u32) -> Result<Ctap1VersionResponse, Error> {
    let request = &Ctap1VersionRequest::new();
    let apdu_request: ApduRequest = request.into();
    let apdu_response = send_apdu_request(device, cid, &apdu_request).await?;
    let response: Ctap1VersionResponse = apdu_response.try_into().or(Err(CtapError::Other))?;
    debug!("CTAP1 version response: {:?}", response);
    Ok(response)
}

async fn ctap1_register(
    device: &FidoDevice,
    cid: u32,
    request: &Ctap1RegisterRequest,
) -> Result<Ctap1RegisterResponse, Error> {
    debug!("CTAP1 register request: {:?}", request);
    // TODO iterate over exclude list

    let apdu_request: ApduRequest = request.into();
    let apdu_response =
        send_apdu_request_wait_uv(device, cid, &apdu_request, request.timeout).await?;
    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
    debug!("CTAP1 register response: {:?}", response);
    Ok(response)
}

async fn ctap1_sign(
    device: &FidoDevice,
    cid: u32,
    request: &Ctap1SignRequest,
) -> Result<Ctap1SignResponse, Error> {
    debug!("CTAP1 sign request: {:?}", request);
    // TODO iterate over exclude list

    let apdu_request: ApduRequest = request.into();
    let apdu_response =
        send_apdu_request_wait_uv(device, cid, &apdu_request, request.timeout).await?;
    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
    debug!("CTAP1 sign response: {:?}", response);
    Ok(response)
}

async fn ctap2_make_credential(
    _: &FidoDevice,
    cid: u32,
    request: &Ctap2MakeCredentialRequest,
) -> Result<Ctap2MakeCredentialResponse, Error> {
    unimplemented!("")
}

async fn ctap2_get_assertion(
    _: &FidoDevice,
    cid: u32,
    request: &Ctap2GetAssertionRequest,
) -> Result<Ctap2GetAssertionResponse, Error> {
    unimplemented!("")
}

async fn negotiate_protocol(
    device: &FidoDevice,
    allow_fido2: bool,
    allow_u2f: bool,
) -> Result<(InitResponse, FidoProtocol), Error> {
    let init_response = init(&device).await?;
    debug!(
        "Negotiating protocol, allowed: FIDO2={}, U2F={}. INIT response: {:?}",
        allow_fido2, allow_u2f, init_response
    );

    if !allow_fido2 && !allow_u2f {
        panic!("At least one of FIDO2, and U2F must be allowed.");
    }

    let cbor_supported = init_response.caps.contains(Caps::CBOR);
    let apdu_supported = !init_response.caps.contains(Caps::NO_MSG);

    if !cbor_supported && !apdu_supported {
        warn!(
            "Device {} does not support either CBOR nor APDU (MSG).",
            device
        );
        return Err(Error::Transport(TransportError::NegotiationFailed));
    }

    if !allow_u2f && !cbor_supported {
        warn!(
            "Device {} does not support CBOR capability, required for FIDO2.",
            device
        );
        return Err(Error::Transport(TransportError::NegotiationFailed));
    }

    if !allow_fido2 && init_response.caps.contains(Caps::NO_MSG) {
        warn!(
            "Device {} does not support APDU (MSG), required for U2F.",
            device
        );
        return Err(Error::Transport(TransportError::NegotiationFailed));
    }

    let fido_protocol = if allow_fido2 && cbor_supported {
        FidoProtocol::FIDO2
    } else {
        // Ensure CTAP1 version is reported correctly.
        ctap1_version(device, init_response.cid).await?;
        FidoProtocol::U2F
    };

    if allow_fido2 && fido_protocol == FidoProtocol::U2F {
        warn!("Negotiated protocol downgrade from FIDO2 to FIDO U2F");
    } else {
        info!("Selected protocol: {:?}", fido_protocol);
    }
    Ok((init_response, fido_protocol))
}

pub async fn wink(device: &FidoDevice) -> Result<bool, Error> {
    let (init, _) = negotiate_protocol(device, false, true).await?;
    if !init.caps.contains(Caps::WINK) {
        warn!("WINK capability is not supported by device: {}", device);
        return Ok(false);
    }
    hid_transact(device, &HidMessage::new(init.cid, HidCommand::Wink, &[])).await?;
    Ok(true)
}

pub async fn webauthn_make_credential(
    device: &FidoDevice,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Error> {
    debug!("WebAuthn MakeCredential request: {:?}", op);
    let (init, protocol) = negotiate_protocol(device, true, op.is_downgradable()).await?;
    match protocol {
        FidoProtocol::FIDO2 => ctap2_make_credential(device, init.cid, op).await,
        FidoProtocol::U2F => {
            let register_request: RegisterRequest =
                op.try_into().or(Err(TransportError::NegotiationFailed))?;
            ctap1_register(device, init.cid, &register_request)
                .await?
                .try_into()
                .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
        }
    }
}

pub async fn webauthn_get_assertion(
    device: &FidoDevice,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, Error> {
    let (init, protocol) = negotiate_protocol(device, true, op.is_downgradable()).await?;
    match protocol {
        FidoProtocol::FIDO2 => ctap2_get_assertion(device, init.cid, op).await,
        FidoProtocol::U2F => {
            let sign_request: SignRequest =
                op.try_into().or(Err(TransportError::NegotiationFailed))?;
            ctap1_sign(device, init.cid, &sign_request)
                .await?
                .try_into()
                .or(Err(Error::Ctap(CtapError::UnsupportedOption)))
        }
    }
}

pub async fn u2f_register(
    device: &FidoDevice,
    op: &RegisterRequest,
) -> Result<RegisterResponse, Error> {
    let (init, protocol) = negotiate_protocol(device, false, true).await?;
    match protocol {
        FidoProtocol::U2F => ctap1_register(device, init.cid, op).await,
        _ => Err(Error::Transport(TransportError::NegotiationFailed)),
    }
}

pub async fn u2f_sign(device: &FidoDevice, op: &SignRequest) -> Result<SignResponse, Error> {
    let (init, protocol) = negotiate_protocol(device, false, true).await?;

    match protocol {
        FidoProtocol::U2F => ctap1_sign(device, init.cid, op).await,
        _ => Err(Error::Transport(TransportError::NegotiationFailed)),
    }
}
