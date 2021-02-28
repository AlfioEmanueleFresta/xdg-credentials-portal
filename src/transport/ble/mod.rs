pub mod bluez;
pub mod device;
pub mod framing;

extern crate log;

pub use device::FidoDevice;

use bluez::FidoDevice as BluezDevice;

use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use crate::proto::ctap2::Ctap2DowngradeCheck;
use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};
use crate::proto::CtapError;

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

use crate::fido::{FidoProtocol, FidoRevision};

use log::{debug, info, warn};
use std::convert::TryInto;

use crate::transport::error::Error::{Ctap, Transport};
use crate::transport::error::{Error, TransportError};
use framing::BleCommand;

use framing::BleFrame;

pub async fn list_devices() -> Result<Vec<FidoDevice>, Error> {
    let devices = bluez::list_devices()
        .await
        .or(Err(Error::Transport(TransportError::TransportUnavailable)))?
        .iter()
        .map(|bluez_device| bluez_device.into())
        .collect();
    Ok(devices)
}

async fn negotiate_protocol(
    device: &FidoDevice,
    allow_fido2: bool,
    allow_u2f: bool,
) -> Result<Option<(FidoProtocol, FidoRevision)>, Error> {
    let bluez_device: BluezDevice = device.into();
    let supported = bluez::supported_fido_revisions(&bluez_device)
        .await
        .or(Err(Error::Transport(TransportError::ConnectionLost)))?;

    info!(
        "Protocol negotiation requirements: allow_fido2={}, allow_u2f={}",
        allow_fido2, allow_u2f
    );

    return if allow_fido2 && supported.contains(&FidoRevision::V2) {
        Ok(Some((FidoProtocol::FIDO2, FidoRevision::V2)))
    } else if allow_u2f && supported.contains(&FidoRevision::U2fv12) {
        Ok(Some((FidoProtocol::U2F, FidoRevision::U2fv12)))
    } else if allow_u2f && supported.contains(&FidoRevision::U2fv11) {
        Ok(Some((FidoProtocol::U2F, FidoRevision::U2fv11)))
    } else {
        warn!("Negotiation failed");
        Ok(None)
    };
}

pub async fn webauthn_make_credential(
    device: &FidoDevice,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Error> {
    let ctap2_request: &Ctap2MakeCredentialRequest = &op.into();
    let (protocol, revision) = negotiate_protocol(device, true, ctap2_request.is_downgradable())
        .await?
        .ok_or(Transport(TransportError::NegotiationFailed))?;

    match protocol {
        FidoProtocol::FIDO2 => ctap2_make_credential(device, ctap2_request).await,
        FidoProtocol::U2F => {
            let register_request: RegisterRequest = ctap2_request
                .try_into()
                .or(Err(TransportError::NegotiationFailed))?;
            ctap1_register(device, &revision, &register_request)
                .await?
                .try_into()
                .or(Err(Ctap(CtapError::UnsupportedOption)))
        }
    }
}

pub async fn webauthn_get_assertion(
    device: &FidoDevice,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, Error> {
    let (protocol, revision) = negotiate_protocol(device, true, op.is_downgradable())
        .await?
        .ok_or(Transport(TransportError::NegotiationFailed))?;

    match protocol {
        FidoProtocol::FIDO2 => ctap2_get_assertion(device, op).await,
        FidoProtocol::U2F => {
            let sign_request: SignRequest =
                op.try_into().or(Err(TransportError::NegotiationFailed))?;
            ctap1_sign(device, &revision, &sign_request)
                .await?
                .try_into()
                .or(Err(Ctap(CtapError::UnsupportedOption)))
        }
    }
}

pub async fn u2f_register(
    device: &FidoDevice,
    op: &RegisterRequest,
) -> Result<RegisterResponse, Error> {
    let (protocol, revision) = negotiate_protocol(device, false, true)
        .await?
        .ok_or(Transport(TransportError::NegotiationFailed))?;

    match protocol {
        FidoProtocol::U2F => ctap1_register(device, &revision, op).await,
        _ => Err(Transport(TransportError::NegotiationFailed)),
    }
}

pub async fn u2f_sign(device: &FidoDevice, op: &SignRequest) -> Result<SignResponse, Error> {
    let (protocol, revision) = negotiate_protocol(device, false, true)
        .await?
        .ok_or(Transport(TransportError::NegotiationFailed))?;

    match protocol {
        FidoProtocol::U2F => ctap1_sign(device, &revision, op).await,
        _ => Err(Transport(TransportError::NegotiationFailed)),
    }
}

async fn ctap2_make_credential(
    _: &FidoDevice,
    _: &Ctap2MakeCredentialRequest,
) -> Result<Ctap2MakeCredentialResponse, Error> {
    unimplemented!()
}

async fn ctap2_get_assertion(
    _: &FidoDevice,
    _: &Ctap2GetAssertionRequest,
) -> Result<Ctap2GetAssertionResponse, Error> {
    unimplemented!()
}

async fn ctap1_register(
    device: &FidoDevice,
    revision: &FidoRevision,
    request: &Ctap1RegisterRequest,
) -> Result<Ctap1RegisterResponse, Error> {
    let apdu_request: ApduRequest = request.into();
    let apdu_response = send_apdu_request(device, revision, apdu_request).await?;

    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
    info!("Register response: {:?}", response);

    Ok(response)
}

async fn ctap1_sign(
    device: &FidoDevice,
    revision: &FidoRevision,
    request: &Ctap1SignRequest,
) -> Result<Ctap1SignResponse, Error> {
    let apdu_request: ApduRequest = request.into();
    let apdu_response = send_apdu_request(device, revision, apdu_request).await?;

    let status = apdu_response.status().or(Err(CtapError::Other))?;
    if status != ApduResponseStatus::NoError {
        return Err(Error::Ctap(CtapError::from(status)));
    }

    let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
    info!("Sign response: {:?}", response);

    Ok(response)
}

async fn send_apdu_request(
    device: &FidoDevice,
    revision: &FidoRevision,
    request: ApduRequest,
) -> Result<ApduResponse, Error> {
    debug!("Sending APDU request: {:?}", request);
    let request_apdu_packet = request.raw_long().or(Err(TransportError::InvalidFraming))?;
    let request_frame = BleFrame::new(BleCommand::Msg, &request_apdu_packet);

    let bluez_device: BluezDevice = device.into();
    let response_frame = bluez::request(&bluez_device, revision, &request_frame)
        .await
        .or(Err(Transport(TransportError::ConnectionFailed)))?;
    match response_frame.cmd {
        BleCommand::Error => return Err(Error::Transport(TransportError::InvalidFraming)), // Encapsulation layer error
        BleCommand::Cancel => return Err(Error::Ctap(CtapError::KeepAliveCancel)),
        BleCommand::Keepalive | BleCommand::Ping => return Err(Error::Ctap(CtapError::Other)), // Unexpected
        BleCommand::Msg => {}
    }
    let response_apdu_packet = &response_frame.data;
    let response_apdu: ApduResponse = response_apdu_packet
        .try_into()
        .or(Err(TransportError::InvalidFraming))?;

    debug!("Received APDU response: {:?}", &response_apdu);
    Ok(response_apdu)
}

#[cfg(tests)]
pub mod tests {
    #[test]
    fn test_connection_failed() {}
}
