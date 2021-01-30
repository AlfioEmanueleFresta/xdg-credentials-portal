extern crate hidapi;
extern crate log;

pub mod device;
pub mod framing;
pub mod init;

const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0x00;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use init::{init, Caps};
use log::{debug, info, warn};

use crate::transport::error::{Error, TransportError};

use device::FidoDevice;
use framing::{HidCommand, HidMessage, HidMessageParser, HidMessageParserState};
use hidapi::HidApi;

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

pub async fn wink(device: &FidoDevice) -> Result<(), Error> {
    let init_response = init(&device).await?;
    if !init_response.caps.contains(Caps::WINK) {
        warn!("Wink is not supported by {}. Ignoring.", device);
        return Ok(());
    }

    let cid = init_response.cid;
    hid_transact(device, &HidMessage::new(cid, HidCommand::Wink, &[])).await?;
    Ok(())
}

async fn hid_transact(device: &FidoDevice, msg: &HidMessage) -> Result<HidMessage, Error> {
    let hidapi = get_hidapi()?;
    let hidapi_device = device
        .hidapi_device
        .open_device(&hidapi)
        .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;

    info!("Request to {:}: {:?}", device, msg);
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

    println!("Waiting for response");
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
    info!("Response from {:}: {:?}", device, response);
    Ok(response)
}
