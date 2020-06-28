mod error;
mod framing;
mod gatt;

extern crate blurz;
extern crate byteorder;
extern crate log;

use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest, Ctap1VersionRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

use blurz::bluetooth_device::BluetoothDevice;
use blurz::bluetooth_event::BluetoothEvent;
use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_descriptor::BluetoothGATTDescriptor;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use log::{debug, info, warn};
use std::error::Error as StdError;
use std::io::Cursor as IOCursor;

use self::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
pub use error::Error;
use std::collections::HashSet;
use std::convert::TryInto;

use crate::transport::ble::framing::{BleCommand, BleFrameParser, BleFrameParserResult};
use framing::BleFrame;
use std::borrow::Borrow;

pub const WAIT_LOOP_MS: u32 = 250;
pub const TIMEOUT_MS: u32 = 5_000;
pub const CTAP2_BLE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(u8)]
enum FidoRevision {
    V2 = 0x20,
    U2fv12 = 0x40,
    U2fv11 = 0x80,
}

enum FidoProtocol {
    FIDO2,
    U2F,
}

impl From<FidoRevision> for FidoProtocol {
    fn from(revision: FidoRevision) -> Self {
        match revision {
            FidoRevision::V2 => FidoProtocol::FIDO2,
            FidoRevision::U2fv11 | FidoRevision::U2fv12 => FidoProtocol::U2F,
        }
    }
}

pub type BleDevicePath = String;

#[derive(Debug)]
struct FidoBleEndpoints<'a> {
    pub fido_control_point: BluetoothGATTCharacteristic<'a>,
    pub fido_control_point_length: BluetoothGATTCharacteristic<'a>,
    pub fido_status: BluetoothGATTCharacteristic<'a>,
    pub fido_status_desc: BluetoothGATTDescriptor<'a>,
    pub fido_service_revision_bitfield: BluetoothGATTCharacteristic<'a>,
    pub fido_service_revision_bitfield_desc: BluetoothGATTDescriptor<'a>,
}

fn get_fido_characteristics<'a>(
    session: &'a BluetoothSession,
    device: &'a BleDevicePath,
) -> Result<FidoBleEndpoints<'a>, Error> {
    let device = BluetoothDevice::new(&session, String::from(device));
    if !device.is_connected().unwrap() {
        debug!(
            "Connecting to BLE device: {:?} (timeout: {}ms)",
            device, TIMEOUT_MS
        );
        device.connect(TIMEOUT_MS as i32).unwrap();
    }

    debug!("Found device: {:?}", device);
    let fido_service = device
        .get_gatt_services()
        .unwrap()
        .iter()
        .map(|service_path| BluetoothGATTService::new(&session, service_path.to_owned()))
        .find(|service| service.get_uuid().unwrap() == CTAP2_BLE_UUID)
        .ok_or(Error::AuthenticatorError)?;

    debug!("Found fido service: {:?}", fido_service);
    let fido_control_point =
        gatt::get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_UUID)?;
    let fido_control_point_length =
        gatt::get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_LENGTH_UUID)?;
    let fido_status = gatt::get_gatt_characteristic(session, &fido_service, FIDO_STATUS_UUID)?;
    let fido_status_desc = gatt::get_gatt_descriptor(session, &fido_status)?;
    let fido_service_revision_bitfield =
        gatt::get_gatt_characteristic(session, &fido_service, FIDO_REVISION_BITFIELD_UUID)?;
    let fido_service_revision_bitfield_desc =
        gatt::get_gatt_descriptor(session, &fido_service_revision_bitfield)?;

    Ok(FidoBleEndpoints {
        fido_control_point,
        fido_control_point_length,
        fido_status,
        fido_status_desc,
        fido_service_revision_bitfield,
        fido_service_revision_bitfield_desc,
    })
}

pub struct BLEManager {
    session: BluetoothSession,
}

impl BLEManager {
    pub fn new() -> Option<BLEManager> {
        // TODO check if BLE is available
        Some(BLEManager {
            session: BluetoothSession::create_session(None).unwrap(),
        })
    }

    fn _supported_fido_revisions(
        &self,
        device: &BleDevicePath,
    ) -> Result<HashSet<FidoRevision>, Error> {
        let endpoints = get_fido_characteristics(&self.session, &device)?;

        debug!("Fetching supported revisions...");
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-protocol-overview
        let revision = endpoints
            .fido_service_revision_bitfield
            .read_value(None)
            .or(Err(Error::AuthenticatorError))?;
        let bitfield = revision.iter().next().ok_or(Error::AuthenticatorError)?;

        debug!("Supported revision bitfield: {:?}", revision);

        let mut supported = HashSet::new();
        if bitfield & FidoRevision::V2 as u8 != 0x00 {
            supported.insert(FidoRevision::V2);
        }

        if bitfield & FidoRevision::U2fv12 as u8 != 0x00 {
            supported.insert(FidoRevision::U2fv12);
        }

        if bitfield & FidoRevision::U2fv11 as u8 != 0x00 {
            supported.insert(FidoRevision::U2fv11);
        }

        info!("Device reported supporting FIDO revisions {:?}", supported);
        Ok(supported)
    }

    fn _use_fido_revision(
        &self,
        device: &BleDevicePath,
        revision: FidoRevision,
    ) -> Result<(), Error> {
        let endpoints = get_fido_characteristics(&self.session, &device)?;

        let ack: u8 = revision.clone() as u8;
        endpoints
            .fido_service_revision_bitfield
            .write_value(vec![ack], None)
            .unwrap();

        info!("Successfully negotiated FIDO revision: {:?}", &revision);
        Ok(())
    }

    fn _negotiate_protocol(
        &self,
        device: &BleDevicePath,
        allow_fido2: bool,
        allow_u2f: bool,
    ) -> Result<Option<FidoProtocol>, Error> {
        info!(
            "Protocol negotiation requirements: allow_fido2={}, allow_u2f={}",
            allow_fido2, allow_u2f
        );
        let supported = self._supported_fido_revisions(device)?;

        return if allow_fido2 && supported.contains(&FidoRevision::V2) {
            self._use_fido_revision(device, FidoRevision::V2);
            Ok(Some(FidoProtocol::FIDO2))
        } else if allow_u2f && supported.contains(&FidoRevision::U2fv12) {
            self._use_fido_revision(device, FidoRevision::U2fv12);
            Ok(Some(FidoProtocol::U2F))
        } else if allow_u2f && supported.contains(&FidoRevision::U2fv11) {
            self._use_fido_revision(device, FidoRevision::U2fv11);
            Ok(Some(FidoProtocol::U2F))
        } else {
            warn!("Negotiation failed");
            Ok(None)
        };
    }

    fn _get_max_fragment_length(&self, endpoints: &FidoBleEndpoints) -> Result<usize, Error> {
        let max_fragment_size = endpoints
            .fido_control_point_length
            .read_value(None)
            .unwrap();

        if max_fragment_size.len() != 2 {
            return Err(Error::AuthenticatorError);
        }

        let mut cursor = IOCursor::new(max_fragment_size);
        let max_fragment_size = cursor.read_u16::<BigEndian>().unwrap() as usize;
        Ok(max_fragment_size)
    }

    pub async fn webauthn_make_credential(
        &self,
        device: &BleDevicePath,
        op: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let downgradable = true; // FIXME check!
        let protocol = self._negotiate_protocol(device, true, downgradable)?;

        match protocol {
            Some(FidoProtocol::FIDO2) => self.ctap2_make_credential(device, op).await,
            Some(FidoProtocol::U2F) => {
                let register_request: RegisterRequest =
                    op.try_into().or(Err(Error::UnsupportedRequestVersion))?;
                self.ctap1_register(device, register_request)
                    .await?
                    .try_into()
                    .or(Err(Error::AuthenticatorError))
            }
            None => Err(Error::NegotiationFailed),
        }
    }

    pub async fn webauthn_get_assertion(
        &self,
        device: &BleDevicePath,
        op: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let downgradable = true; // FIXME check!
        let protocol = self._negotiate_protocol(device, true, downgradable)?;

        match protocol {
            Some(FidoProtocol::FIDO2) => self.ctap2_get_assertion(device, op).await,
            Some(FidoProtocol::U2F) => {
                let sign_request: SignRequest =
                    op.try_into().or(Err(Error::UnsupportedRequestVersion))?;
                self.ctap1_sign(device, sign_request)
                    .await?
                    .try_into()
                    .or(Err(Error::AuthenticatorError))
            }
            None => Err(Error::NegotiationFailed),
        }
    }

    pub async fn u2f_register(
        &self,
        device: &BleDevicePath,
        op: RegisterRequest,
    ) -> Result<RegisterResponse, Error> {
        let protocol = self._negotiate_protocol(device, false, true)?;

        match protocol {
            Some(FidoProtocol::U2F) => self.ctap1_register(device, op).await,
            _ => Err(Error::NegotiationFailed),
        }
    }

    pub async fn u2f_sign(
        &self,
        device: &BleDevicePath,
        op: SignRequest,
    ) -> Result<SignResponse, Error> {
        let protocol = self._negotiate_protocol(device, false, true)?;

        match protocol {
            Some(FidoProtocol::U2F) => self.ctap1_sign(device, op).await,
            _ => Err(Error::NegotiationFailed),
        }
    }

    async fn ctap2_make_credential(
        &self,
        _: &BleDevicePath,
        _: Ctap2MakeCredentialRequest,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        unimplemented!()
    }

    async fn ctap2_get_assertion(
        &self,
        _: &BleDevicePath,
        _: Ctap2GetAssertionRequest,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        unimplemented!()
    }

    async fn ctap1_register(
        &self,
        device: &BleDevicePath,
        request: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error> {
        let endpoints = get_fido_characteristics(&self.session, device)?;
        let timeout_ms = request.timeout_seconds * 1000;

        let apdu_request: ApduRequest = request.into();
        let apdu_response = self.send_apdu_request(apdu_request, &endpoints, timeout_ms)?;

        let status = apdu_response.status().or(Err(Error::AuthenticatorError))?;
        match status {
            ApduResponseStatus::NoError => {}
            ApduResponseStatus::UserPresenceTestFailed => {
                warn!("User presence test failed");
                return Err(Error::UserPresenceTestFailed);
            }
            _ => return Err(Error::AuthenticatorError),
        }

        let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
        info!("Response: {:?}", response);

        Ok(response)
    }

    fn send_apdu_request(
        &self,
        request: ApduRequest,
        endpoints: &FidoBleEndpoints,
        timeout_ms: u32,
    ) -> Result<ApduResponse, Error> {
        let max_fragment_length = self._get_max_fragment_length(endpoints)?;

        debug!("Sending APDU request: {:?}", request);
        let request_apdu_packet = request.raw_long().or(Err(Error::InvalidData))?;
        let request_frame = BleFrame::new(
            Some(max_fragment_length),
            BleCommand::Msg,
            &request_apdu_packet,
        );

        let response_frame =
            self.send_frame_and_wait_for_response(request_frame, &endpoints, timeout_ms)?;
        match response_frame.cmd {
            BleCommand::Error => return Err(Error::AuthenticatorError), // Encapsulation layer error
            BleCommand::Cancel => return Err(Error::AuthenticatorCancel),
            BleCommand::Keepalive | BleCommand::Ping => return Err(Error::AuthenticatorError), // Unexpected
            BleCommand::Msg => {}
        }
        let resposne_apdu_packet = &response_frame.data;
        let response_apdu: ApduResponse = resposne_apdu_packet
            .try_into()
            .or(Err(Error::AuthenticatorError))?;

        debug!("Received APDU response: {:?}", &response_apdu);
        Ok(response_apdu)
    }

    fn send_frame_and_wait_for_response(
        &self,
        frame: BleFrame,
        endpoints: &FidoBleEndpoints,
        timeout_ms: u32,
    ) -> Result<BleFrame, Error> {
        let fragments = frame.fragments().or(Err(Error::AuthenticatorError))?;

        endpoints
            .fido_status
            .start_notify()
            .or(Err(Error::ConnectionLost))?;
        info!("Registered for notifications (responses)");

        for fragment in fragments {
            debug!("Sending fragment: {:?}", fragment);
            endpoints
                .fido_control_point
                .write_value(fragment, None)
                .or(Err(Error::ConnectionLost))?;
        }

        let frame = self.wait_for_response(&endpoints, timeout_ms)?;

        endpoints
            .fido_status
            .start_notify()
            .or(Err(Error::ConnectionLost))?;
        info!("Unregistered for notifications (responses)");

        Ok(frame)
    }

    fn wait_for_response(
        &self,
        endpoints: &FidoBleEndpoints,
        timeout_ms: u32,
    ) -> Result<BleFrame, Error> {
        let mut waited_for = 0;
        loop {
            let fragments = self.receive_fragments(endpoints, WAIT_LOOP_MS);
            waited_for += WAIT_LOOP_MS;
            info!("Received fragments: {:?}", fragments);

            let mut parser = BleFrameParser::new();
            for fragment in &fragments {
                let status = parser.update(fragment).or(Err(Error::AuthenticatorError))?;
                match status {
                    BleFrameParserResult::Done => {
                        let frame = parser.frame().unwrap();
                        if frame.cmd == BleCommand::Keepalive {
                            info!("Received Keepalive from authenticator. Ignoring.");
                            parser.reset();
                        } else {
                            info!("Received complete response: {:?}", frame);
                            return Ok(frame);
                        }
                    }
                    BleFrameParserResult::MoreFragmentsExpected => {}
                }
            }

            if waited_for > timeout_ms {
                return Err(Error::Timeout);
            }
        }
    }

    fn receive_fragments(&self, endpoints: &FidoBleEndpoints, wait_for_ms: u32) -> Vec<Vec<u8>> {
        let id = endpoints.fido_status.get_id();
        let fragments: Vec<Vec<u8>> = self
            .session
            .incoming(wait_for_ms)
            .map(BluetoothEvent::from)
            .filter(Option::is_some)
            .flat_map(move |event| match event.unwrap() {
                BluetoothEvent::Value { object_path, value } => {
                    if object_path == id {
                        Some(value)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .map(move |e| Vec::from(e))
            .collect();
        fragments
    }

    async fn ctap1_sign(
        &self,
        _: &BleDevicePath,
        _: Ctap1SignRequest,
    ) -> Result<Ctap1SignResponse, Error> {
        unimplemented!();
    }
}
