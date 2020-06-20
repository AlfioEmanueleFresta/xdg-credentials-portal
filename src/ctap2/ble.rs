extern crate async_trait;
extern crate blurz;
extern crate byteorder;
extern crate log;

use async_trait::async_trait;

use super::protocol::Ctap2Error;
use super::protocol::Ctap2Operation;
use super::protocol::{Ctap2GetAssertionRequest, Ctap2GetAssertionResponse};
use super::protocol::{Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse};
use super::Ctap2BleAuthenticator;

use blurz::bluetooth_device::BluetoothDevice;
use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_descriptor::BluetoothGATTDescriptor;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use std::io;

pub const TIMEOUT_MS: i32 = 5_000;
pub const CTAP2_BLE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

pub type Ctap2BleDevicePath = String;

pub struct BlueZCtap2BleAuthenticator {}

impl BlueZCtap2BleAuthenticator {
    pub fn new() -> BlueZCtap2BleAuthenticator {
        BlueZCtap2BleAuthenticator {}
    }
}

#[derive(Debug)]
struct FidoBleEndpoints<'a> {
    pub fido_control_point: BluetoothGATTCharacteristic<'a>,
    pub fido_control_point_length: BluetoothGATTCharacteristic<'a>,
    pub fido_status: BluetoothGATTCharacteristic<'a>,
    pub fido_service_revision_bitfield: BluetoothGATTCharacteristic<'a>,
    pub fido_service_revision_bitfield_desc: BluetoothGATTDescriptor<'a>,
}

fn get_fido_characteristic<'a>(
    session: &'a BluetoothSession,
    service: &BluetoothGATTService<'a>,
    uuid: &str,
) -> Result<BluetoothGATTCharacteristic<'a>, io::Error> {
    Ok(service
        .get_gatt_characteristics()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTCharacteristic::new(session, char_path.to_owned()))
        .find(|charct| charct.get_uuid().unwrap() == FIDO_CONTROL_POINT_UUID)
        .unwrap())
}

fn get_descriptor<'a>(
    session: &'a BluetoothSession,
    characteristic: &BluetoothGATTCharacteristic<'a>,
) -> Result<BluetoothGATTDescriptor<'a>, io::Error> {
    Ok(characteristic
        .get_gatt_descriptors()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTDescriptor::new(session, char_path.to_owned()))
        .next()
        .unwrap())
}

fn get_fido_characteristics(
    session: &BluetoothSession,
    device: Ctap2BleDevicePath,
) -> Result<FidoBleEndpoints, io::Error> {
    let device = BluetoothDevice::new(&session, device.to_owned());
    debug!(
        "Connecting to BLE device: {:?} (timeout: {}ms)",
        device, TIMEOUT_MS
    );
    device.connect(TIMEOUT_MS).unwrap();

    debug!("Found device: {:?}", device);
    let fido_service = device
        .get_gatt_services()
        .unwrap()
        .iter()
        .map(|service_path| BluetoothGATTService::new(&session, service_path.to_owned()))
        .find(|service| service.get_uuid().unwrap() == CTAP2_BLE_UUID)
        .unwrap();

    debug!("Found fido service: {:?}", fido_service);
    let fido_control_point =
        get_fido_characteristic(session, &fido_service, FIDO_CONTROL_POINT_UUID)?;
    let fido_control_point_length =
        get_fido_characteristic(session, &fido_service, FIDO_CONTROL_POINT_LENGTH_UUID)?;
    let fido_status = get_fido_characteristic(session, &fido_service, FIDO_STATUS_UUID)?;
    let fido_service_revision_bitfield =
        get_fido_characteristic(session, &fido_service, FIDO_REVISION_BITFIELD_UUID)?;
    let fido_service_revision_bitfield_desc =
        get_descriptor(session, &fido_service_revision_bitfield)?;

    Ok(FidoBleEndpoints {
        fido_control_point,
        fido_control_point_length,
        fido_status,
        fido_service_revision_bitfield,
        fido_service_revision_bitfield_desc,
    })
}

#[async_trait]
impl Ctap2BleAuthenticator for BlueZCtap2BleAuthenticator {
    async fn make_credentials(
        &self,
        device: Ctap2BleDevicePath,
        request: Ctap2MakeCredentialRequest,
    ) -> Result<Ctap2MakeCredentialResponse, Ctap2Error> {
        let session = BluetoothSession::create_session(None).unwrap(); // FIXME
        let endpoints = get_fido_characteristics(&session, device).unwrap();

        // TODO read max length from FIDO control point length characteristic
        let max_fragment_length: usize = 20;

        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-protocol-overview
        let revision = endpoints
            .fido_service_revision_bitfield_desc
            .read_value(None)
            .unwrap();

        debug!("Supported revisions: {:?}", revision);
        if revision.iter().next().unwrap() & 0x20 == 0 {
            panic!("FIDO2 not supported"); // FIXME
        }
        endpoints
            .fido_service_revision_bitfield
            .write_value(vec![0x20], None)
            .unwrap();

        let get_info = Ctap2Operation::GetInfo;
        debug!("get_info request: {:?}", get_info);

        for fragment in get_info.as_ble_frame(max_fragment_length).unwrap() {
            debug!("writing fragment: {:?}", fragment);
            endpoints
                .fido_control_point
                .write_value(fragment, None)
                .unwrap();
        }

        endpoints.fido_status.start_notify().unwrap();

        loop {
            debug!("reading...");
            let read = endpoints.fido_status.get_value().unwrap();
            debug!("received: {:?}", read);
        }
    }

    async fn get_assertion(
        &self,
        device: Ctap2BleDevicePath,
        request: Ctap2GetAssertionRequest,
    ) -> Result<Ctap2GetAssertionResponse, Ctap2Error> {
        unimplemented!()
    }
}

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-constants
#[derive(Debug)]
#[repr(u8)]
enum Ctap2BleCommand {
    Ping = 0x81,
    Keepalive = 0x82,
    Msg = 0x83,
    Cancel = 0xBE,
    Error = 0xBF,
}

type BleFrame = Vec<BleFragment>;
type BleFragment = Vec<u8>;

trait AsBleFrame {
    fn as_ble_frame(self, max_fragment_length: usize) -> Result<BleFrame, io::Error>;
}

impl AsBleFrame for Ctap2Operation {
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-framing-fragmentation
    fn as_ble_frame(self, max_fragment_length: usize) -> Result<BleFrame, io::Error> {
        let message = self.serialize().unwrap();
        let length = message.len() as u16;
        let mut message = message.into_iter().peekable();
        let mut frame = vec![];

        // Initial fragment
        let mut fragment = vec![Ctap2BleCommand::Msg as u8];
        fragment.write_u16::<BigEndian>(length)?;
        let mut chunk: Vec<u8> = message.by_ref().take(max_fragment_length - 3).collect();
        fragment.append(&mut chunk);
        frame.push(fragment);

        // Sequence fragments
        let mut seq: u8 = 0;
        while message.peek().is_some() {
            let mut fragment = vec![seq];
            let mut chunk: Vec<u8> = message.by_ref().take(max_fragment_length - 1).collect();
            fragment.append(&mut chunk);
            frame.push(fragment);
            seq += 1;
        }

        debug!("Ctap2Operatoin::as_ble_frame: {:?}", frame);
        Ok(frame)
    }
}
