mod error;
mod gatt;

extern crate blurz;
extern crate byteorder;
extern crate log;

use crate::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};

use crate::ops::u2f::{RegisterRequest, SignRequest};

use crate::proto::ctap2::{Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest};
use crate::proto::ctap2::{Ctap2GetAssertionResponse, Ctap2MakeCredentialResponse};

use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};

use blurz::bluetooth_device::BluetoothDevice;
use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_descriptor::BluetoothGATTDescriptor;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use log::{debug, info};
use std::error::Error as StdError;

use self::byteorder::{BigEndian, WriteBytesExt};
pub use error::Error;
use std::collections::HashSet;
use std::convert::TryInto;

pub const TIMEOUT_MS: i32 = 5_000;
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

    pub async fn webauthn_make_credential(
        &self,
        device: &BleDevicePath,
        op: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        let supported = self._supported_fido_revisions(device)?;
        return if supported.contains(&FidoRevision::V2) {
            self._webauthn_make_credential(device, op).await
        } else if supported.contains(&FidoRevision::U2fv11)
            || supported.contains(&FidoRevision::U2fv12)
        {
            let register_request: RegisterRequest =
                op.try_into().or(Err(Error::UnsupportedRequestVersion))?;
            self._u2f_register(device, register_request)
                .await?
                .try_into()
                .or(Err(Error::AuthenticatorError))
        } else {
            Err(Error::NegotiationFailed)
        };
    }

    pub async fn webauthn_get_assertion(
        &self,
        device: &BleDevicePath,
        op: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        let supported = self._supported_fido_revisions(&device)?;
        return if supported.contains(&FidoRevision::V2) {
            self._webauthn_get_assertion(device, op).await
        } else if supported.contains(&FidoRevision::U2fv11)
            || supported.contains(&FidoRevision::U2fv12)
        {
            let sign_request: SignRequest =
                op.try_into().or(Err(Error::UnsupportedRequestVersion))?;
            self._u2f_sign(device, sign_request)
                .await?
                .try_into()
                .or(Err(Error::AuthenticatorError))
        } else {
            Err(Error::NegotiationFailed)
        };
    }

    async fn _webauthn_make_credential(
        &self,
        _: &BleDevicePath,
        _: Ctap2MakeCredentialRequest,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        unimplemented!()
    }

    async fn _webauthn_get_assertion(
        &self,
        _: &BleDevicePath,
        _: Ctap2GetAssertionRequest,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        unimplemented!()
    }

    async fn _u2f_register(
        &self,
        _: &BleDevicePath,
        _: Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error> {
        unimplemented!()
    }

    async fn _u2f_sign(
        &self,
        _: &BleDevicePath,
        _: Ctap1SignRequest,
    ) -> Result<Ctap1SignResponse, Error> {
        unimplemented!();
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
    fn as_ble_frame(self, max_fragment_length: usize) -> Result<BleFrame, Box<dyn StdError>>;
}

// TODO CTAP1 operation downgrade to CTAP1
// CBOR and ADPU, both as bleFrame (tryInto)
impl AsBleFrame for Vec<u8> {
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-framing-fragmentation
    fn as_ble_frame(self, max_fragment_length: usize) -> Result<BleFrame, Box<dyn StdError>> {
        let length = self.len() as u16;
        let mut message = self.into_iter().peekable();
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
