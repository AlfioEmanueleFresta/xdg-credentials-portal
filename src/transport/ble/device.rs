extern crate byteorder;

use crate::transport::ble::{gatt, BleDevicePath, FidoRevision};

use blurz::bluetooth_device::BluetoothDevice;
use blurz::bluetooth_event::BluetoothEvent;
use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use byteorder::{BigEndian, ReadBytesExt};

use crate::transport::ble::framing::{BleCommand, BleFrame, BleFrameParser, BleFrameParserResult};
use crate::transport::error::TransportError;

use std::collections::HashSet;
use std::io::Cursor as IOCursor;

use log::{debug, info, warn};

pub const WAIT_LOOP_MS: u32 = 250;

pub const TIMEOUT_MS: u32 = 5_000;
pub const FIDO_PROFILE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

#[derive(Debug)]
pub struct KnownDevice {
    device: BleDevicePath,
}

impl KnownDevice {
    pub fn new(device: &BleDevicePath) -> Self {
        Self {
            device: device.to_owned(),
        }
    }

    pub fn connect<'a>(
        &self,
        session: &'a BluetoothSession,
    ) -> Result<ConnectedDevice<'a>, TransportError> {
        let device = BluetoothDevice::new(&session, self.device.clone());
        if !device.is_connected().unwrap() {
            debug!(
                "Connecting to BLE device: {:?} (timeout: {}ms)",
                device, TIMEOUT_MS
            );
            device
                .connect(TIMEOUT_MS as i32)
                .or(Err(TransportError::ConnectionFailed))?;
        }

        info!("Connected to device: {:?}", device);
        let fido_service = device
            .get_gatt_services()
            .unwrap()
            .iter()
            .map(|service_path| BluetoothGATTService::new(&session, service_path.to_owned()))
            .find(|service| service.get_uuid().unwrap() == FIDO_PROFILE_UUID)
            .ok_or(TransportError::InvalidEndpoint)?;

        debug!("Discovered FIDO service: {:?}", fido_service);
        let fido_control_point =
            gatt::get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_UUID)?;
        let fido_control_point_length =
            gatt::get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_LENGTH_UUID)?;
        let fido_status = gatt::get_gatt_characteristic(&session, &fido_service, FIDO_STATUS_UUID)?;
        let fido_service_revision_bitfield =
            gatt::get_gatt_characteristic(session, &fido_service, FIDO_REVISION_BITFIELD_UUID)?;

        Ok(ConnectedDevice {
            session,
            device: self.device.clone(),
            fido_control_point,
            fido_control_point_length,
            fido_status,
            fido_service_revision_bitfield,
        })
    }
}

#[derive(Debug)]
pub struct ConnectedDevice<'a> {
    session: &'a BluetoothSession,
    device: BleDevicePath,
    fido_control_point: BluetoothGATTCharacteristic<'a>,
    fido_control_point_length: BluetoothGATTCharacteristic<'a>,
    fido_status: BluetoothGATTCharacteristic<'a>,
    fido_service_revision_bitfield: BluetoothGATTCharacteristic<'a>,
}

impl ConnectedDevice<'_> {
    pub fn supported_fido_revisions(&self) -> Result<HashSet<FidoRevision>, TransportError> {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-protocol-overview
        let revision = self
            .fido_service_revision_bitfield
            .read_value(None)
            .or(Err(TransportError::ConnectionLost))?;
        let bitfield = revision
            .iter()
            .next()
            .ok_or(TransportError::InvalidEndpoint)?;
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

    pub fn control_point_length(&self) -> Result<usize, TransportError> {
        let max_fragment_size = self
            .fido_control_point_length
            .read_value(None)
            .or(Err(TransportError::ConnectionLost))?;

        if max_fragment_size.len() != 2 {
            return Err(TransportError::InvalidEndpoint);
        }

        let mut cursor = IOCursor::new(max_fragment_size);
        let max_fragment_size = cursor.read_u16::<BigEndian>().unwrap() as usize;
        Ok(max_fragment_size)
    }

    pub fn select_fido_revision(&self, revision: FidoRevision) -> Result<(), TransportError> {
        let ack: u8 = revision.clone() as u8;
        self.fido_service_revision_bitfield
            .write_value(vec![ack], None)
            .or(Err(TransportError::ConnectionLost))?;

        info!("Successfully selected FIDO revision: {:?}", &revision);
        Ok(())
    }

    pub fn send_frame_and_wait_for_response(
        &self,
        frame: BleFrame,
        timeout_ms: u32,
    ) -> Result<BleFrame, TransportError> {
        let fragments = frame.fragments().or(Err(TransportError::InvalidFraming))?;

        self.fido_status
            .start_notify()
            .or(Err(TransportError::ConnectionLost))?;
        info!("Registered for notifications (responses)");

        for fragment in fragments {
            debug!("Sending fragment: {:?}", fragment);
            self.fido_control_point
                .write_value(fragment, None)
                .or(Err(TransportError::ConnectionLost))?;
        }

        let frame = self.wait_for_response(timeout_ms)?;

        self.fido_status
            .start_notify()
            .or(Err(TransportError::ConnectionLost))?;
        info!("Unregistered for notifications (responses)");

        Ok(frame)
    }

    fn wait_for_response(&self, timeout_ms: u32) -> Result<BleFrame, TransportError> {
        let mut waited_for = 0;
        loop {
            let fragments = self.receive_fragments(WAIT_LOOP_MS);
            waited_for += WAIT_LOOP_MS;
            info!("Received fragments: {:?}", fragments);

            let mut parser = BleFrameParser::new();
            for fragment in &fragments {
                let status = parser
                    .update(fragment)
                    .or(Err(TransportError::InvalidFraming))?;
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
                warn!("Timeout waiting for a response from the BLE device.");
                return Err(TransportError::Timeout);
            }
        }
    }

    pub fn receive_fragments(&self, wait_for_ms: u32) -> Vec<Vec<u8>> {
        let id = self.fido_status.get_id();
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
}
