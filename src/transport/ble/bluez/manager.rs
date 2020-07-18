use super::device::{FidoDevice as Device, FidoEndpoints as Endpoints};
use super::gatt::{get_gatt_characteristic, get_gatt_service};
use super::Error;

use crate::transport::ble::framing::{
    BleCommand, BleFrame as Frame, BleFrameParser, BleFrameParserResult,
};
use crate::transport::ble::FidoRevision;

use blurz::{
    BluetoothAdapter, BluetoothDevice, BluetoothDiscoverySession, BluetoothEvent,
    BluetoothGATTCharacteristic, BluetoothGATTService, BluetoothSession,
};

use byteorder::{BigEndian, ReadBytesExt};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::io::Cursor as IOCursor;
use std::thread::sleep;
use std::time::Duration;

pub const WAIT_LOOP_MS: u32 = 250;
pub const CONNECT_MAX_TIMEOUT_MS: i32 = 30_000;
pub const SERVICES_DISCOVERY_MAX_TIMEOUT_MS: u32 = 5_000;
pub const DEVICE_RESPONSE_TIMEOUT_MS: u32 = 3_000;
pub const FIDO_PROFILE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

pub async fn start_discovery() -> Result<(), Error> {
    tokio::task::spawn_blocking(move || start_discovery_blocking())
        .await
        .unwrap()
}

pub async fn list_devices() -> Result<Vec<Device>, Error> {
    tokio::task::spawn_blocking(move || list_devices_blocking())
        .await
        .unwrap()
}

pub async fn supported_fido_revisions(target: &Device) -> Result<HashSet<FidoRevision>, Error> {
    let target = target.clone();
    tokio::task::spawn_blocking(move || supported_fido_revisions_blocking(&target))
        .await
        .unwrap()
}

pub async fn request(
    device: &Device,
    revision: &FidoRevision,
    frame: &Frame,
) -> Result<Frame, Error> {
    let device = device.clone();
    let revision = revision.clone();
    let frame = frame.clone();
    tokio::task::spawn_blocking(move || request_blocking(&device, &revision, &frame))
        .await
        .unwrap()
}

fn start_discovery_blocking() -> Result<(), Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    let adapter = BluetoothAdapter::init(&session).or(Err(Error::Unavailable))?;
    if !adapter.is_powered().unwrap() {
        return Err(Error::PoweredOff);
    };
    let discovery_session =
        BluetoothDiscoverySession::create_session(&session, adapter.get_id()).unwrap();
    discovery_session
        .set_discovery_filter(vec![FIDO_PROFILE_UUID.into()], None, None)
        .unwrap();
    discovery_session
        .start_discovery()
        .or(Err(Error::Unavailable))?;
    Ok(())
}

fn list_devices_blocking() -> Result<Vec<Device>, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    let adapter = BluetoothAdapter::init(&session).or(Err(Error::Unavailable))?;
    let devices = adapter
        .get_device_list()
        .or(Err(Error::Unavailable))?
        .iter()
        .map(|device_path| BluetoothDevice::new(&session, device_path.into()))
        .filter(|device| {
            device
                .get_uuids()
                .unwrap()
                .contains(&FIDO_PROFILE_UUID.into())
        })
        .map(|device| {
            Device::new(
                &device.get_id(),
                &device.get_alias().unwrap(),
                device.is_paired().unwrap(),
                device.is_connected().unwrap(),
            )
        })
        .collect();
    Ok(devices)
}

fn request_blocking(
    device: &Device,
    revision: &FidoRevision,
    frame: &Frame,
) -> Result<Frame, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    connect(&session, device)?;
    let endpoints = discover_services(&session, device)?;
    let status = BluetoothGATTCharacteristic::new(&session, endpoints.status.clone());
    select_fido_revision(&session, &endpoints, revision)?;

    status.start_notify().or(Err(Error::OperationFailed))?;
    debug!("Registered for notifications on FIDO status endpoint");

    let max_fragment_size = control_point_length(&session, &endpoints)?;
    let fragments = frame
        .fragments(max_fragment_size)
        .or(Err(Error::InvalidFraming))?;

    let control_point = BluetoothGATTCharacteristic::new(&session, endpoints.control_point.clone());
    for fragment in fragments {
        debug!("Sending fragment: {:?}", fragment);
        control_point
            .write_value(fragment, None)
            .or(Err(Error::OperationFailed))?;
    }

    let frame = wait_for_response(&session, &endpoints)?;
    status.stop_notify().or(Err(Error::OperationFailed))?;
    debug!("Unregistered for notifications");

    Ok(frame)
}

fn control_point_length(session: &BluetoothSession, endpoints: &Endpoints) -> Result<usize, Error> {
    let control_point_length =
        BluetoothGATTCharacteristic::new(&session, endpoints.control_point_length.clone());
    let max_fragment_length = control_point_length
        .read_value(None)
        .or(Err(Error::OperationFailed))?;

    if max_fragment_length.len() != 2 {
        warn!(
            "Control point length endpoint returned an unexpected number of bytes ({}).",
            max_fragment_length.len()
        );
        return Err(Error::OperationFailed);
    }

    let mut cursor = IOCursor::new(max_fragment_length);
    let max_fragment_size = cursor.read_u16::<BigEndian>().unwrap() as usize;
    Ok(max_fragment_size)
}

fn connect(session: &BluetoothSession, target: &Device) -> Result<(), Error> {
    let device = BluetoothDevice::new(session, target.path.clone());
    if !device.is_paired().or(Err(Error::Unavailable))? {
        info!("Pairing required to target device: {:?}", target);
        device.pair().or(Err(Error::ConnectionFailed))?;
    }
    if !device.is_connected().or(Err(Error::Unavailable))? {
        debug!("Connecting to target device: {:?}", target);
        device
            .connect(CONNECT_MAX_TIMEOUT_MS)
            .or(Err(Error::ConnectionFailed))?;
    }
    wait_until_services_resolved(&device)?;
    info!("Connected to target device: {:?}", target);
    Ok(())
}

fn wait_until_services_resolved(device: &BluetoothDevice) -> Result<(), Error> {
    debug!("Waiting until services are resolved for this device");
    // Unfortunately bluez does not support the ServicesResolved property of BlueZ devices
    // so we have to get creative - we'll keep enumerating services until at least one is found.
    let mut waited_for = 0;
    loop {
        let services = device
            .get_gatt_services()
            .or(Err(Error::ConnectionFailed))?;
        if !services.is_empty() {
            debug!("{} services found. Continuing.", services.len());
            return Ok(());
        }
        if waited_for >= SERVICES_DISCOVERY_MAX_TIMEOUT_MS {
            warn!(
                "Timed out whilst waiting for services to be resolved for device {:?}",
                device
            );
            return Err(Error::ConnectionFailed);
        }
        debug!("Services not yet resolved. Waiting {} ms.", WAIT_LOOP_MS);
        sleep(Duration::from_millis(WAIT_LOOP_MS as u64));
        waited_for += WAIT_LOOP_MS;
    }
}

fn discover_services(session: &BluetoothSession, target: &Device) -> Result<Endpoints, Error> {
    debug!("Attempting to discover FIDO services.");
    let device = BluetoothDevice::new(session, target.path.clone());
    let fido_service =
        get_gatt_service(&session, &device, FIDO_PROFILE_UUID).or(Err(Error::ConnectionFailed))?;
    debug!(
        "Discovered FIDO service (UUID {}): {:?}",
        FIDO_PROFILE_UUID, fido_service
    );

    let control_point = get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_UUID)?;
    let control_point_length =
        get_gatt_characteristic(session, &fido_service, FIDO_CONTROL_POINT_LENGTH_UUID)?;
    let status = get_gatt_characteristic(&session, &fido_service, FIDO_STATUS_UUID)?;
    let service_revision_bitfield =
        get_gatt_characteristic(session, &fido_service, FIDO_REVISION_BITFIELD_UUID)?;
    let endpoints = Endpoints::new(
        &control_point.get_id(),
        &control_point_length.get_id(),
        &status.get_id(),
        &service_revision_bitfield.get_id(),
    );
    Ok(endpoints)
}

fn supported_fido_revisions_blocking(target: &Device) -> Result<HashSet<FidoRevision>, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    connect(&session, &target)?;
    let endpoints = discover_services(&session, target)?;

    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-protocol-overview
    let service_revision_bitfield =
        BluetoothGATTCharacteristic::new(&session, endpoints.service_revision_bitfield.into());
    let revision = service_revision_bitfield
        .read_value(None)
        .or(Err(Error::OperationFailed))?;
    let bitfield = revision.iter().next().ok_or(Error::OperationFailed)?;
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

fn select_fido_revision(
    session: &BluetoothSession,
    endpoints: &Endpoints,
    revision: &FidoRevision,
) -> Result<(), Error> {
    let service_revision_bitfield =
        BluetoothGATTCharacteristic::new(session, endpoints.service_revision_bitfield.clone());
    let ack: u8 = revision.clone() as u8;
    service_revision_bitfield
        .write_value(vec![ack], None)
        .or(Err(Error::OperationFailed))?;

    info!("Successfully selected FIDO revision: {:?}", &revision);
    Ok(())
}

fn wait_for_response(session: &BluetoothSession, endpoints: &Endpoints) -> Result<Frame, Error> {
    let mut waited_for = 0;
    loop {
        let fragments = receive_fragments(session, endpoints, WAIT_LOOP_MS);
        waited_for += WAIT_LOOP_MS;
        debug!("Received fragments: {:?}", fragments);

        let mut parser = BleFrameParser::new();
        for fragment in &fragments {
            let status = parser.update(fragment).or(Err(Error::InvalidFraming))?;
            match status {
                BleFrameParserResult::Done => {
                    let frame = parser.frame().unwrap();
                    match frame.cmd {
                        BleCommand::Keepalive => {
                            waited_for = 0;
                            debug!("Received keep-alive from authenticator.");
                            parser.reset();
                        }
                        BleCommand::Cancel => {
                            info!("Device canceled: {:?}", frame);
                            return Err(Error::Canceled);
                        }
                        BleCommand::Error => {
                            warn!("Received error frame: {:?}", frame);
                            return Err(Error::OperationFailed);
                        }
                        BleCommand::Ping => {
                            debug!("Ping received. Ignoring.");
                        }
                        BleCommand::Msg => {
                            debug!("Received complete response: {:?}", frame);
                            return Ok(frame);
                        }
                    }
                }
                BleFrameParserResult::MoreFragmentsExpected => {}
            }
        }

        if waited_for > DEVICE_RESPONSE_TIMEOUT_MS {
            warn!("Timeout waiting for a response from the BLE device.");
            return Err(Error::Timeout);
        }
    }
}

fn receive_fragments(
    session: &BluetoothSession,
    endpoints: &Endpoints,
    wait_for_ms: u32,
) -> Vec<Vec<u8>> {
    let fragments: Vec<Vec<u8>> = session
        .incoming(wait_for_ms)
        .map(BluetoothEvent::from)
        .filter(Option::is_some)
        .flat_map(move |event| match event.unwrap() {
            BluetoothEvent::Value { object_path, value } => {
                if object_path == endpoints.status {
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
