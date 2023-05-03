use std::collections::HashMap;
use std::io::Cursor as IOCursor;
use std::thread::sleep;
use std::time::Duration;

use tracing::{debug, info, instrument, span, trace, warn, Level};
use x509_parser::nom::bytes::complete::tag_no_case;

use super::device::{FidoDevice as Device, FidoEndpoints as Endpoints};
use super::gatt::{get_gatt_characteristic, get_gatt_service};
use super::Error;

use crate::fido::FidoProtocol;
use crate::fido::FidoRevision;
use crate::transport::ble::framing::{
    BleCommand, BleFrame as Frame, BleFrameParser, BleFrameParserResult,
};

use blurz::{
    BluetoothAdapter, BluetoothDevice, BluetoothDiscoverySession, BluetoothEvent,
    BluetoothGATTCharacteristic, BluetoothSession,
};

use byteorder::{BigEndian, ReadBytesExt};

pub const WAIT_LOOP_MS: u32 = 250;
pub const CONNECT_MAX_TIMEOUT_MS: i32 = 30_000;
pub const SERVICES_DISCOVERY_MAX_TIMEOUT_MS: u32 = 5_000;
pub const DEVICE_RESPONSE_TIMEOUT_MS: u32 = 3_000;
pub const FIDO_PROFILE_UUID: &str = "0000fffd-0000-1000-8000-00805f9b34fb";

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

#[derive(Debug, Copy, Clone)]
pub struct SupportedRevisions {
    pub u2fv11: bool,
    pub u2fv12: bool,
    pub v2: bool,
}

impl SupportedRevisions {
    pub fn select_protocol(&self, protocol: FidoProtocol) -> Option<FidoRevision> {
        match protocol {
            FidoProtocol::FIDO2 => {
                if self.v2 {
                    Some(FidoRevision::V2)
                } else {
                    None
                }
            }
            FidoProtocol::U2F => {
                if self.u2fv12 {
                    Some(FidoRevision::U2fv12)
                } else if self.u2fv11 {
                    Some(FidoRevision::U2fv11)
                } else {
                    None
                }
            }
        }
    }
}

pub async fn start_discovery(uuids: &Vec<String>) -> Result<(), Error> {
    let span = span!(Level::INFO, "start_discovery");
    let uuids = uuids.to_owned();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        start_discovery_blocking(&uuids)
    })
    .await
    .unwrap()
}

pub async fn list_devices() -> Result<Vec<Device>, Error> {
    let span = span!(Level::INFO, "list_devices");
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        list_devices_blocking()
    })
    .await
    .unwrap()
}

pub async fn supported_fido_revisions(target: &Device) -> Result<SupportedRevisions, Error> {
    let span = span!(Level::DEBUG, "supported_fido_revisions");
    let target = target.to_owned();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        supported_fido_revisions_blocking(&target)
    })
    .await
    .unwrap()
}

pub async fn connect(device: &Device, revision: &FidoRevision) -> Result<Connection, Error> {
    let span = span!(Level::DEBUG, "connect");
    let device = device.to_owned();
    let revision = revision.to_owned();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        connect_blocking(&device, &revision)
    })
    .await
    .unwrap()
}

pub async fn frame_send(
    connection: &Connection,
    frame: &Frame,
    timeout: Duration,
) -> Result<(), Error> {
    let span = span!(Level::DEBUG, "frame_send");
    // tokio::task::block_in_place(|| {
    let _enter = span.enter();
    frame_send_blocking(connection, frame, timeout)
    //})
}

pub async fn frame_recv(connection: &Connection, timeout: Duration) -> Result<Frame, Error> {
    let span = span!(Level::DEBUG, "frame_recv");
    // tokio::task::block_in_place(|| {
    let _enter = span.enter();
    frame_recv_blocking(connection, timeout)
    // })
}

pub async fn notify_start(connection: &Connection) -> Result<(), Error> {
    let span = span!(Level::DEBUG, "notify_start");
    tokio::task::block_in_place(|| {
        let _enter = span.enter();
        notify_start_blocking(connection)
    })
}

#[instrument(skip_all)]
pub fn notify_stop(connection: &Connection) -> Result<(), Error> {
    notify_stop_blocking(connection)
}

fn start_discovery_blocking(uuids: &Vec<String>) -> Result<(), Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    let adapter = BluetoothAdapter::init(&session).or(Err(Error::Unavailable))?;
    if !adapter.is_powered().unwrap() {
        return Err(Error::PoweredOff);
    };
    let discovery_session =
        BluetoothDiscoverySession::create_session(&session, adapter.get_id()).unwrap();
    discovery_session
        .set_discovery_filter(uuids.to_owned(), None, None)
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

#[derive(Debug)]
pub struct Connection {
    session: BluetoothSession,
    endpoints: Endpoints,
}

unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

fn connect_blocking(device: &Device, revision: &FidoRevision) -> Result<Connection, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    connect_and_pair(&session, device)?;
    let endpoints = discover_services(&session, device)?;
    select_fido_revision(&session, &endpoints, revision)?;

    Ok(Connection { session, endpoints })
}

fn frame_send_blocking(
    connection: &Connection,
    frame: &Frame,
    _timeout: Duration,
) -> Result<(), Error> {
    let max_fragment_size = control_point_length(&connection.session, &connection.endpoints)?;
    let fragments = frame
        .fragments(max_fragment_size)
        .or(Err(Error::InvalidFraming))?;

    let control_point = BluetoothGATTCharacteristic::new(
        &connection.session,
        connection.endpoints.control_point.clone(),
    );
    for (i, fragment) in fragments.into_iter().enumerate() {
        debug!({ fragment = i, len = fragment.len() }, "Sending fragment");
        trace!(?fragment);

        control_point
            .write_value(fragment, None)
            .or(Err(Error::OperationFailed))?;
    }

    Ok(())
}

fn notify_start_blocking(connection: &Connection) -> Result<(), Error> {
    let status =
        BluetoothGATTCharacteristic::new(&connection.session, connection.endpoints.status.clone());
    status.start_notify().or(Err(Error::OperationFailed))?;
    debug!("Registered for notifications on FIDO status endpoint");
    Ok(())
}

fn notify_stop_blocking(connection: &Connection) -> Result<(), Error> {
    let status =
        BluetoothGATTCharacteristic::new(&connection.session, connection.endpoints.status.clone());
    status.stop_notify().or(Err(Error::OperationFailed))?;
    debug!("Unregistered for notifications");
    Ok(())
}

fn frame_recv_blocking(connection: &Connection, timeout: Duration) -> Result<Frame, Error> {
    let frame = wait_for_response(&connection.session, &connection.endpoints, timeout)?;
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
            { len = max_fragment_length.len() },
            "Control point length endpoint returned an unexpected number of bytes",
        );
        return Err(Error::OperationFailed);
    }

    let mut cursor = IOCursor::new(max_fragment_length);
    let max_fragment_size = cursor.read_u16::<BigEndian>().unwrap() as usize;
    Ok(max_fragment_size)
}

#[instrument(level = Level::DEBUG, skip_all)]
fn connect_and_pair(session: &BluetoothSession, target: &Device) -> Result<(), Error> {
    let device = BluetoothDevice::new(session, target.path.clone());
    if !device.is_paired().or(Err(Error::Unavailable))? {
        info!("Sending pairing required to target device");
        device.pair().or(Err(Error::ConnectionFailed))?;
    }
    if !device.is_connected().or(Err(Error::Unavailable))? {
        debug!(
            { timeout_ms = CONNECT_MAX_TIMEOUT_MS },
            "Attempting connection..."
        );
        device
            .connect(CONNECT_MAX_TIMEOUT_MS)
            .or(Err(Error::ConnectionFailed))?;
    }
    wait_until_services_resolved(&device)?;
    info!("Connected to target device");
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
            debug!({ count = services.len() }, "GATT services discovered");
            return Ok(());
        }
        if waited_for >= SERVICES_DISCOVERY_MAX_TIMEOUT_MS {
            warn!("Timed out whilst waiting for services to be resolved");
            return Err(Error::ConnectionFailed);
        }
        debug!("Services not yet resolved. Waiting {} ms.", WAIT_LOOP_MS);
        sleep(Duration::from_millis(WAIT_LOOP_MS as u64));
        waited_for += WAIT_LOOP_MS;
    }
}

#[instrument(level = Level::DEBUG, skip_all)]
fn discover_services(session: &BluetoothSession, target: &Device) -> Result<Endpoints, Error> {
    debug!("Attempting to discover FIDO services.");
    let device = BluetoothDevice::new(session, target.path.clone());
    let fido_service =
        get_gatt_service(&session, &device, FIDO_PROFILE_UUID).or(Err(Error::ConnectionFailed))?;
    debug!({ uuid = FIDO_PROFILE_UUID }, "Discovered FIDO service");
    trace!(?fido_service);

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

fn supported_fido_revisions_blocking(target: &Device) -> Result<SupportedRevisions, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    connect_and_pair(&session, target)?;
    let endpoints = discover_services(&session, target)?;

    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-protocol-overview
    let service_revision_bitfield =
        BluetoothGATTCharacteristic::new(&session, endpoints.service_revision_bitfield.into());
    let revision = service_revision_bitfield
        .read_value(None)
        .or(Err(Error::OperationFailed))?;
    let bitfield = revision.iter().next().ok_or(Error::OperationFailed)?;
    debug!(?revision, "Supported revision bitfield");

    let supported = SupportedRevisions {
        u2fv11: bitfield & FidoRevision::U2fv11 as u8 != 0x00,
        u2fv12: bitfield & FidoRevision::U2fv12 as u8 != 0x00,
        v2: bitfield & FidoRevision::V2 as u8 != 0x00,
    };
    info!(?supported, "Device reported supporting FIDO revisions");
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

    info!(?revision, "Successfully selected FIDO revision");
    Ok(())
}

fn wait_for_response(
    session: &BluetoothSession,
    endpoints: &Endpoints,
    timeout: Duration,
) -> Result<Frame, Error> {
    let mut waited_for = 0;
    loop {
        let fragments = receive_fragments(session, endpoints, WAIT_LOOP_MS);
        waited_for += WAIT_LOOP_MS;
        debug!({ count = fragments.len() }, "Received response fragments");
        trace!(?fragments);

        let mut parser = BleFrameParser::new();
        for fragment in &fragments {
            let status = parser.update(fragment).or(Err(Error::InvalidFraming))?;
            match status {
                BleFrameParserResult::Done => {
                    let frame = parser.frame().unwrap();
                    trace!(?frame, "Received frame");
                    match frame.cmd {
                        BleCommand::Keepalive => {
                            waited_for = 0;
                            debug!("Received keep-alive from authenticator");
                            parser.reset();
                        }
                        BleCommand::Cancel => {
                            info!("Device canceled operation");
                            return Err(Error::Canceled);
                        }
                        BleCommand::Error => {
                            warn!("Received error frame");
                            return Err(Error::OperationFailed);
                        }
                        BleCommand::Ping => {
                            debug!("Ignoring ping from device");
                        }
                        BleCommand::Msg => {
                            debug!("Received operation response");
                            return Ok(frame);
                        }
                    }
                }
                BleFrameParserResult::MoreFragmentsExpected => {}
            }
        }

        if waited_for > timeout.as_millis() as u32 {
            warn!("Timeout waiting for a response from the BLE device");
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

/// Finds all devices that advertise a given service UUID, and returns a map of device to service data.
#[instrument(level = Level::DEBUG, skip_all)]
fn devices_by_service_blocking(uuid: &str) -> Result<HashMap<Device, Vec<u8>>, Error> {
    let session = BluetoothSession::create_session(None).or(Err(Error::Unavailable))?;
    let adapter = BluetoothAdapter::init(&session).or(Err(Error::Unavailable))?;
    let devices = adapter
        .get_device_list()
        .or(Err(Error::Unavailable))?
        .iter()
        .map(|device_path| BluetoothDevice::new(&session, device_path.into()))
        .map(|device| (device.clone(), device.get_service_data()))
        .filter_map(|(device, service_data)| match service_data {
            Ok(data) => {
                let services = device.get_gatt_services().unwrap();
                debug!(?device, ?data, ?services, "Found device with service data");
                if let Some(data) = data.get(uuid) {
                    Some((device, data.clone()))
                } else {
                    None
                }
            }
            Err(_) => None,
        })
        .map(|(device, data)| {
            (
                Device::new(
                    &device.get_id(),
                    &device.get_alias().unwrap(),
                    device.is_paired().unwrap(),
                    device.is_connected().unwrap(),
                ),
                data,
            )
        })
        .collect();
    Ok(devices)
}

pub async fn devices_by_service(uuid: &str) -> Result<HashMap<Device, Vec<u8>>, Error> {
    let span = span!(Level::DEBUG, "devices_by_service");
    let uuid = uuid.to_owned();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        devices_by_service_blocking(&uuid)
    })
    .await
    .unwrap()
}
