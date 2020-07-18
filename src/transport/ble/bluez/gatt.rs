use blurz::{BluetoothDevice, BluetoothGATTCharacteristic, BluetoothGATTService, BluetoothSession};

use super::Error;

pub fn get_gatt_characteristic<'a>(
    session: &'a BluetoothSession,
    service: &BluetoothGATTService<'a>,
    uuid: &str,
) -> Result<BluetoothGATTCharacteristic<'a>, Error> {
    service
        .get_gatt_characteristics()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTCharacteristic::new(session, char_path.to_owned()))
        .find(|charct| charct.get_uuid().unwrap() == uuid)
        .ok_or(Error::ConnectionFailed)
}

pub fn get_gatt_service<'a>(
    session: &'a BluetoothSession,
    device: &'a BluetoothDevice,
    uuid: &str,
) -> Result<BluetoothGATTService<'a>, Error> {
    device
        .get_gatt_services()
        .unwrap()
        .iter()
        .map(|service_path| BluetoothGATTService::new(&session, service_path.to_owned()))
        .find(|service| service.get_uuid().unwrap() == uuid)
        .ok_or(Error::ConnectionFailed)
}
