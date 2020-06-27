use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_descriptor::BluetoothGATTDescriptor;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use super::error::Error as BLEError;

pub fn get_gatt_characteristic<'a>(
    session: &'a BluetoothSession,
    service: &BluetoothGATTService<'a>,
    uuid: &str,
) -> Result<BluetoothGATTCharacteristic<'a>, BLEError> {
    service
        .get_gatt_characteristics()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTCharacteristic::new(session, char_path.to_owned()))
        .find(|charct| charct.get_uuid().unwrap() == uuid)
        .ok_or(BLEError::AuthenticatorError)
}

pub fn get_gatt_descriptor<'a>(
    session: &'a BluetoothSession,
    characteristic: &BluetoothGATTCharacteristic<'a>,
) -> Result<BluetoothGATTDescriptor<'a>, BLEError> {
    characteristic
        .get_gatt_descriptors()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTDescriptor::new(session, char_path.to_owned()))
        .next()
        .ok_or(BLEError::AuthenticatorError)
}
