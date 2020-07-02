use blurz::bluetooth_gatt_characteristic::BluetoothGATTCharacteristic;
use blurz::bluetooth_gatt_service::BluetoothGATTService;
use blurz::bluetooth_session::BluetoothSession;

use crate::transport::error::TransportError;

pub fn get_gatt_characteristic<'a>(
    session: &'a BluetoothSession,
    service: &BluetoothGATTService<'a>,
    uuid: &str,
) -> Result<BluetoothGATTCharacteristic<'a>, TransportError> {
    service
        .get_gatt_characteristics()
        .unwrap()
        .iter()
        .map(|char_path| BluetoothGATTCharacteristic::new(session, char_path.to_owned()))
        .find(|charct| charct.get_uuid().unwrap() == uuid)
        .ok_or(TransportError::InvalidEndpoint)
}
