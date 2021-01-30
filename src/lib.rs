pub mod ops;
pub mod proto;
pub mod transport;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate bitflags;

#[derive(Debug)]
pub enum Transport {
    Usb,
    Ble,
}

pub fn available_transports() -> Vec<Transport> {
    vec![Transport::Usb, Transport::Ble]
}
