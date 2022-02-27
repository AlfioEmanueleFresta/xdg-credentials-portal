#![feature(let_else)]
#![feature(option_get_or_insert_default)]

pub mod fido;
pub mod ops;
pub mod pin;
pub mod proto;
pub mod transport;
pub mod u2f;
pub mod webauthn;

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
