pub mod device;
pub mod error;
pub mod gatt;
pub mod manager;

pub use device::FidoDevice;
pub use error::Error;
pub use manager::{
    connect, devices_by_service, frame_recv, frame_send, list_devices, notify_start, notify_stop,
    start_discovery, supported_fido_revisions, Connection,
};
