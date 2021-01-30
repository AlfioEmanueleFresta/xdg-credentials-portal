extern crate backend;
extern crate log;
extern crate tokio;

use backend::transport::hid::{list_devices, wink};
use log::info;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let devices = list_devices().await?;

    info!("Found {} devices.", devices.len());
    for device in &devices {
        info!("Winking device: {}", device);
        wink(&device).await?;
    }

    return Ok(());
}
