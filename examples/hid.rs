extern crate backend;
extern crate log;
extern crate tokio;

use backend::transport::hid::{list_devices, wink};

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let devices = list_devices().await?;

    for device in devices {
        println!("Found device: {:}", device);
        wink(&device).await?;
    }
    return Ok(());
}
