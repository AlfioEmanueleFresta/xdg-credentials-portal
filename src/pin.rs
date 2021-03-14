extern crate async_trait;
extern crate log;

use async_trait::async_trait;
use log::info;

pub struct PinUvAuthToken {
    pub rpid: Option<String>,
    pub user_verified: bool,
    pub user_present: bool,
}

impl Default for PinUvAuthToken {
    fn default() -> Self {
        Self {
            rpid: None,
            user_verified: false,
            user_present: false,
        }
    }
}

#[async_trait]
pub trait PinProvider {
    async fn provide_pin(&self, attempts_left: Option<u32>) -> Option<String>;
}

#[derive(Debug, Clone)]
pub struct StaticPinProvider {
    pin: String,
}

impl StaticPinProvider {
    pub fn new(pin: &str) -> Self {
        Self {
            pin: pin.to_owned(),
        }
    }
}

#[async_trait]
impl PinProvider for StaticPinProvider {
    async fn provide_pin(&self, attempts_left: Option<u32>) -> Option<String> {
        info!(
            "Providing static PIN '{}' ({:?} attempts left)",
            self.pin, attempts_left
        );
        Some(self.pin.clone())
    }
}
