use std::io;

#[derive(Debug)]
pub enum Ctap1Transport {
    BT,
    BLE,
    NFC,
    USB,
}

#[derive(Debug)]
pub enum Ctap1Version {
    U2fV2,
}

#[derive(Debug)]
pub enum Ctap1Error {
    OtherError,
    BadRequest,
    ConfigurationUnsupported,
    DeviceIneligible,
    Timeout,
}

#[derive(Debug)]
pub struct Ctap1RegisteredKey {
    pub version: Ctap1Version,
    pub key_handle: Vec<u8>,
    pub transports: Option<Vec<Ctap1Transport>>,
    pub app_id: Option<String>,
}

impl Ctap1RegisteredKey {
    pub fn new_u2f_v2(key_handle: &[u8]) -> Ctap1RegisteredKey {
        Ctap1RegisteredKey {
            version: Ctap1Version::U2fV2,
            key_handle: Vec::from(key_handle),
            transports: None,
            app_id: None,
        }
    }
}

#[derive(Debug)]
pub struct Ctap1RegisterRequest {
    pub version: Ctap1Version,
    pub app_id: String,
    pub challenge: Vec<u8>,
    pub registered_keys: Vec<Ctap1RegisteredKey>,
    pub timeout_seconds: u32,
}

impl Ctap1RegisterRequest {
    pub fn new_u2f_v2(
        app_id: &str,
        challenge: &[u8],
        registered_keys: Vec<Ctap1RegisteredKey>,
        timeout_seconds: u32,
    ) -> Ctap1RegisterRequest {
        Ctap1RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id: String::from(app_id),
            challenge: Vec::from(challenge),
            registered_keys,
            timeout_seconds,
        }
    }
}

#[derive(Debug)]
pub struct Ctap1RegisterResponse {
    pub version: Ctap1Version,
    pub registration_data: Vec<u8>,
    pub client_data: Vec<u8>,
}

impl Ctap1RegisterResponse {
    pub fn as_registered_key(&self) -> Result<Ctap1RegisteredKey, io::Error> {
        if self.registration_data[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Reserved byte not set correctly",
            ));
        }

        let key_handle_len = self.registration_data[66] as usize;
        let mut public_key = self.registration_data.to_owned();
        let mut key_handle = public_key.split_off(67);
        let _attestation = key_handle.split_off(key_handle_len);

        Ok(Ctap1RegisteredKey::new_u2f_v2(&key_handle))
    }
}

#[derive(Debug)]
pub struct Ctap1SignRequest {
    pub app_id: String,
    pub challenge: Vec<u8>,
    pub registered_keys: Vec<Ctap1RegisteredKey>,
    pub timeout_seconds: u32,
}

impl Ctap1SignRequest {
    pub fn new(
        app_id: &str,
        challenge: &[u8],
        registered_keys: Vec<Ctap1RegisteredKey>,
        timeout_seconds: u32,
    ) -> Ctap1SignRequest {
        Ctap1SignRequest {
            app_id: String::from(app_id),
            challenge: Vec::from(challenge),
            registered_keys,
            timeout_seconds,
        }
    }
}

#[derive(Debug)]
pub struct Ctap1SignResponse {
    pub key_handle: Vec<u8>,
    pub signature_data: Vec<u8>,
    pub client_data: Vec<u8>,
}
