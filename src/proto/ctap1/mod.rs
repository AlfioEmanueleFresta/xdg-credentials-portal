mod protocol;

pub mod apdu;

pub use self::protocol::Ctap1RegisteredKey;
pub use self::protocol::Ctap1VersionRequest;
pub use self::protocol::{Ctap1Error, Ctap1Version};
pub use self::protocol::{Ctap1RegisterRequest, Ctap1RegisterResponse};
pub use self::protocol::{Ctap1SignRequest, Ctap1SignResponse};

use sha2::{Digest, Sha256};

pub fn build_client_data(challenge: &Vec<u8>, app_id: &String) -> (String, Vec<u8>) {
    let challenge_base64url = base64_url::encode(&challenge);
    let version_string = "U2F_V2";

    let client_data = format!(
        "{{\"challenge\": \"{}\", \"version:\": \"{}\", \"appId\": \"{}\"}}",
        challenge_base64url, version_string, app_id
    );

    let mut hasher = Sha256::default();
    hasher.input(client_data.as_bytes());
    let client_data_hash = hasher.result().to_vec();

    (client_data, client_data_hash)
}
