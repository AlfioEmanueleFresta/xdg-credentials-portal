use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256, Block};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{instrument, warn};

use crate::pin::hmac_sha256;

pub enum KeyPurpose {
    EIDKey = 1,
    TunnelID = 2,
    PSK = 3,
}

/*


func derive(output, secret, salt []byte, purpose keyPurpose) {
    if uint32(purpose) >= 0x100 {
        panic("unsupported purpose")
    }

    var purpose32 [4]byte
    purpose32[0] = byte(purpose)

    h := hkdf.New(sha256.New, secret, salt, purpose32[:])
    if n, err := h.Read(output); err != nil || n != len(output) {
        panic("HKDF error")
    }
} */

pub fn derive(secret: &[u8], salt: Option<&[u8]>, purpose: KeyPurpose) -> Vec<u8> {
    let mut purpose32 = [0u8; 4];
    purpose32[0] = purpose as u8;

    let hkdf = Hkdf::<Sha256>::new(salt, secret);
    let mut output = vec![0u8; 32];
    hkdf.expand(&purpose32, &mut output).unwrap();
    output
}

fn reserved_bits_are_zero(plaintext: &[u8]) -> bool {
    plaintext[0] == 0
}

#[instrument]
pub fn trial_decrypt_advert(eid_key: &[u8], candidate_advert: &[u8]) -> Option<Vec<u8>> {
    if candidate_advert.len() != 20 {
        warn!("candidate advert is not 20 bytes");
        return None;
    }

    let expected_tag = hmac_sha256(eid_key, &candidate_advert[..16]);
    if expected_tag[..4] != candidate_advert[16..] {
        warn!({ expected = ?expected_tag[..4], actual = ?candidate_advert[16..] }, 
              "candidate advert HMAC tag does not match");
        return None;
    }

    let cipher = Aes256::new_from_slice(&eid_key[..32]).unwrap();
    let mut block = Block::clone_from_slice(&candidate_advert[..16]);
    cipher.decrypt_block(&mut block);

    if !reserved_bits_are_zero(&block) {
        warn!("reserved bits are not zero");
        return None;
    }

    Some(block.to_vec())
}
