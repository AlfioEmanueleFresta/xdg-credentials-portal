#[derive(Debug, PartialEq, Eq)]
pub enum FidoProtocol {
    FIDO2,
    U2F,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[repr(u8)]
pub enum FidoRevision {
    V2 = 0x20,
    U2fv12 = 0x40,
    U2fv11 = 0x80,
}

impl From<FidoRevision> for FidoProtocol {
    fn from(revision: FidoRevision) -> Self {
        match revision {
            FidoRevision::V2 => FidoProtocol::FIDO2,
            FidoRevision::U2fv11 | FidoRevision::U2fv12 => FidoProtocol::U2F,
        }
    }
}

/*
bitflags! {
    pub struct AuthenticatorDataFlags: u8 {
        const USER_PRESENT = 0x01;
        const RFU_1 = 0x02;
        const USER_VERIFIED = 0x04;
        const RFU_2_1 = 0x08;
        const RFU_2_2 = 0x10;
        const RFU_2_3 = 0x20;
        const ATTESTED_CREDENTIALS = 0x30;
        const EXTENSION_DATA = 0x40;
    }
}

#[derive(Debug, Copy)]
pub struct AttestedCredentialData {
    pub raw: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}

#[derive(Debug, Copy)]
pub struct AuthenticatorData {
    pub raw: Vec<u8>,
    pub relying_party_id: Vec<u8>,
    pub flags: AuthenticatorDataFlags,
    pub signature_count: u32,
    pub attested_credential: Option<AttestedCredentialData>,
    pub extensions_cbor: Option<Vec<u8>>,
}
*/
