use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use cosey::PublicKey;
use serde::{
    de::{DeserializeOwned, Error as DesError, Visitor},
    ser::Error as SerError,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use std::{
    fmt,
    io::{Cursor, Read},
    marker::PhantomData,
};
use tracing::warn;

use crate::proto::{
    ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType},
    CtapError,
};

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

bitflags! {
    #[derive(Debug, Clone)]
    pub struct AuthenticatorDataFlags: u8 {
        const USER_PRESENT = 0x01;
        const RFU_1 = 0x02;
        const USER_VERIFIED = 0x04;
        const RFU_2_1 = 0x08;
        const RFU_2_2 = 0x10;
        const RFU_2_3 = 0x20;
        const ATTESTED_CREDENTIALS = 0x40;
        const EXTENSION_DATA = 0x80;
    }
}

#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: PublicKey,
}

impl Serialize for AttestedCredentialData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Name                 | Length
        // --------------------------------
        //  aaguid              | 16
        //  credentialIdLenght  | 2
        //  credentialId        | L
        //  credentialPublicKey | variable
        let mut res = self.aaguid.to_vec();
        res.write_u16::<BigEndian>(self.credential_id.len() as u16)
            .map_err(SerError::custom)?;
        res.extend(&self.credential_id);
        let cose_encoded_public_key =
            serde_cbor::to_vec(&self.credential_public_key).map_err(SerError::custom)?;
        res.extend(cose_encoded_public_key);
        serializer.serialize_bytes(&res)
    }
}

impl From<&AttestedCredentialData> for Ctap2PublicKeyCredentialDescriptor {
    fn from(data: &AttestedCredentialData) -> Self {
        Self {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(data.credential_id.clone()),
            transports: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorData<T> {
    pub rp_id_hash: [u8; 32],
    pub flags: AuthenticatorDataFlags,
    pub signature_count: u32,
    pub attested_credential: Option<AttestedCredentialData>,
    pub extensions: Option<T>,
}

impl<T> Serialize for AuthenticatorData<T>
where
    T: Clone + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Name                    | Length
        // -----------------------------------
        // rpIdHash                | 32
        // flags                   | 1
        // signCount               | 4
        // attestedCredentialData  | variable
        // extensions              | variable
        let mut res = self.rp_id_hash.to_vec();
        res.push(self.flags.bits());
        res.write_u32::<BigEndian>(self.signature_count)
            .map_err(SerError::custom)?;
        if let Some(att_data) = &self.attested_credential {
            res.extend(serde_cbor::to_vec(att_data).map_err(SerError::custom)?);
        }
        if let Some(extensions) = &self.extensions {
            res.extend(serde_cbor::to_vec(extensions).map_err(SerError::custom)?);
        }
        serializer.serialize_bytes(&res)
    }
}

impl<T> TryFrom<&AuthenticatorData<T>> for Ctap2PublicKeyCredentialDescriptor {
    type Error = CtapError;

    fn try_from(data: &AuthenticatorData<T>) -> Result<Self, Self::Error> {
        if let Some(att_data) = &data.attested_credential {
            Ok(att_data.into())
        } else {
            warn!("Failed to parse credential ID: invalid authenticator data length");
            Err(CtapError::InvalidCredential)
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for AuthenticatorData<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This is a bit ugly. The Visitor needs _something_ of type T (which is Deserialize),
        // for the compiler to grok this. So we have to add PhantomData of type T here, in
        // order for us to be able to specify "type Value = AuthenticatorData<T>"
        struct AuthenticatorDataVisitor<T>(PhantomData<T>);

        impl<'de, T: DeserializeOwned> Visitor<'de> for AuthenticatorDataVisitor<T> {
            type Value = AuthenticatorData<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ByteBuf: Authenticator data")
            }

            fn visit_bytes<E>(self, data: &[u8]) -> Result<Self::Value, E>
            where
                E: DesError,
            {
                // Name                    | Length      | Start index
                // ---------------------------------------------------
                // rpIdHash                | 32          | 0
                // flags                   | 1           | 32
                // signCount               | 4           | 33
                // attestedCredentialData  | variable    |
                //     aaguid              |    16       | 37
                //     credentialIdLenght  |    2        | 53
                //     credentialId        |    L        | 55
                //     credentialPublicKey |    variable |
                // extensions              | variable    | variable

                // -> 32 + 1 + 4 = 37
                if data.len() < 37 {
                    return Err(DesError::invalid_length(data.len(), &"37"));
                }

                let mut cursor = Cursor::new(&data);
                let mut rp_id_hash = [0u8; 32];
                cursor.read_exact(&mut rp_id_hash).unwrap(); // We checked the length
                let flags_raw = cursor.read_u8().unwrap(); // We checked the length
                let flags = AuthenticatorDataFlags::from_bits_truncate(flags_raw);
                let signature_count = cursor.read_u32::<BigEndian>().unwrap(); // We checked the length

                let mut attested_credential = None;
                if flags.contains(AuthenticatorDataFlags::ATTESTED_CREDENTIALS) {
                    // -> 32 + 1 + 4 + 16 + 2 + X = 55
                    if data.len() < 55 {
                        return Err(DesError::invalid_length(data.len(), &"55"));
                    }

                    let mut aaguid = [0u8; 16];
                    cursor.read_exact(&mut aaguid).unwrap(); // We checked the length
                    let credential_id_len = cursor.read_u16::<BigEndian>().unwrap() as usize; // We checked the length
                    if data.len() < 55 + credential_id_len {
                        return Err(DesError::invalid_length(data.len(), &"55+L"));
                    }
                    let mut credential_id = vec![0u8; credential_id_len];
                    cursor.read_exact(&mut credential_id).unwrap(); // We checked the length

                    let mut deserializer = serde_cbor::Deserializer::from_reader(&mut cursor);
                    let credential_public_key: PublicKey =
                        Deserialize::deserialize(&mut deserializer).map_err(DesError::custom)?;

                    attested_credential = Some(AttestedCredentialData {
                        aaguid,
                        credential_id,
                        credential_public_key,
                    });
                }

                let extensions: Option<T> =
                    if flags.contains(AuthenticatorDataFlags::EXTENSION_DATA) {
                        serde_cbor::from_reader(&mut cursor).map_err(DesError::custom)?
                    } else {
                        Default::default()
                    };

                Ok(AuthenticatorData {
                    rp_id_hash,
                    flags,
                    signature_count,
                    attested_credential,
                    extensions,
                })
            }
        }

        deserializer.deserialize_bytes(AuthenticatorDataVisitor(PhantomData))
    }
}
