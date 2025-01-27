use std::time::Duration;

use byteorder::{BigEndian, WriteBytesExt};
use ctap_types::cose;
use serde_bytes::ByteBuf;
use serde_cbor::to_vec;
use sha2::{Digest, Sha256};
use tracing::{error, trace};
use x509_parser::nom::AsBytes;

use super::webauthn::MakeCredentialRequest;
use crate::ops::webauthn::{GetAssertionResponse, MakeCredentialResponse};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};
use crate::proto::ctap2::{
    Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2GetAssertionResponse,
    Ctap2MakeCredentialResponse, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType,
    FidoU2fAttestationStmt,
};
use crate::webauthn::{CtapError, Error};

// FIDO U2F operations can be aliased to CTAP1 requests, as they have no other representation.
pub type RegisterRequest = Ctap1RegisterRequest;
pub type RegisterResponse = Ctap1RegisterResponse;
pub type SignRequest = Ctap1SignRequest;
pub type SignResponse = Ctap1SignResponse;

impl SignRequest {
    pub fn new_upgraded(
        rp_id_hash: &[u8],
        challenge: &[u8],
        key_handle: &[u8],
        timeout: Duration,
    ) -> Self {
        Self {
            app_id_hash: Vec::from(rp_id_hash),
            challenge: Vec::from(challenge),
            key_handle: Vec::from(key_handle),
            timeout,
            require_user_presence: true,
        }
    }
}

pub trait UpgradableResponse<T, R> {
    fn try_upgrade(&self, request: &R) -> Result<T, Error>;
}

impl UpgradableResponse<MakeCredentialResponse, MakeCredentialRequest> for RegisterResponse {
    fn try_upgrade(
        &self,
        request: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        // Initialize attestedCredData:
        // Let credentialIdLength be a 2-byte unsigned big-endian integer representing length of the Credential ID
        // initialized with CTAP1/U2F response key handle length.
        let credential_id_len: usize = self.key_handle.len();

        // Let x9encodedUserPublicKeybe the user public key returned in the U2F registration response message [U2FRawMsgs].
        // Let coseEncodedCredentialPublicKey be the result of converting x9encodedUserPublicKey’s value
        // from ANS X9.62 / Sec-1 v2 uncompressed curve point representation [SEC1V2]
        // to COSE_Key representation ([RFC8152] Section 7).
        let Ok(encoded_point) = p256::EncodedPoint::from_bytes(&self.public_key) else {
            error!(?self.public_key, "Failed to parse public key as SEC-1 v2 encoded point");
            return Err(Error::Ctap(CtapError::Other));
        };
        let x: heapless::Vec<u8, 32> = heapless::Vec::from_slice(
            encoded_point
                .x()
                .expect("Not the identity point")
                .as_bytes(),
        )
        .unwrap();
        let y: heapless::Vec<u8, 32> = heapless::Vec::from_slice(
            encoded_point
                .y()
                .expect("Not identity nor compressed")
                .as_bytes(),
        )
        .unwrap();
        let cose_public_key = cose::PublicKey::P256Key(cose::P256PublicKey {
            x: x.into(),
            y: y.into(),
        });
        let cose_encoded_public_key = to_vec(&cose_public_key).unwrap();
        assert!(cose_encoded_public_key.len() == 77);

        // Let attestedCredData be a byte string with following structure:
        //
        // Length (in bytes)   Description                        Value
        // -------------------------------------------------------------------------------------------------------------
        // 16                  The AAGUID of the authenticator.   Initialized with all zeros.
        // 2                   Byte length L of Credential ID     Initialized with credentialIdLength bytes.
        // credentialIdLength  Credential ID.                     Initialized with credentialId bytes.
        // 77                  The credential public key.         Initialized with coseEncodedCredentialPublicKey bytes.

        let mut attested_cred_data = Vec::new();
        attested_cred_data.extend(&[0u8; 16]); // aaguid zeros
        attested_cred_data
            .write_u16::<BigEndian>(credential_id_len as u16)
            .unwrap();
        attested_cred_data.extend(&self.key_handle);
        attested_cred_data.extend(cose_encoded_public_key);

        // Initialize authenticatorData:
        // Let flags be a byte whose zeroth bit (bit 0, UP) is set, and whose sixth bit (bit 6, AT) is set,
        // and all other bits are zero (bit zero is the least significant bit)
        let flags: u8 = 0b00000001 | 0b01000000;

        // Let signCount be a 4-byte unsigned integer initialized to zero.
        let sign_count: [u8; 4] = [0u8; 4];

        // Let authenticatorData be a byte string with the following structure:
        //
        // Length (in bytes)   Description                              Value
        // -------------------------------------------------------------------------------------------------------------
        // 32                  SHA-256 hash of the rp.id.               Initialized with rpIdHash bytes.
        // 1                   Flags                                    Initialized with flags' value.
        // 4                   Signature counter (signCount).           Initialized with signCount bytes.
        // Variable Length     Attested credential data.                Initialized with attestedCredData’s value.
        let mut auth_data = Vec::new();
        let mut hasher = Sha256::default();
        hasher.update(request.relying_party.id.as_bytes());
        let rp_id_hash = hasher.finalize().to_vec();
        auth_data.extend(rp_id_hash);
        auth_data.extend(&[flags]);
        auth_data.extend(&sign_count);
        auth_data.extend(&attested_cred_data);

        // Let attestationStatement be a CBOR map (see "attStmtTemplate" in Generating an Attestation Object [WebAuthn])
        // with the following keys, whose values are as follows:
        // * Set "x5c" as an array of the one attestation cert extracted from CTAP1/U2F response.
        // * Set "sig" to be the "signature" bytes from the U2F registration response message [U2FRawMsgs].
        //   Note: An ASN.1-encoded ECDSA signature value ranges over 8–72 bytes in length. [U2FRawMsgs] incorrectly
        //   states a different length range.
        let attestation_statement = Ctap2AttestationStatement::FidoU2F(FidoU2fAttestationStmt {
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            signature: ByteBuf::from(self.signature.clone()),
            certificates: vec![ByteBuf::from(self.attestation.clone())],
        });

        // Let attestationObject be a CBOR map (see "attObj" in Generating an Attestation Object [WebAuthn]) with the
        // following keys, whose values are as follows:
        // * Set "authData" to authenticatorData.
        // * Set "fmt" to "fido-u2f".
        // * Set "attStmt" to attestationStatement.
        Ok(Ctap2MakeCredentialResponse {
            format: String::from("fido-u2f"),
            authenticator_data: ByteBuf::from(auth_data),
            attestation_statement: attestation_statement,
            enterprise_attestation: None,
            large_blob_key: None,
            unsigned_extension_output: None,
        })
    }
}

impl UpgradableResponse<GetAssertionResponse, SignRequest> for SignResponse {
    fn try_upgrade(&self, request: &SignRequest) -> Result<GetAssertionResponse, Error> {
        // Generate authenticatorData from the U2F authentication response message received from the authenticator:

        // Copy bits 0 (the UP bit) and bit 1 from the CTAP2/U2F response user presence byte to bits 0 and 1 of the
        // CTAP2 flags, respectively. Set all other bits of flags to zero. Note: bit zero is the least significant bit.
        // See also Authenticator Data section of [WebAuthn].
        let mut flags: u8 = 0;
        flags |= 0b00000001; // up always set
                             // bit 1 is unused, ignoring

        // Let signCount be a 4-byte unsigned integer initialized with CTAP1/U2F response counter field.
        let sign_count = self.counter;

        // Let authenticatorData is a byte string of following structure:
        // Length (in bytes)        Description                     Value
        // -------------------------------------------------------------------------------------------------------------
        // 32                       SHA-256 hash of the rp.id.      Initialized with rpIdHash bytes.
        // 1                        Flags                           Initialized with flags' value.
        // 4                        Signature counter (signCount)   Initialized with signCount bytes.
        let mut auth_data = Vec::new();
        auth_data.extend(&request.app_id_hash);
        auth_data.extend(&[flags]);
        auth_data.write_u32::<BigEndian>(sign_count).unwrap();

        // Let authenticatorGetAssertionResponse be a CBOR map with the following keys whose values are as follows: [..]
        let upgraded_response: GetAssertionResponse = Ctap2GetAssertionResponse {
            credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(request.key_handle.clone()),
                transports: None,
            }),
            authenticator_data: ByteBuf::from(auth_data),
            signature: ByteBuf::from(self.signature.clone()),
            user: None,
            credentials_count: None,
            user_selected: None,
            large_blob_key: None,
            unsigned_extension_outputs: None,
            enterprise_attestation: None,
            attestation_statement: None,
        }
        .into();

        trace!(?upgraded_response);
        Ok(upgraded_response)
    }
}
