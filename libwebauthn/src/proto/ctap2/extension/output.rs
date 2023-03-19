use crate::transport::error::CtapError;
use serde_cbor::{self, Value};
use std::collections::BTreeMap;
use tracing::error;

pub type Ctap2ExtensionOutput = BTreeMap<String, Value>;

pub fn from_slice(data: &[u8]) -> Result<Ctap2ExtensionOutput, CtapError> {
    let map_result: Result<BTreeMap<String, Value>, serde_cbor::Error> =
        serde_cbor::from_slice(data);
    match map_result {
        Ok(output) => return Ok(output),
        Err(err) => {
            error!({ %err, ?data }, "Unable to parse CTAP2 extension output");
            return Err(CtapError::InvalidCbor);
        }
    };
}

#[cfg(test)]
mod tests {
    use serde_cbor::Value;

    use crate::webauthn::CtapError;

    use super::from_slice;
    use super::Ctap2ExtensionOutput;

    #[test]
    fn test_deserialize_empty() {
        let serialized: Vec<u8> = vec![0xA0 /* map(0) */];
        let expected = Ctap2ExtensionOutput::new();
        let actual = from_slice(&serialized).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_deserialize_values() {
        let serialized: Vec<u8> = vec![
            0xA2, /* map(2) */
            0x61, /*  text(1) */
            0x62, /*   "b" */
            0xF5, /*  primitive(21) */
            0x61, /*  text(1) */
            0x69, /*   "i" */
            0x01, /*  unsigned(1) */
        ];
        let mut expected = Ctap2ExtensionOutput::new();
        expected.insert("b".to_owned(), Value::Bool(true));
        expected.insert("i".to_owned(), Value::Integer(1));

        let actual = from_slice(&serialized).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_deserialize_err() {
        let serialized: Vec<u8> = vec![0x80 /* array(0) */];
        let actual = from_slice(&serialized);
        let expected = Err(CtapError::InvalidCbor);
        assert_eq!(expected, actual);
    }
}
