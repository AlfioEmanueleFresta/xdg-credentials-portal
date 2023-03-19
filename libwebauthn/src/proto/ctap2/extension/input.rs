use std::collections::BTreeMap;

use serde_cbor::Value;

pub type Ctap2ExtensionInput = BTreeMap<String, Value>;

#[cfg(test)]
mod tests {
    use serde_cbor::{to_vec, Value};

    use super::Ctap2ExtensionInput;

    #[test]
    fn test_serialize_empty() {
        let map = Ctap2ExtensionInput::new();
        let actual = to_vec(&map).unwrap();
        let expected: Vec<u8> = vec![0xA0 /* map(0) */];
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_serialize_values() {
        let mut map = Ctap2ExtensionInput::new();
        map.insert("b".to_owned(), Value::Bool(true));
        map.insert("i".to_owned(), Value::Integer(1));
        let actual = to_vec(&map).unwrap();
        let expected: Vec<u8> = vec![
            0xA2, /* map(2) */
            0x61, /*  text(1) */
            0x62, /*   "b" */
            0xF5, /*  primitive(21) */
            0x61, /*  text(1) */
            0x69, /*   "i" */
            0x01, /*  unsigned(1) */
        ];
        assert_eq!(expected, actual);
    }
}
