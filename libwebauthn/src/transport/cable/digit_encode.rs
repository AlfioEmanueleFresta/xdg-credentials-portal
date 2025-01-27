const CHUNK_SIZE: usize = 7;
const CHUNK_DIGITS: usize = 17;
const ZEROS: &str = "00000000000000000";

/// The number of digits needed to encode each length of trailing data from 6 bytes down to zero,
/// i.e. it’s 15, 13, 10, 8, 5, 3, 0 written in hex.
const PARTIAL_CHUNK_DIGITS: usize = 0x0fda8530;

pub fn digit_encode(input: &[u8]) -> String {
    let mut output = String::new();
    let mut input = input;
    while input.len() >= CHUNK_SIZE {
        let mut chunk = [0u8; 8];
        chunk[..CHUNK_SIZE].copy_from_slice(&input[..CHUNK_SIZE]);
        let v = u64::from_le_bytes(chunk);
        let v = v.to_string();
        output.push_str(&ZEROS[..CHUNK_DIGITS - v.len()]);
        output.push_str(&v);
        input = &input[CHUNK_SIZE..];
    }
    if !input.is_empty() {
        let digits = 0x0F & (PARTIAL_CHUNK_DIGITS >> (4 * input.len()));
        let mut chunk = [0u8; 8];
        chunk[..input.len()].copy_from_slice(input);
        let v = u64::from_le_bytes(chunk);
        let v = v.to_string();
        output.push_str(&ZEROS[..digits - v.len()]);
        output.push_str(&v);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::digit_encode;

    #[test]
    fn test_digit_encode() {
        assert_eq!(digit_encode(b"hello world"), "335311851610699281684828783")
    }
}
