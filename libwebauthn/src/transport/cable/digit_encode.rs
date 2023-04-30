const CHUNK_SIZE: usize = 7;
const CHUNK_DIGITS: usize = 17;
const ZEROS: &str = "00000000000000000";


pub fn digit_encode(bytes: &[u8]) -> String {
    let mut input = Vec::from(bytes);
    let mut output = String::new();

    while input.len() >= CHUNK_SIZE {
        let chunk: &[u8] = &input[..CHUNK_SIZE];
        // TODO: [u8] to u64
        let chunk: u64 = todo!();
        let v = format!("{}", chunk);

    }

    "ok".to_owned()
    //
    /// fundigitEncode(d []byte) string {
        // const chunkSize = 7
        // const chunkDigits = 17
        // const zeros = "00000000000000000"
        // var ret string
        // for len(d) >= chunkSize {
            // var chunk [8]byte
            // copy(chunk[:], d[:chunkSize])
            // v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
            // ret += zeros[:chunkDigits-len(v)]
            // ret += v
            // d = d[chunkSize:]
        // }
        // if len(d) != 0 {
            // // partialChunkDigits is the number of digits needed to encode
            // // each length of trailing data from 6 bytes down to zero. I.e.
            // // it’s 15, 13, 10, 8, 5, 3, 0 written in hex.
            // const partialChunkDigits = 0x0fda8530
            // digits := 15 & (partialChunkDigits >> (4 * len(d)))
            // var chunk [8]byte
            // copy(chunk[:], d)
            // v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
            // ret += zeros[:digits-len(v)]
            // ret += v
        // }
        // return ret
    // }
}
