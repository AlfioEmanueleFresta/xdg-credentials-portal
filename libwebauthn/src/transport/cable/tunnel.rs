use sha2::{Digest, Sha256};

pub(crate) const KNOWN_TUNNEL_DOMAINS: &[&str] = &["cable.ua5v.com", "cable.auth.com"];
const SHA_INPUT: &[u8] = b"caBLEv2 tunnel server domain";
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const TLDS: &[&str] = &[".com", ".org", ".net", ".info"];

/**
 * Specs:
 *
 * func decodeTunnelServerDomain(encoded uint16) (string, bool) {
    if encoded < 256 {
        if int(encoded) >= len(assignedTunnelServerDomains) {
            return "", false
        }
        return assignedTunnelServerDomains[encoded], true
    }

    shaInput := []byte{
        0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
        0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
        0x6d, 0x61, 0x69, 0x6e,
    }
    shaInput = append(shaInput, byte(encoded), byte(encoded>>8), 0)
    digest := sha256.Sum256(shaInput)

    v := binary.LittleEndian.Uint64(digest[:8])
    tldIndex := uint(v & 3)
    v >>= 2

    ret := "cable."
    const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
    for v != 0 {
        ret += string(base32Chars[v&31])
        v >>= 5
    }

    tlds := []string{".com", ".org", ".net", ".info"}
    ret += tlds[tldIndex&3]

    return ret, true
}
*/

fn decode_tunnel_server_domain(encoded: u16) -> Option<String> {
    if encoded < 256 {
        if encoded as usize >= KNOWN_TUNNEL_DOMAINS.len() {
            return None;
        }
        return Some(KNOWN_TUNNEL_DOMAINS[encoded as usize].to_string());
    }

    let mut sha_input = SHA_INPUT.to_vec();
    sha_input.push(encoded as u8);
    sha_input.push((encoded >> 8) as u8);
    sha_input.push(0);
    let mut hasher = Sha256::default();
    hasher.update(&sha_input);
    let digest = hasher.finalize();

    let mut v = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let tld_index = v & 3;
    v >>= 2;

    let mut ret = String::from("cable.");
    while v != 0 {
        ret.push(BASE32_CHARS[(v & 31) as usize] as char);
        v >>= 5;
    }

    ret.push_str(TLDS[tld_index as usize]);
    Some(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_tunnel_server_domain_known() {
        assert_eq!(
            decode_tunnel_server_domain(0).unwrap(),
            "cable.ua5v.com".to_string()
        );
        assert_eq!(
            decode_tunnel_server_domain(1).unwrap(),
            "cable.auth.com".to_string()
        );
    }

    // TODO: test the non-known case
}
