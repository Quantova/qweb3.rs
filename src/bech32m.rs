//! Bech32m (BIP-350) codec for Quantova's Q-branded address/key strings.
//!
//! Output uses only lowercase letters + digits (no symbols); callers uppercase it for the
//! capital-"Q" display form. Mirrors qweb3.js and qweb3.py byte-for-byte.

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32M_CONST: u32 = 0x2bc830a3;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        v.push(b >> 5);
    }
    v.push(0);
    for b in hrp.bytes() {
        v.push(b & 31);
    }
    v
}

fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let m = polymod(&values) ^ BECH32M_CONST;
    (0..6).map(|i| ((m >> (5 * (5 - i))) & 31) as u8).collect()
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32M_CONST
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv = (1u32 << to) - 1;
    for &value in data {
        let value = u32::from(value);
        if (value >> from) != 0 {
            return None;
        }
        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(ret)
}

/// Encode raw bytes as a Bech32m string with the given prefix (lowercase canonical form).
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let conv = convert_bits(data, 8, 5, true).expect("convert_bits (encode) cannot fail");
    let mut combined = conv.clone();
    combined.extend(create_checksum(hrp, &conv));
    let mut s = String::with_capacity(hrp.len() + 1 + combined.len());
    s.push_str(hrp);
    s.push('1');
    for d in combined {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Decode a Bech32m string, verifying prefix + checksum. Accepts upper- or lower-case.
pub fn decode(expected_hrp: &str, s: &str) -> Option<Vec<u8>> {
    let lower = s.to_lowercase();
    let upper = s.to_uppercase();
    if s != lower && s != upper {
        return None; // mixed case
    }
    let s = lower;
    let pos = s.rfind('1')?;
    if pos < 1 || pos + 7 > s.len() {
        return None;
    }
    if &s[..pos] != expected_hrp {
        return None;
    }
    let mut data = Vec::new();
    for c in s[pos + 1..].bytes() {
        let idx = CHARSET.iter().position(|&x| x == c)?;
        data.push(idx as u8);
    }
    if !verify_checksum(expected_hrp, &data) {
        return None;
    }
    convert_bits(&data[..data.len() - 6], 5, 8, false)
}
