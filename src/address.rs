//! Quantova address derivation.
//!
//! A canonical Quantova address is derived from a post-quantum public key:
//!
//! 1. hash the public key with **SHA3-256**,
//! 2. take the first **20 bytes** (H160 width) as the account body,
//! 3. set the **leading byte to `0x40`** (the fixed `Q` marker),
//! 4. the canonical address is the **Base64** encoding of those 20 bytes — it
//!    always begins with `Q`.
//!
//! All three signature schemes (Dilithium, Falcon, SPHINCS+) derive into this same
//! 20-byte address space.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha3::{Digest, Sha3_256};

use crate::error::{Error, Result};

/// The fixed leading byte of every Quantova account body (Base64 `0x40` -> `Q`).
pub const Q_MARKER: u8 = 0x40;

/// Derive the 20-byte Quantova account body (H160) from a post-quantum public key.
///
/// `account_id = SHA3-256(public_key)[..20]` with `account_id[0] = 0x40`.
pub fn account_id_from_public_key(public_key: &[u8]) -> [u8; 20] {
    let digest = Sha3_256::digest(public_key);
    let mut body = [0u8; 20];
    body.copy_from_slice(&digest[..20]);
    body[0] = Q_MARKER;
    body
}

/// Derive the canonical Quantova address (Base64 of the 20-byte body) from a public key.
///
/// The result always begins with `Q`.
pub fn address_from_public_key(public_key: &[u8]) -> String {
    B64.encode(account_id_from_public_key(public_key))
}

/// Decode a canonical Quantova address back to its 20-byte account body, validating it.
///
/// Returns [`Error::InvalidAddress`] if it is not valid Base64 of 20 bytes whose
/// leading byte is `0x40`.
pub fn decode_address(address: &str) -> Result<[u8; 20]> {
    let raw = B64
        .decode(address.trim())
        .map_err(|_| Error::InvalidAddress(address.to_string()))?;
    if raw.len() != 20 {
        return Err(Error::InvalidAddress(format!(
            "expected 20 bytes, got {}",
            raw.len()
        )));
    }
    if raw[0] != Q_MARKER {
        return Err(Error::InvalidAddress(
            "leading byte is not the Q marker (0x40)".into(),
        ));
    }
    let mut body = [0u8; 20];
    body.copy_from_slice(&raw);
    Ok(body)
}

/// Return `true` if `address` is a well-formed canonical Quantova address.
pub fn is_valid_address(address: &str) -> bool {
    decode_address(address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed public key 0x0001..1f -> known address (cross-checked independently).
    #[test]
    fn derives_known_address() {
        let pk: Vec<u8> = (0u8..32).collect();
        let addr = address_from_public_key(&pk);
        assert_eq!(addr, "QApIczvVwnVrqVxYKMyD7hb6vNM=");
        assert!(addr.starts_with('Q'));
    }

    #[test]
    fn roundtrips_address() {
        let pk: Vec<u8> = (0u8..32).collect();
        let addr = address_from_public_key(&pk);
        let body = decode_address(&addr).unwrap();
        assert_eq!(body[0], Q_MARKER);
        assert!(is_valid_address(&addr));
        assert!(!is_valid_address("0xnotanaddress"));
    }
}
