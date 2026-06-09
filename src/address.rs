//! Quantova address derivation.
//!
//! A canonical Quantova account address is derived from a post-quantum public key:
//!
//! 1. hash the public key with **SHA3-256**,
//! 2. take the first **20 bytes** (H160 width) as the account body,
//! 3. set the **leading byte to `0x40`** (the fixed `Q` marker),
//! 4. the canonical address is the **Bech32m** encoding (prefix `q`) of those 20 bytes,
//!    shown upper-case — it always begins with `Q1` and contains only letters + digits.
//!
//! All three signature schemes (Dilithium, Falcon, SPHINCS+) derive into this same
//! 20-byte address space. Public keys are encoded as `QPUB1...` (Bech32m, prefix `qpub`).
//! Solidity/QVM contract addresses remain `0x` hex.

use sha3::{Digest, Sha3_256};

use crate::bech32m;
use crate::error::{Error, Result};

/// Bech32m human-readable prefixes.
const HRP_ADDRESS: &str = "q";
const HRP_PUBLIC: &str = "qpub";

/// The fixed leading byte of every Quantova account body (the `Q` marker).
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

/// Encode a 20-byte account body as a canonical `Q1...` address (Bech32m, upper-case).
pub fn body_to_address(body: &[u8]) -> String {
    bech32m::encode(HRP_ADDRESS, body).to_uppercase()
}

/// Derive the canonical Quantova account address (`Q1...`) from a public key.
pub fn address_from_public_key(public_key: &[u8]) -> String {
    body_to_address(&account_id_from_public_key(public_key))
}

/// Encode a public key as `QPUB1...` (Bech32m, upper-case).
pub fn public_key_to_q(public_key: &[u8]) -> String {
    bech32m::encode(HRP_PUBLIC, public_key).to_uppercase()
}

/// Decode a `Q1...` address back to its 20-byte account body, validating it.
pub fn decode_address(address: &str) -> Result<[u8; 20]> {
    let raw = bech32m::decode(HRP_ADDRESS, address.trim())
        .ok_or_else(|| Error::InvalidAddress(address.to_string()))?;
    if raw.len() != 20 {
        return Err(Error::InvalidAddress(format!("expected 20 bytes, got {}", raw.len())));
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

/// Return `true` if `address` is a well-formed canonical Quantova account address.
pub fn is_valid_address(address: &str) -> bool {
    decode_address(address).is_ok()
}

/// Translate a `Q1...` account address to the `0x`-hex form the node RPC expects;
/// any other value (e.g. a `0x` contract address) is returned unchanged.
pub fn to_node_address(address: &str) -> String {
    let lead = address.get(..2).unwrap_or("").to_uppercase();
    if lead == "Q1" {
        if let Ok(body) = decode_address(address) {
            return format!("0x{}", hex::encode(body));
        }
    }
    address.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed public key 0x00..1f -> known Q1 address (cross-checked against qweb3.js / qweb3.py).
    #[test]
    fn derives_known_address() {
        let pk: Vec<u8> = (0u8..32).collect();
        let addr = address_from_public_key(&pk);
        assert_eq!(addr, "Q1GQ9YSUEM6HP826AFT3VZ3NYRACT040XNKRUCWF");
        assert!(addr.starts_with("Q1"));
        assert!(!addr.contains(['/', '+', '_', '=']));
    }

    #[test]
    fn roundtrips_address() {
        let pk: Vec<u8> = (0u8..32).collect();
        let addr = address_from_public_key(&pk);
        let body = decode_address(&addr).unwrap();
        assert_eq!(body[0], Q_MARKER);
        assert!(is_valid_address(&addr));
        assert!(!is_valid_address("0xnotanaddress"));
        // legacy Base64 form must no longer validate
        assert!(!is_valid_address("QApIczvVwnVrqVxYKMyD7hb6vNM="));
    }

    #[test]
    fn node_address_is_hex_body() {
        let pk: Vec<u8> = (0u8..32).collect();
        let addr = address_from_public_key(&pk);
        let node = to_node_address(&addr);
        assert!(node.starts_with("0x40")); // 0x + brand byte
        assert_eq!(node.len(), 42);
    }
}
