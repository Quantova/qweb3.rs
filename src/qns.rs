//! Quantova Name Service (QNS) helpers.
//!
//! Names under the branded `qtov` root (for example `jason.qtov`) are reduced to a
//! 32-byte node with the **EIP-137 namehash over keccak-256** — the same algorithm
//! the QNS pallet uses. Resolution reads the on-chain QVM registry.

use crate::abi::keccak256;

/// EIP-137 namehash of `name`.
///
/// `namehash("")` is 32 zero bytes; otherwise, for each label right-to-left:
/// `node = keccak256(node || keccak256(label))`.
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    for label in name.split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&node);
        combined[32..].copy_from_slice(&label_hash);
        node = keccak256(&combined);
    }
    node
}

/// The namehash as a `0x`-prefixed hex string.
pub fn namehash_hex(name: &str) -> String {
    format!("0x{}", hex::encode(namehash(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(namehash(""), [0u8; 32]);
    }

    // Cross-checked against the published EIP-137 / ENS vector for "eth".
    #[test]
    fn matches_eip137_vector() {
        assert_eq!(
            namehash_hex("eth"),
            "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
    }

    #[test]
    fn qtov_name() {
        assert_eq!(
            namehash_hex("jason.qtov"),
            "0x9e882d38b25139dd882010f6031ad3ecf6672d898d513a3704f7bf59a798a9f6"
        );
    }
}
