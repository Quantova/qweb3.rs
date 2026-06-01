//! Quantova Virtual Machine (QVM) Solidity ABI helpers.
//!
//! The QVM speaks the standard Solidity ABI, so function selectors and event topics
//! are computed with **keccak-256** exactly as on any EVM-compatible chain. Only the
//! transaction that carries a contract call is post-quantum signed; the ABI itself
//! is unchanged, so existing Solidity tooling applies.

use tiny_keccak::{Hasher, Keccak};

/// keccak-256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// The 4-byte function selector for a Solidity signature, e.g.
/// `function_selector("transfer(address,uint256)") == [0xa9, 0x05, 0x9c, 0xbb]`.
pub fn function_selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// The function selector as a `0x`-prefixed hex string, e.g. `"0xa9059cbb"`.
pub fn function_selector_hex(signature: &str) -> String {
    format!("0x{}", hex::encode(function_selector(signature)))
}

/// The 32-byte event topic for a Solidity event signature, e.g.
/// `event_topic("Transfer(address,address,uint256)")`.
pub fn event_topic(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes())
}

/// The event topic as a `0x`-prefixed hex string.
pub fn event_topic_hex(signature: &str) -> String {
    format!("0x{}", hex::encode(event_topic(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors() {
        assert_eq!(function_selector_hex("transfer(address,uint256)"), "0xa9059cbb");
        assert_eq!(function_selector_hex("balanceOf(address)"), "0x70a08231");
        assert_eq!(function_selector_hex("approve(address,uint256)"), "0x095ea7b3");
    }

    #[test]
    fn known_event_topic() {
        assert_eq!(
            event_topic_hex("Transfer(address,address,uint256)"),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }
}
