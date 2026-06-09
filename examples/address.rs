//! Derive a canonical Quantova address (and Q-branded public key) from a post-quantum public key.
//!
//! Run (no node, no `pq` feature needed):
//!     cargo run --example address
//!
//! Expected output:
//!     public key : QPUB1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0S6JR5LF
//!     Q-address  : Q1GQ9YSUEM6HP826AFT3VZ3NYRACT040XNKRUCWF

use qweb3::address::{address_from_public_key, is_valid_address, public_key_to_q};

fn main() {
    // a fixed example public key so the output is reproducible
    let pk: Vec<u8> = (0u8..32).collect();

    let address = address_from_public_key(&pk);

    println!("public key : {}", public_key_to_q(&pk)); // QPUB1...
    println!("Q-address  : {address}"); // Q1...
    assert!(address.starts_with("Q1"));
    assert!(is_valid_address(&address));
}
