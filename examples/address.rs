//! Derive a canonical Quantova address from a post-quantum public key.
//!
//! Run (no node, no `pq` feature needed):
//!     cargo run --example address
//!
//! Expected output:
//!     public key : 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//!     account id : 0x400a48733bd5c2756ba95c5828cc83ee16fabcd3
//!     Q-address  : Q1GQ9YSUEM6HP826AFT3VZ3NYRACT040XNKRUCWF

use qweb3::address::{account_id_from_public_key, address_from_public_key, is_valid_address};

fn main() {
    // a fixed example public key so the output is reproducible
    let pk: Vec<u8> = (0u8..32).collect();

    let account_id = account_id_from_public_key(&pk);
    let address = address_from_public_key(&pk);

    println!("public key : 0x{}", hex::encode(&pk));
    println!("account id : 0x{}", hex::encode(account_id));
    println!("Q-address  : {address}");
    assert!(address.starts_with('Q'));
    assert!(is_valid_address(&address));
}
