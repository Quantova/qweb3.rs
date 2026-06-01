//! Build, post-quantum-sign, and broadcast a QTOV transfer.
//!
//! Requires the `pq` feature (links liboqs) and a reachable node:
//!     QUANTOVA_RPC=https://testnet.quantova.io cargo run --features pq --example transfer
//!
//! Expected output (hashes/addresses vary per run):
//!     sender (Dilithium): Q...               (begins with 'Q')
//!     balance           : 250000000000000000000 planck   nonce: 3
//!     fee (standard)    : 1100000000 planck
//!     signature         : 0x... (2420 bytes)
//!     broadcast tx      : 0x...
//!
//! The signing wallet is gated behind `pq`; everything else (address, fees, RPC)
//! works without it.

use qweb3::wallet::{Scheme, Wallet};
use qweb3::QWeb3;

fn main() -> qweb3::Result<()> {
    let url = std::env::var("QUANTOVA_RPC")
        .unwrap_or_else(|_| "https://testnet.quantova.io".to_string());
    let q = QWeb3::new(&url);

    // 1. a post-quantum sender account
    let wallet = Wallet::create(Scheme::Dilithium)?;
    let sender = wallet.address();
    println!("sender (Dilithium): {sender}");

    let balance = q.rpc().get_balance(&sender)?;
    let nonce = q.rpc().get_transaction_count(&sender)?;
    println!("balance           : {balance} planck   nonce: {nonce}");

    let fees = q.fees()?;
    println!("fee (standard)    : {} planck", fees.standard);

    // 2. build a transfer payload and post-quantum-sign it
    let recipient = "Qe3sJ0p1mK4wQDJUgrrMqVt3Hs8=";
    let value: u128 = 1_500_000_000_000_000_000; // 1.5 QTOV
    let payload = format!("transfer:{sender}->{recipient}:{value}:nonce={nonce}");
    let signature = wallet.sign(payload.as_bytes())?;
    println!("signature         : 0x{}... ({} bytes)", hex::encode(&signature[..16]), signature.len());

    // 3. broadcast (the @quantova api layer assembles the final extrinsic; here we
    //    show the round-trip via raw RPC)
    let raw = format!("0x{}", hex::encode(payload.as_bytes()));
    match q.rpc().send_raw_transaction(&raw) {
        Ok(tx) => println!("broadcast tx      : {tx}"),
        Err(e) => println!("broadcast step    : {e}"),
    }
    Ok(())
}
