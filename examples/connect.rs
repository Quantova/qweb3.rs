//! Connect to a Quantova node and read chain state.
//!
//! Run (needs a reachable node):
//!     QUANTOVA_RPC=https://testnet.quantova.io cargo run --example connect
//!     # or a local node: QUANTOVA_RPC=http://127.0.0.1:9933 cargo run --example connect
//!
//! Expected output (values depend on the live chain):
//!     connected to https://testnet.quantova.io
//!     runtime    : quantova-runtime v1 (tx v1)
//!     best block : 1234567
//!     balance    : 250000000000000000000 planck

use qweb3::QWeb3;

fn main() -> qweb3::Result<()> {
    let url = std::env::var("QUANTOVA_RPC")
        .unwrap_or_else(|_| "https://testnet.quantova.io".to_string());
    let q = QWeb3::new(&url);
    println!("connected to {url}");

    let rv = q.rpc().runtime_version()?;
    println!(
        "runtime    : {} v{} (tx v{})",
        rv.spec_name, rv.spec_version, rv.transaction_version
    );
    println!("best block : {}", q.rpc().block_number()?);

    let address = "Qf2t7p9C5Im4waDJUgrrMqVt3Hs8=";
    println!("balance    : {} planck", q.rpc().get_balance(address)?);
    Ok(())
}
