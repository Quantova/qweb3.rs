//! Compute QVM Solidity ABI selectors and event topics (keccak-256).
//!
//! Run (no node needed):
//!     cargo run --example abi_selectors
//!
//! Expected output:
//!     transfer(address,uint256)            -> 0xa9059cbb
//!     balanceOf(address)                   -> 0x70a08231
//!     approve(address,uint256)             -> 0x095ea7b3
//!     Transfer(address,address,uint256)    -> 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef

use qweb3::abi::{event_topic_hex, function_selector_hex};

fn main() {
    for sig in [
        "transfer(address,uint256)",
        "balanceOf(address)",
        "approve(address,uint256)",
    ] {
        println!("{sig:36} -> {}", function_selector_hex(sig));
    }
    let ev = "Transfer(address,address,uint256)";
    println!("{ev:36} -> {}", event_topic_hex(ev));
}
