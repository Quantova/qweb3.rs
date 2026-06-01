//! Fee estimation.
//!
//! A small helper over the node's gas price that returns slow / standard / fast
//! tiers, mirroring `q.fees.estimate()` in qweb3.js and qweb3.py.

use crate::error::Result;
use crate::rpc::RpcClient;

/// Suggested fee tiers (in planck) derived from the current gas price.
#[derive(Debug, Clone)]
pub struct FeeTiers {
    pub slow: u128,
    pub standard: u128,
    pub fast: u128,
    /// The fee model in effect on Quantova.
    pub model: &'static str,
}

/// Estimate fee tiers from the node's current gas price.
pub fn estimate(rpc: &RpcClient) -> Result<FeeTiers> {
    let base = rpc.gas_price()?;
    Ok(FeeTiers {
        slow: base,
        standard: base + base / 10,       // +10%
        fast: base + base / 2,            // +50%
        model: "quantova-dynamic-no-burn",
    })
}
