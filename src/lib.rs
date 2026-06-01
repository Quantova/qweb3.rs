//! # qweb3 — the Rust client for Quantova
//!
//! `qweb3` is the official Rust client for **Quantova**, the post-quantum Layer-1
//! blockchain — the Rust counterpart of `qweb3.js` and `qweb3.py`. It connects to a
//! Quantova node over JSON-RPC, derives canonical `Q` addresses, computes the QVM
//! Solidity ABI (keccak-256) and QNS namehash, estimates fees, and — with the `pq`
//! feature — generates post-quantum keypairs and signs transactions.
//!
//! Everything is post-quantum by construction: accounts and signatures use the NIST
//! schemes Quantova supports (CRYSTALS-Dilithium, Falcon, SPHINCS+) and SHA3-256
//! hashing, with no classical-cryptography fallback.
//!
//! ## Quick start
//!
//! Connect and read the chain (no keys, no `pq` feature needed):
//!
//! ```no_run
//! use qweb3::QWeb3;
//!
//! # fn main() -> qweb3::Result<()> {
//! let q = QWeb3::new("https://testnet.quantova.io");
//! let block = q.rpc().block_number()?;
//! let rv = q.rpc().runtime_version()?;
//! println!("block {block} on {} v{}", rv.spec_name, rv.spec_version);
//! # Ok(())
//! # }
//! ```
//!
//! Derive a canonical `Q` address from a public key (always available):
//!
//! ```
//! let pk: Vec<u8> = (0u8..32).collect();
//! let address = qweb3::address::address_from_public_key(&pk);
//! assert!(address.starts_with('Q'));
//! ```
//!
//! Compute a QVM Solidity selector and a QNS namehash:
//!
//! ```
//! assert_eq!(qweb3::abi::function_selector_hex("transfer(address,uint256)"), "0xa9059cbb");
//! assert_eq!(
//!     qweb3::qns::namehash_hex("eth"),
//!     "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
//! );
//! ```
//!
//! Create a post-quantum account and sign (requires the `pq` feature):
//!
//! ```ignore
//! use qweb3::wallet::{Wallet, Scheme};
//!
//! let wallet = Wallet::create(Scheme::Dilithium)?;   // address begins with 'Q'
//! let signature = wallet.sign(b"...payload...")?;     // post-quantum signature
//! assert!(wallet.verify(b"...payload...", &signature)?);
//! ```
//!
//! ## Feature flags
//!
//! - **`pq`** — enables real post-quantum key generation and signing via Open
//!   Quantum Safe (liboqs). Without it, address derivation, ABI, QNS, RPC, and fees
//!   all work; only the signing wallet requires it.

pub mod abi;
pub mod address;
pub mod error;
pub mod fees;
pub mod qns;
pub mod rpc;
pub mod wallet;

pub use error::{Error, Result};
pub use rpc::RpcClient;

/// The top-level Quantova client.
///
/// Holds an [`RpcClient`] and exposes the SDK surfaces. Construct it with an
/// endpoint URL.
#[derive(Clone, Debug)]
pub struct QWeb3 {
    rpc: RpcClient,
}

impl QWeb3 {
    /// Create a client for an endpoint, e.g. `https://testnet.quantova.io`,
    /// `https://mainnet.quantova.io`, or `http://127.0.0.1:9933`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            rpc: RpcClient::new(url),
        }
    }

    /// Access the JSON-RPC client (`q_*`, `state_*`, `chain_*`, `system_*`).
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Estimate fee tiers from the node's current gas price.
    pub fn fees(&self) -> Result<fees::FeeTiers> {
        fees::estimate(&self.rpc)
    }

    /// Resolve a `.qtov` name to a canonical `Q` address via the QVM registry.
    ///
    /// `registry` is the QNS registry contract address (H160 hex). Returns the
    /// resolved address, or `None` if the name does not resolve.
    pub fn resolve_name(&self, registry: &str, name: &str) -> Result<Option<String>> {
        // resolver(bytes32) selector + the namehash as the argument
        let selector = abi::function_selector_hex("resolver(bytes32)");
        let node = hex::encode(qns::namehash(name));
        let data = format!("{selector}{node}");
        let ret = self.rpc.eth_call(registry, &data)?;
        let raw = ret.strip_prefix("0x").unwrap_or(&ret);
        if raw.len() < 40 || raw.chars().all(|c| c == '0') {
            return Ok(None);
        }
        // last 20 bytes are the address body
        let body = &raw[raw.len() - 40..];
        let bytes = hex::decode(body).map_err(|e| Error::Decode(e.to_string()))?;
        Ok(Some(
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
        ))
    }
}
