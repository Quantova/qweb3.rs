//! Error types for the Quantova client.

use thiserror::Error;

/// The error type returned across the crate.
#[derive(Debug, Error)]
pub enum Error {
    /// A JSON-RPC transport or protocol error.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// The node returned an error object for a request.
    #[error("node returned error {code}: {message}")]
    Node { code: i64, message: String },

    /// A value could not be decoded (hex, Bech32m, or an unexpected shape).
    #[error("decode error: {0}")]
    Decode(String),

    /// An address was not a valid canonical Quantova address.
    #[error("invalid Quantova address: {0}")]
    InvalidAddress(String),

    /// A post-quantum operation failed (only with the `pq` feature).
    #[error("post-quantum signing error: {0}")]
    Signing(String),

    /// JSON (de)serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, Error>;
