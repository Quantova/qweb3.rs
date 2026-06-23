//! Error types for the Quantova client.

use thiserror::Error;

/// The error type returned across the crate.
#[derive(Debug, Error)]
pub enum Error {
    /// A JSON-RPC transport or protocol error.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// The node returned an error object for a request.
    ///
    /// **Security note (QWEB3RS-RPC-007):** `message` is supplied by the remote
    /// node and is therefore untrusted. The client sanitizes it (strips ASCII
    /// control characters and ANSI escape sequences, caps the length) before
    /// constructing this variant, but callers should still treat it as
    /// adversarial data and avoid interpreting it as anything but display text.
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
