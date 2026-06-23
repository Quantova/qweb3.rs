//! Read-and-write JSON-RPC client for a Quantova node.
//!
//! Exposes the Quantova `q_*` namespace plus the standard `state_*`, `chain_*`, and
//! `system_*` methods. All calls are synchronous (powered by `ureq`).

use std::io::Read;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::error::{Error, Result};

/// Maximum number of bytes read from a node response body before bailing out.
/// Bounds memory consumption when talking to a hostile or buggy node (QW3RS-001).
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

/// Maximum length (in chars) of a node-supplied error message we will surface,
/// after which it is truncated. Bounds log/UI abuse from a hostile node (QWEB3RS-RPC-007).
const MAX_NODE_MESSAGE_CHARS: usize = 512;

/// A thin JSON-RPC client bound to a single endpoint.
#[derive(Clone, Debug)]
pub struct RpcClient {
    url: String,
    id: std::cell::Cell<u64>,
    // QW3RS-001: a single shared agent with connect/read/write timeouts, reused
    // across calls so a slow or hostile node cannot hang a request forever and we
    // do not leak connections by building a fresh agent per call.
    agent: ureq::Agent,
}

impl RpcClient {
    /// Create a client for an endpoint such as `https://testnet.quantova.io` or
    /// `http://127.0.0.1:9933`.
    pub fn new(url: impl Into<String>) -> Self {
        // QW3RS-001: bounded connect/read/write timeouts on a shared agent.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self {
            url: url.into(),
            id: std::cell::Cell::new(1),
            agent,
        }
    }

    fn next_id(&self) -> u64 {
        let n = self.id.get();
        self.id.set(n + 1);
        n
    }

    /// Make a raw JSON-RPC call and deserialize the `result` field.
    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
            "params": params,
        });
        // QW3RS-001: use the shared, timeout-bounded agent, and cap the response
        // body size before parsing so a hostile node cannot exhaust memory by
        // streaming an unbounded body. `take(MAX_RESPONSE_BYTES)` truncates the
        // read; a body at the limit will fail to parse as JSON and surface as an
        // RPC error rather than an OOM.
        let response = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let mut buf = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let resp: Value = serde_json::from_slice(&buf).map_err(|e| Error::Rpc(e.to_string()))?;

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let raw = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            // QWEB3RS-RPC-007: the message is attacker-controlled. Strip ASCII
            // control chars and ANSI escape sequences, then cap the length, so it
            // is safe to log or render in a terminal/UI.
            let message = sanitize_node_message(raw);
            return Err(Error::Node { code, message });
        }
        let result = resp
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Rpc("response missing `result`".into()))?;
        Ok(serde_json::from_value(result)?)
    }

    // --- convenience wrappers over common methods --------------------------

    /// `q_blockNumber` -> current best block number.
    pub fn block_number(&self) -> Result<u64> {
        let hex: String = self.call("q_blockNumber", json!([]))?;
        parse_u64_hex(&hex)
    }

    /// `q_getBalance` -> free balance in planck (1 QTOV = 10^18 planck).
    pub fn get_balance(&self, address: &str) -> Result<u128> {
        let hex: String = self.call("q_getBalance", json!([address]))?;
        parse_u128_hex(&hex)
    }

    /// `q_getTransactionCount` -> account nonce.
    pub fn get_transaction_count(&self, address: &str) -> Result<u64> {
        let hex: String = self.call("q_getTransactionCount", json!([address]))?;
        parse_u64_hex(&hex)
    }

    /// `q_gasPrice` -> current gas price in planck.
    pub fn gas_price(&self) -> Result<u128> {
        let hex: String = self.call("q_gasPrice", json!([]))?;
        parse_u128_hex(&hex)
    }

    /// `q_chainId` -> chain id.
    pub fn chain_id(&self) -> Result<u64> {
        let hex: String = self.call("q_chainId", json!([]))?;
        parse_u64_hex(&hex)
    }

    /// `state_getRuntimeVersion` -> runtime identity (spec name, versions).
    pub fn runtime_version(&self) -> Result<RuntimeVersion> {
        self.call("state_getRuntimeVersion", json!([]))
    }

    /// `chain_getFinalizedHead` -> hash of the finalized head.
    pub fn finalized_head(&self) -> Result<String> {
        self.call("chain_getFinalizedHead", json!([]))
    }

    /// `q_call` -> read-only QVM contract call, returning the raw `0x` return data.
    pub fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        self.call("q_call", json!([{ "to": to, "data": data }]))
    }

    /// `q_sendRawTransaction` -> submit a signed transaction, returning its hash.
    pub fn send_raw_transaction(&self, raw: &str) -> Result<String> {
        self.call("q_sendRawTransaction", json!([raw]))
    }
}

/// Subset of the runtime version returned by `state_getRuntimeVersion`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RuntimeVersion {
    #[serde(rename = "specName")]
    pub spec_name: String,
    #[serde(rename = "specVersion")]
    pub spec_version: u32,
    #[serde(rename = "transactionVersion")]
    pub transaction_version: u32,
}

/// QWEB3RS-RPC-007: sanitize an untrusted node-supplied error message.
///
/// Removes ASCII control characters (including the `ESC` used to start ANSI/VT
/// escape sequences, which neutralizes those sequences) and caps the result at
/// [`MAX_NODE_MESSAGE_CHARS`] characters, appending an ellipsis when truncated.
fn sanitize_node_message(raw: &str) -> String {
    let mut out = String::new();
    let mut kept = 0usize;
    for ch in raw.chars() {
        // Drop C0/C1 control chars (incl. 0x1b ESC) and DEL; keep ordinary text.
        if ch.is_control() {
            continue;
        }
        if kept >= MAX_NODE_MESSAGE_CHARS {
            out.push('…');
            break;
        }
        out.push(ch);
        kept += 1;
    }
    out
}

fn parse_u64_hex(s: &str) -> Result<u64> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(t, 16).map_err(|e| Error::Decode(e.to_string()))
}

fn parse_u128_hex(s: &str) -> Result<u128> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(t, 16).map_err(|e| Error::Decode(e.to_string()))
}
