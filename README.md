# qweb3 (Rust)

The official **Rust** client for [Quantova](https://quantova.org), the post-quantum
Layer-1 blockchain — the Rust counterpart of `qweb3.js` and `qweb3.py`.

`qweb3` connects to a Quantova node over JSON-RPC, derives canonical `Q` addresses,
computes the QVM Solidity ABI (keccak-256) and QNS namehash, estimates fees, and —
with the `pq` feature — generates post-quantum keypairs and signs transactions.

Everything is post-quantum by construction: accounts and signatures use the NIST
schemes Quantova supports (CRYSTALS-Dilithium, Falcon, SPHINCS+) and SHA3-256
hashing, with no classical-cryptography fallback.

## Install

Add it to your `Cargo.toml`:

```toml
[dependencies]
qweb3 = "1.0"

# enable post-quantum keygen + signing (links the native liboqs library):
# qweb3 = { version = "1.0", features = ["pq"] }
```

Or from the command line:

```bash
cargo add qweb3                 # client, address, ABI, QNS, fees
cargo add qweb3 --features pq   # also post-quantum keygen + signing
```

The `pq` feature is optional because it links the native Open Quantum Safe
(liboqs) library. Without it, address derivation, ABI, QNS, RPC, and fee estimation
all work; only the signing wallet requires it.

## Endpoints

| Environment | HTTP JSON-RPC |
|---|---|
| Mainnet | `https://mainnet.quantova.io` |
| Testnet | `https://testnet.quantova.io` |
| Local dev | `http://127.0.0.1:9933` |

## Samples

### Derive a canonical Q address (no node, no `pq` needed)

```rust
use qweb3::address::{address_from_public_key, account_id_from_public_key};

fn main() {
    // a post-quantum public key (here a fixed example so output is reproducible)
    let pk: Vec<u8> = (0u8..32).collect();

    let account_id = account_id_from_public_key(&pk); // 20-byte H160, leading 0x40
    let address = address_from_public_key(&pk);        // Bech32m, begins with 'Q1'

    println!("account id : 0x{}", hex::encode(account_id));
    println!("Q-address  : {address}");
}
```

Output:

```
account id : 0x400a48733bd5c2756ba95c5828cc83ee16fabcd3
Q-address  : Q1GQ9YSUEM6HP826AFT3VZ3NYRACT040XNKRUCWF
```

> **Address & key format.** Account/wallet identity is always Q-branded Bech32m:
> `Q1...` addresses and `QPUB1...` public keys — letters and digits only, no
> `+ / _ = -` symbols. The `account id` above is the raw 20-byte body shown in hex
> for reference. The only `0x` hex you'll see is for **Solidity/QVM contract
> addresses**, **transaction signatures**, **calldata**, and **selectors/hashes** —
> none of which are account addresses.

### QVM Solidity ABI selectors and event topics (keccak-256)

```rust
use qweb3::abi::{function_selector_hex, event_topic_hex};

fn main() {
    println!("{}", function_selector_hex("transfer(address,uint256)"));
    println!("{}", function_selector_hex("balanceOf(address)"));
    println!("{}", event_topic_hex("Transfer(address,address,uint256)"));
}
```

Output:

```
0xa9059cbb
0x70a08231
0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
```

### Resolve a `.qtov` namehash (QNS)

```rust
use qweb3::qns::namehash_hex;

fn main() {
    println!("{}", namehash_hex("jason.qtov"));
}
```

Output:

```
0x9e882d38b25139dd882010f6031ad3ecf6672d898d513a3704f7bf59a798a9f6
```

### Connect and read the chain (needs a node)

```rust
use qweb3::QWeb3;

fn main() -> qweb3::Result<()> {
    let q = QWeb3::new("https://testnet.quantova.io");

    let rv = q.rpc().runtime_version()?;
    println!("runtime    : {} v{}", rv.spec_name, rv.spec_version);
    println!("best block : {}", q.rpc().block_number()?);
    println!("balance    : {} planck", q.rpc().get_balance("Qf2t7p9C5Im4waDJUgrrMqVt3Hs8=")?);
    Ok(())
}
```

Output (values depend on the live chain):

```
runtime    : quantova-runtime v1
best block : 1234567
balance    : 250000000000000000000 planck
```

### Create a post-quantum account and sign (requires `pq`)

```rust
use qweb3::wallet::{Wallet, Scheme};

fn main() -> qweb3::Result<()> {
    let wallet = Wallet::create(Scheme::Dilithium)?; // 'falcon' / 'sphincsp' also valid
    println!("address   : {}", wallet.address());     // begins with 'Q'

    let payload = b"transfer:...:nonce=3";
    let signature = wallet.sign(payload)?;            // post-quantum signature
    println!("signature : 0x{}... ({} bytes)", hex::encode(&signature[..16]), signature.len());
    println!("verifies  : {}", wallet.verify(payload, &signature)?);
    Ok(())
}
```

Output (the signature bytes vary per keypair; the length is the scheme's size):

```
address   : Q1G... (Bech32m, begins with Q1; varies per keypair)
signature : 0x60843581143c2cbd... (2420 bytes)
verifies  : true
```

Signature sizes by scheme: Dilithium2 public key 1312 / signature 2420 bytes;
Falcon-512 public key 897 / signature up to 754 bytes; SPHINCS+ (SLH-DSA-SHA2-128s)
public key 32 / signature 7856 bytes.

## Running the examples

The crate ships runnable examples in [`examples/`](examples). Each example's header
comment lists the exact command and the expected output.

```bash
# no node and no pq feature needed:
cargo run --example address
cargo run --example abi_selectors
cargo run --example qns_resolve

# needs a reachable node:
QUANTOVA_RPC=https://testnet.quantova.io cargo run --example connect

# needs the pq feature (links liboqs) and a node:
QUANTOVA_RPC=https://testnet.quantova.io cargo run --features pq --example transfer
```

Expected output of `cargo run --example address`:

```
public key : 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
account id : 0x400a48733bd5c2756ba95c5828cc83ee16fabcd3
Q-address  : Q1GQ9YSUEM6HP826AFT3VZ3NYRACT040XNKRUCWF
```

Expected output of `cargo run --example abi_selectors`:

```
transfer(address,uint256)            -> 0xa9059cbb
balanceOf(address)                   -> 0x70a08231
approve(address,uint256)             -> 0x095ea7b3
Transfer(address,address,uint256)    -> 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
```

## Running the tests

The deterministic logic (address derivation, ABI selectors, namehash) is covered by
unit tests with known-answer values:

```bash
cargo test            # address / ABI / QNS / wallet-scheme tests
cargo test --features pq   # also exercises post-quantum keygen + sign + verify
```

Expected (the exact count may grow over time):

```
running 8 tests
test abi::tests::known_selectors ... ok
test abi::tests::known_event_topic ... ok
test address::tests::derives_known_address ... ok
test address::tests::roundtrips_address ... ok
test qns::tests::empty_is_zero ... ok
test qns::tests::matches_eip137_vector ... ok
test qns::tests::qtov_name ... ok
test wallet::tests::scheme_sizes_and_parse ... ok

test result: ok. 8 passed; 0 failed
```

## API overview

| Module | What it provides |
|---|---|
| `qweb3::QWeb3` | Top-level client: `rpc()`, `fees()`, `resolve_name()` |
| `qweb3::rpc` | JSON-RPC client (`block_number`, `get_balance`, `get_transaction_count`, `gas_price`, `chain_id`, `runtime_version`, `finalized_head`, `eth_call`, `send_raw_transaction`, and raw `call`) |
| `qweb3::address` | Canonical `Q`-address derivation and validation |
| `qweb3::abi` | keccak-256, function selectors, event topics |
| `qweb3::qns` | EIP-137 namehash for `.qtov` names |
| `qweb3::fees` | Fee-tier estimation |
| `qweb3::wallet` | `Scheme`, `Account`, and (with `pq`) `Wallet` keygen / sign / verify |
| `qweb3::error` | `Error` and `Result` |

## How it relates to qweb3.js / qweb3.py

This crate mirrors the same surface as the JavaScript and Python clients — connect,
read, derive addresses, ABI, QNS, fees, and post-quantum signing — so a team can use
Quantova from Rust services with the same model. Verify any implementation against
the protocol with the `pq-test-vectors` tool.

## License

Licensed under the Business Source License 1.1 (BUSL-1.1), © 2026 Quantova Inc.
See [LICENSE](LICENSE) and [LICENSE-OVERVIEW.md](LICENSE-OVERVIEW.md).
