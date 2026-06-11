# qweb3.rs

**Quantova Post-Quantum Web3 Client — Rust SDK.** Connect to a
[Quantova](https://quantova.org) node, manage post-quantum accounts, sign and
broadcast transactions, and interact with QVM smart contracts from Rust. The Rust
counterpart of [qweb3.js](https://github.com/Quantova/Qweb3.js) and
[qweb3.py](https://github.com/Quantova/Qweb3.py).

## Quantum security
Quantova is a post-quantum Layer-1. Accounts use **NIST post-quantum signatures**
(**Falcon-512**, **SPHINCS+ SHAKE-128s**, **CRYSTALS-Dilithium2/ML-DSA-44**) with
**SHA3-256** — no ECDSA/secp256k1 — resistant to quantum attacks. Addresses are
**Bech32m `Q1…`**; the chain speaks **`q_*` JSON-RPC**.

## Cross-SDK compatibility (byte-for-byte)
Keys are derived **deterministically** from the mnemonic using the **exact same cores
as qweb3.js and the Quantova node** — pure Rust, no native `liboqs`:

| Scheme | Crate | Seeding |
|---|---|---|
| Falcon-512 | [`fn-dsa`](https://crates.io/crates/fn-dsa) | `ChaCha20Rng::from_seed(seed)` |
| Dilithium2 | [`fips204`](https://crates.io/crates/fips204) | `ml_dsa_44::keygen_from_seed(seed)` |
| SPHINCS+ | [`fips205`](https://crates.io/crates/fips205) | `blake2_256(SCALE(seed,label))[..16]` components |

The mnemonic → 32-byte seed step is the substrate mini-secret
(`PBKDF2-HMAC-SHA512(BIP-39 entropy, "mnemonic", 2048)[..32]`). The result: **the same
phrase yields the same `Q1…` address and valid signatures in qweb3.js, qweb3.py and
qweb3.rs.** Verified against qweb3.js reference vectors in the test suite, e.g.
`"test test … junk"` → Falcon `Q1GREP2A5A6DX9UFFPWW72PCZ4X429LMQMV6ZW35`.

## Add to your project
```toml
[dependencies]
qweb3 = "1.1"
```

## Quick start
```rust
use qweb3::wallet::{Wallet, Scheme};

// Generate a new account (returns the wallet + its 24-word mnemonic).
let (wallet, mnemonic) = Wallet::create(Scheme::Falcon)?;
println!("address: {}", wallet.address());        // Q1…
println!("mnemonic: {mnemonic}");

// Or restore from a mnemonic — same address as qweb3.js / qweb3.py.
let wallet = Wallet::import_mnemonic(&mnemonic, Scheme::Falcon)?;

// Sign and verify (post-quantum).
let sig = wallet.sign(b"hello quantova")?;
assert!(wallet.verify(b"hello quantova", &sig));
# Ok::<(), qweb3::error::Error>(())
```

Post-quantum keygen and signing are **always available** (pure Rust, no system
libraries). `Wallet`, `Scheme`, address derivation, ABI, QNS, fees and RPC need no
extra features.

## Resources
- 🌐 https://quantova.org · 🔎 https://qvmscan.io · 💻 https://github.com/Quantova/qweb3.rs

## License
Apache-2.0 © Quantova
