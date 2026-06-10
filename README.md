# qweb3.rs

**Quantova Post-Quantum Web3 Client — Rust SDK.** Connect to a
[Quantova](https://quantova.org) node, manage post-quantum accounts, sign and
broadcast transactions, and interact with QVM smart contracts from Rust.

## Quantum security
Quantova is a post-quantum Layer-1. Accounts use **NIST post-quantum signatures**
(**Falcon**, **SPHINCS+**, **CRYSTALS-Dilithium**) with **SHA3-256** — no ECDSA —
resistant to quantum attacks. Addresses are **Bech32m `Q1…`**; the chain speaks
**`q_*` JSON-RPC**.

## Add to your project
```toml
[dependencies]
qweb3 = "1.0"
```

## Resources
- 🌐 https://quantova.org · 🔎 https://qvmscan.io · 💻 https://github.com/Quantova/qweb3.rs

## License
Apache-2.0 © Quantova
