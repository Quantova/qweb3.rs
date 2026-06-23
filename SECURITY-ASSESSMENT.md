# Security Assessment - qweb3 (Rust)

- **Crate:** `qweb3`
- **Assessment date:** 2026-06-23
- **Scope:** the client crate (`src/`)
- **Release status:** not yet published to crates.io; the assessment below is performed against
  the source on the default branch.

## Summary

An adversarial security review of the qweb3 Rust SDK found **no cryptographic break and no
remote path to recover a private key or forge a signature** from public data. Key generation,
the sign/verify binding, and address derivation are sound and consistent with the JavaScript and
Python SDKs.

The two defect classes that affected the JavaScript and Python SDKs largely **do not apply** to
the Rust crate by design, as detailed below.

qweb3 (Rust) is a thin client over the `q_*` JSON-RPC. Post-quantum signing is delegated to the
external crates listed under *Trust boundary*, which require their own review.

## Cross-SDK findings: applicability to Rust

| ID | JS/Py issue | Status in the Rust crate |
| --- | --- | --- |
| KEY-001 | Secret material reachable through default serialization/printing | **Not applicable.** The secret-holding `Wallet` type derives no `Debug`, `Display`, or `Serialize`; only the public `Account` type derives `Debug`, and it carries no secret fields. The seed and secret key are zeroized on `Drop`. |
| KEY-003 | CLI printed secrets / accepted the seed as argv | **Not applicable.** The crate is a library; it ships no secret-printing CLI. |
| VAL-001 | REST path-segment injection from unvalidated input | **Not applicable.** Requests use JSON-RPC with parameters in the request body, not interpolated into URL paths. |
| VAL-002 | Non-total `verify()` / scheme fall-through | **Low residual.** The signature scheme is a typed `enum` (no string fall-through to a default algorithm). Confirmation that `verify` returns `false` on every malformed input - rather than returning an error to the caller - will be re-checked at the point of the crates.io release. |

## Verified sound

- **Cryptography.** Accounts originate from a 24-word BIP-39 mnemonic (256-bit entropy). Seeds
  are derived by PBKDF2-HMAC-SHA512. Per-message signing randomness is derived deterministically
  from the seed and message (`ChaCha20Rng` seeded with `blake2_256(seed || message)`), which
  avoids any nonce-reuse failure mode and removes the dependency on an OS RNG at signing time.
  The sign/verify round-trip passes for all schemes.
- **Address derivation.** `Q1...` = Bech32m of `SHA3-256(public_key)[0:20]` with the leading
  `0x40` brand byte; consistent across all three SDKs.
- **Memory safety of key material.** `Wallet` holds the seed and secret key in fixed buffers
  that are zeroized on `Drop`, and the type is not printable or serializable.
- **Dependencies.** `cargo audit` reports no actionable vulnerabilities.

## Trust boundary

The crate delegates all signing, per-signature randomness, and verification math to external
crates that are outside the scope of this assessment and require their own cryptographic review:

- Falcon-512 - `fn-dsa`
- ML-DSA / Dilithium - FIPS-204 (`fips204`)
- SLH-DSA / SPHINCS+ - FIPS-205 (`fips205`)

## Recommendations for integrators

1. Track the crates.io release; until then, pin to a specific commit.
2. For high-value keys, hold key material in an HSM or OS keystore. The `Drop`-time zeroization
   reduces the window in which a secret sits in process memory, but no software library can
   prevent code running in the same process from reading a live key.
