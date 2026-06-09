//! Post-quantum accounts and signing.
//!
//! Quantova accounts are post-quantum. A keypair is generated for one of the three
//! NIST schemes, and its canonical `Q` address is derived from the public key (see
//! [`crate::address`]). Signing produces a `QSignature` the runtime verifies.
//!
//! Real key generation and signing link the native Open Quantum Safe (liboqs)
//! library and are therefore gated behind the **`pq`** feature. The [`Scheme`] enum
//! and address derivation are always available.

use crate::address::address_from_public_key;

/// A Quantova post-quantum signature scheme.
///
/// All three derive into the same `Q` address space; choose per account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// CRYSTALS-Dilithium (Dilithium2 / ML-DSA-44) — balanced default.
    Dilithium,
    /// Falcon-512 (FN-DSA) — compact signatures.
    Falcon,
    /// SPHINCS+ (SLH-DSA-SHA2-128s) — conservative, hash-based.
    SphincsPlus,
}

impl Scheme {
    /// Public-key size in bytes for this scheme's parameter set.
    pub fn public_key_bytes(self) -> usize {
        match self {
            Scheme::Dilithium => 1312,
            Scheme::Falcon => 897,
            Scheme::SphincsPlus => 32,
        }
    }

    /// Maximum signature size in bytes for this scheme's parameter set.
    pub fn max_signature_bytes(self) -> usize {
        match self {
            Scheme::Dilithium => 2420,
            Scheme::Falcon => 754,
            Scheme::SphincsPlus => 7856,
        }
    }

    /// Parse a scheme from a string: `"dilithium"`, `"falcon"`, or `"sphincsp"`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "dilithium" => Some(Scheme::Dilithium),
            "falcon" => Some(Scheme::Falcon),
            "sphincsp" | "sphincs+" | "sphincs" => Some(Scheme::SphincsPlus),
            _ => None,
        }
    }
}

/// A post-quantum account: a scheme, a public key, and the canonical `Q` address.
#[derive(Debug, Clone)]
pub struct Account {
    pub scheme: Scheme,
    pub public_key: Vec<u8>,
    /// The public key as a Q-branded Bech32m string ("QPUB1...").
    pub public_key_q: String,
    /// The canonical Quantova account address ("Q1...").
    pub address: String,
}

impl Account {
    /// Build an account from an existing public key (no secret key held).
    pub fn from_public_key(scheme: Scheme, public_key: Vec<u8>) -> Self {
        let address = address_from_public_key(&public_key);
        let public_key_q = crate::address::public_key_to_q(&public_key);
        Self {
            scheme,
            public_key,
            public_key_q,
            address,
        }
    }
}

#[cfg(feature = "pq")]
mod pq {
    use super::*;
    use crate::error::{Error, Result};
    use oqs::sig::{Algorithm, Sig};

    fn algorithm(scheme: Scheme) -> Algorithm {
        match scheme {
            Scheme::Dilithium => Algorithm::Dilithium2,
            Scheme::Falcon => Algorithm::Falcon512,
            Scheme::SphincsPlus => Algorithm::SphincsSha2128sSimple,
        }
    }

    /// A post-quantum keypair that can sign. Available with the `pq` feature.
    pub struct Wallet {
        scheme: Scheme,
        sig: Sig,
        public_key: oqs::sig::PublicKey,
        secret_key: oqs::sig::SecretKey,
    }

    impl Wallet {
        /// Generate a fresh post-quantum keypair for `scheme`.
        pub fn create(scheme: Scheme) -> Result<Self> {
            let sig = Sig::new(algorithm(scheme)).map_err(|e| Error::Signing(e.to_string()))?;
            let (public_key, secret_key) =
                sig.keypair().map_err(|e| Error::Signing(e.to_string()))?;
            Ok(Self {
                scheme,
                sig,
                public_key,
                secret_key,
            })
        }

        /// The account view (scheme, public key, canonical `Q` address).
        pub fn account(&self) -> Account {
            Account::from_public_key(self.scheme, self.public_key.as_ref().to_vec())
        }

        /// The canonical `Q` address for this wallet.
        pub fn address(&self) -> String {
            address_from_public_key(self.public_key.as_ref())
        }

        /// Post-quantum-sign `message`, returning the raw signature bytes.
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let signed = self
                .sig
                .sign(message, &self.secret_key)
                .map_err(|e| Error::Signing(e.to_string()))?;
            Ok(signed.into_vec())
        }

        /// Verify a signature against this wallet's public key.
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
            let sig_ref = self
                .sig
                .signature_from_bytes(signature)
                .ok_or_else(|| Error::Signing("malformed signature".into()))?;
            Ok(self
                .sig
                .verify(message, sig_ref, &self.public_key)
                .is_ok())
        }
    }
}

#[cfg(feature = "pq")]
pub use pq::Wallet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_sizes_and_parse() {
        assert_eq!(Scheme::Dilithium.max_signature_bytes(), 2420);
        assert_eq!(Scheme::Falcon.public_key_bytes(), 897);
        assert_eq!(Scheme::parse("sphincs+"), Some(Scheme::SphincsPlus));
        assert_eq!(Scheme::parse("nope"), None);
    }

    #[test]
    fn account_from_public_key_derives_q_address() {
        let pk: Vec<u8> = (0u8..32).collect();
        let acct = Account::from_public_key(Scheme::Dilithium, pk);
        assert!(acct.address.starts_with('Q'));
    }
}
