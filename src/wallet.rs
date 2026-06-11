//! Post-quantum accounts and signing — **byte-compatible with qweb3.js and qweb3.py**.
//!
//! A Quantova account is a post-quantum keypair (Falcon-512, Dilithium2/ML-DSA-44, or
//! SPHINCS+ SHAKE-128s) whose canonical `Q` address is `SHA3-256(public_key)[..20]`
//! with the leading byte forced to `0x40` (see [`crate::address`]).
//!
//! Keys are derived **deterministically from a 32-byte seed** using the exact same
//! cores as `@quantova/falcon-wasm` (qweb3.js) and the Quantova node (`sp-core`):
//!   * Falcon-512  → `fn-dsa`, seeded with `ChaCha20Rng::from_seed(seed)`
//!   * Dilithium2  → `fips204::ml_dsa_44::keygen_from_seed(seed)`
//!   * SPHINCS+    → `fips205::slh_dsa_shake_128s::keygen_with_seeds(c("sk_seed"), c("sk_prf"), c("pk_seed"))`
//!     where `c(label) = blake2_256(SCALE(seed, label))[..16]`
//!
//! A mnemonic maps to that seed via the substrate mini-secret
//! (`PBKDF2-HMAC-SHA512(entropy, "mnemonic", 2048)[..32]`), identical to qweb3.js. So
//! the **same phrase yields the same address and valid signatures across all SDKs**.

use crate::address::{address_from_public_key, public_key_to_q};
use crate::error::{Error, Result};
use zeroize::Zeroize;

/// A Quantova post-quantum signature scheme. All derive into the same `Q` address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// CRYSTALS-Dilithium2 (ML-DSA-44) — balanced.
    Dilithium,
    /// Falcon-512 (FN-DSA) — compact signatures. The default scheme.
    Falcon,
    /// SPHINCS+ SHAKE-128s (SLH-DSA) — conservative, hash-based.
    SphincsPlus,
}

impl Scheme {
    /// Serialized public-key size in bytes.
    pub fn public_key_bytes(self) -> usize {
        match self {
            Scheme::Dilithium => 1312,
            Scheme::Falcon => 897,
            Scheme::SphincsPlus => 32,
        }
    }

    /// The lowercase scheme name used across the SDKs (`"falcon"`, `"dilithium"`, `"sphincsp"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Dilithium => "dilithium",
            Scheme::Falcon => "falcon",
            Scheme::SphincsPlus => "sphincsp",
        }
    }

    /// Parse a scheme name (`"falcon"`, `"dilithium"`, `"sphincsp"`/`"sphincs+"`).
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
    /// The public key as a Q-branded Bech32m string (`QPUB1…`).
    pub public_key_q: String,
    /// The canonical Quantova account address (`Q1…`).
    pub address: String,
}

impl Account {
    /// Build an account view from a public key (no secret key held).
    pub fn from_public_key(scheme: Scheme, public_key: Vec<u8>) -> Self {
        let address = address_from_public_key(&public_key);
        let public_key_q = public_key_to_q(&public_key);
        Self { scheme, public_key, public_key_q, address }
    }
}

/// Substrate mini-secret: `PBKDF2-HMAC-SHA512(BIP-39 entropy, "mnemonic", 2048)[..32]`.
/// Identical to `mnemonicToMiniSecret` in qweb3.js.
pub fn mnemonic_to_mini_secret(mnemonic: &str) -> Result<[u8; 32]> {
    use hmac::Hmac;
    use sha2::Sha512;
    let mn = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| Error::Signing(format!("invalid mnemonic: {e}")))?;
    let (entropy, len) = mn.to_entropy_array();
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(&entropy[..len], b"mnemonic", 2048, &mut out)
        .map_err(|_| Error::Signing("pbkdf2 failed".into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    out.zeroize();
    Ok(seed)
}

// ── seeded keygen, byte-identical to the node + falcon-wasm ──────────────────

/// SPHINCS+ per-component seed: `blake2_256(SCALE(seed, label))[..16]` (matches sp-core).
fn sphincs_component(seed: &[u8; 32], label: &[u8]) -> [u8; 16] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    // SCALE-encode (seed: [u8;32], label: &[u8]) = seed ++ compact(len) ++ label.
    let mut enc = Vec::with_capacity(32 + 1 + label.len());
    enc.extend_from_slice(seed);
    enc.push((label.len() as u8) << 2); // compact length (labels are < 64 bytes)
    enc.extend_from_slice(label);
    let digest = Blake2b::<U32>::digest(&enc);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn keygen(scheme: Scheme, seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    match scheme {
        Scheme::Falcon => {
            use fn_dsa::{
                sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard,
                FN_DSA_LOGN_512,
            };
            use rand_core::SeedableRng;
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
            let mut kg = KeyPairGeneratorStandard::default();
            let mut public = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
            let mut secret = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
            kg.keygen(FN_DSA_LOGN_512, &mut rng, &mut secret, &mut public);
            (public, secret)
        }
        Scheme::Dilithium => {
            use fips204::ml_dsa_44;
            use fips204::traits::{KeyGen, SerDes};
            let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }
        Scheme::SphincsPlus => {
            use fips205::slh_dsa_shake_128s;
            use fips205::traits::{KeyGen, SerDes};
            let (pk, sk) = slh_dsa_shake_128s::KG::keygen_with_seeds(
                &sphincs_component(seed, b"sk_seed"),
                &sphincs_component(seed, b"sk_prf"),
                &sphincs_component(seed, b"pk_seed"),
            );
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }
    }
}

/// A post-quantum keypair that can sign. Derived deterministically from a seed/mnemonic.
pub struct Wallet {
    scheme: Scheme,
    seed: [u8; 32],
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.secret_key.zeroize();
    }
}

impl Wallet {
    /// Derive a wallet deterministically from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32], scheme: Scheme) -> Result<Self> {
        let (public_key, secret_key) = keygen(scheme, &seed);
        Ok(Self { scheme, seed, public_key, secret_key })
    }

    /// Derive a wallet from a BIP-39 mnemonic (same derivation as qweb3.js/py).
    pub fn import_mnemonic(mnemonic: &str, scheme: Scheme) -> Result<Self> {
        let seed = mnemonic_to_mini_secret(mnemonic)?;
        Self::from_seed(seed, scheme)
    }

    /// Generate a fresh 24-word wallet, returning the wallet and its mnemonic phrase.
    pub fn create(scheme: Scheme) -> Result<(Self, String)> {
        use rand_core::{OsRng, RngCore};
        let mut entropy = [0u8; 32]; // 32 bytes → 24 words
        OsRng.fill_bytes(&mut entropy);
        let mn = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| Error::Signing(format!("mnemonic gen failed: {e}")))?;
        entropy.zeroize();
        let phrase = mn.to_string();
        let wallet = Self::import_mnemonic(&phrase, scheme)?;
        Ok((wallet, phrase))
    }

    /// The scheme this wallet uses.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The serialized public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The account view (scheme, public key, canonical `Q` address).
    pub fn account(&self) -> Account {
        Account::from_public_key(self.scheme, self.public_key.clone())
    }

    /// The canonical `Q` address for this wallet.
    pub fn address(&self) -> String {
        address_from_public_key(&self.public_key)
    }

    /// A deterministic per-signature RNG seed = `blake2_256(seed ++ msg)`. Keeps signing
    /// reproducible and free of any OS RNG dependency, while still producing a valid sig.
    fn sign_rng(&self, message: &[u8]) -> rand_chacha::ChaCha20Rng {
        use blake2::digest::consts::U32;
        use blake2::{Blake2b, Digest};
        use rand_core::SeedableRng;
        let mut h = Blake2b::<U32>::new();
        h.update(self.seed);
        h.update(message);
        let d = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&d[..32]);
        rand_chacha::ChaCha20Rng::from_seed(s)
    }

    /// Post-quantum-sign `message`, returning the raw signature bytes (verifiable on-chain).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rng = self.sign_rng(message);
        match self.scheme {
            Scheme::Falcon => {
                use fn_dsa::{
                    signature_size, SigningKey, SigningKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512,
                    HASH_ID_RAW,
                };
                let mut sk = SigningKeyStandard::decode(&self.secret_key)
                    .ok_or_else(|| Error::Signing("falcon secret key decode failed".into()))?;
                let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
                sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig);
                Ok(sig)
            }
            Scheme::Dilithium => {
                use fips204::ml_dsa_44;
                use fips204::traits::{SerDes, Signer};
                let sk_arr: [u8; ml_dsa_44::SK_LEN] = self
                    .secret_key
                    .clone()
                    .try_into()
                    .map_err(|_| Error::Signing("dilithium secret key size".into()))?;
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_arr)
                    .map_err(|e| Error::Signing(format!("dilithium sk: {e}")))?;
                let sig = sk
                    .try_sign_with_rng(&mut rng, message, &[])
                    .map_err(|e| Error::Signing(format!("dilithium sign: {e}")))?;
                Ok(sig.to_vec())
            }
            Scheme::SphincsPlus => {
                use fips205::slh_dsa_shake_128s;
                use fips205::traits::{SerDes, Signer};
                let sk_arr: [u8; slh_dsa_shake_128s::SK_LEN] = self
                    .secret_key
                    .clone()
                    .try_into()
                    .map_err(|_| Error::Signing("sphincs+ secret key size".into()))?;
                let sk = slh_dsa_shake_128s::PrivateKey::try_from_bytes(&sk_arr)
                    .map_err(|e| Error::Signing(format!("sphincs+ sk: {e}")))?;
                let sig = sk
                    .try_sign_with_rng(&mut rng, message, &[], false)
                    .map_err(|e| Error::Signing(format!("sphincs+ sign: {e}")))?;
                Ok(sig.to_vec())
            }
        }
    }

    /// Verify `signature` over `message` against this wallet's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify(self.scheme, &self.public_key, message, signature)
    }
}

/// Verify a post-quantum signature against a public key (no secret key needed).
pub fn verify(scheme: Scheme, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match scheme {
        Scheme::Falcon => {
            use fn_dsa::{VerifyingKey, VerifyingKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
            match VerifyingKeyStandard::decode(public_key) {
                Some(vk) => vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message),
                None => false,
            }
        }
        Scheme::Dilithium => {
            use fips204::ml_dsa_44;
            use fips204::traits::{SerDes, Verifier};
            let pk_arr: [u8; ml_dsa_44::PK_LEN] = match public_key.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let sig_arr: [u8; ml_dsa_44::SIG_LEN] = match signature.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
                Ok(pk) => pk.verify(message, &sig_arr, &[]),
                Err(_) => false,
            }
        }
        Scheme::SphincsPlus => {
            use fips205::slh_dsa_shake_128s;
            use fips205::traits::{SerDes, Verifier};
            let pk_arr: [u8; slh_dsa_shake_128s::PK_LEN] = match public_key.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let sig_arr: [u8; slh_dsa_shake_128s::SIG_LEN] = match signature.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            match slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_arr) {
                Ok(pk) => pk.verify(message, &sig_arr, &[]),
                Err(_) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors captured from qweb3.js (@quantova/falcon-wasm) for the standard
    // test phrase — proves byte-for-byte cross-SDK address compatibility.
    const PHRASE: &str = "test test test test test test test test test test test junk";

    #[test]
    fn mini_secret_matches_js() {
        let s = mnemonic_to_mini_secret(PHRASE).unwrap();
        assert_eq!(
            hex::encode(s),
            "4ca479f5e0dc0ee04ebcbadb64c220267dad42b8cfa4da1f0874787523b4709c"
        );
    }

    #[test]
    fn addresses_match_js_for_all_schemes() {
        let f = Wallet::import_mnemonic(PHRASE, Scheme::Falcon).unwrap();
        let d = Wallet::import_mnemonic(PHRASE, Scheme::Dilithium).unwrap();
        let s = Wallet::import_mnemonic(PHRASE, Scheme::SphincsPlus).unwrap();
        // Canonical Q1 addresses captured from qweb3.js's deriveAddressFromPublicKey.
        assert_eq!(f.address(), "Q1GREP2A5A6DX9UFFPWW72PCZ4X429LMQMV6ZW35");
        assert_eq!(d.address(), "Q1GPSMQ0QEDGLMACE0FNNY3K4F5V40E6J6MVV45M");
        assert_eq!(s.address(), "Q1GPJWTNCPKQNRTQ2X4CZHSE5298DMVYPQE6X6UY");
        assert_eq!(f.public_key().len(), 897);
        assert_eq!(d.public_key().len(), 1312);
        assert_eq!(s.public_key().len(), 32);
    }

    #[test]
    fn sign_verify_roundtrip_all_schemes() {
        for scheme in [Scheme::Falcon, Scheme::Dilithium, Scheme::SphincsPlus] {
            let w = Wallet::import_mnemonic(PHRASE, scheme).unwrap();
            let sig = w.sign(b"qweb3").unwrap();
            assert!(w.verify(b"qweb3", &sig), "{} sign/verify failed", scheme.as_str());
            assert!(!w.verify(b"tampered", &sig));
        }
    }

    #[test]
    fn scheme_parse() {
        assert_eq!(Scheme::parse("FALCON"), Some(Scheme::Falcon));
        assert_eq!(Scheme::parse("sphincs+"), Some(Scheme::SphincsPlus));
        assert_eq!(Scheme::parse("nope"), None);
    }
}
