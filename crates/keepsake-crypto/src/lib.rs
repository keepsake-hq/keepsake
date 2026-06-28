//! `keepsake-crypto` — the trust root for the Keepsake vault.
//!
//! BIP-39 seed -> domain-separated HKDF roots -> random-DEK envelope encryption
//! with cryptographic erasure. See §4 / §4a of the design dossier:
//! Cell DEKs are **random** (never seed-derived) and wrapped under a KEK, so
//! destroying the wrapping makes a cell undecryptable even with the seed.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod quickunlock;

/// Errors surfaced by the crypto core.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The BIP-39 mnemonic was invalid (bad word or checksum).
    Mnemonic,
    /// AEAD decryption / authentication failed (wrong key, tampered ciphertext,
    /// or — by design — a DEK that has been erased).
    Aead,
}

/// Domain-separated key roots derived from the wallet seed.
///
/// Each root is an independent 32-byte key; knowledge of one reveals nothing
/// about the others (HKDF domain separation via distinct `info` strings).
///
/// Wiped from memory on drop (`ZeroizeOnDrop`), so a long-lived unlocked session does not leave
/// raw root key material lingering in freed pages / swap / a core dump.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKeys {
    /// Root for ML-DSA identity / operation signing keys.
    pub signing_root: [u8; 32],
    /// Root for the KEK that wraps per-cell DEKs.
    pub encryption_root: [u8; 32],
    /// Root for per-device wrapping / pairing keys.
    pub device_root: [u8; 32],
    /// Root for the local Memory-Receipt signing chain.
    pub receipt_root: [u8; 32],
}

/// Generate a fresh 24-word BIP-39 seed phrase (256-bit entropy from the OS CSPRNG).
/// This is the user's sole key to the vault — losing it loses the data.
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let phrase = bip39::Mnemonic::from_entropy(&entropy)
        .expect("32 bytes is valid 24-word BIP-39 entropy")
        .to_string();
    entropy.zeroize();
    phrase
}

/// Constant-time byte-slice equality: compares every byte with no early-out, so a mismatch can't be
/// located by timing. Use for verifying secrets / codes (e.g. the pairing SAS) instead of `==`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

impl RootKeys {
    /// Derive the four domain-separated roots from a BIP-39 mnemonic and an
    /// optional passphrase (the "25th word").
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<RootKeys, CryptoError> {
        let mnemonic = bip39::Mnemonic::parse(phrase).map_err(|_| CryptoError::Mnemonic)?;
        let seed = mnemonic.to_seed(passphrase);
        let hk = Hkdf::<Sha256>::new(None, &seed);
        let derive = |info: &[u8]| {
            let mut out = [0u8; 32];
            hk.expand(info, &mut out)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            out
        };
        Ok(RootKeys {
            signing_root: derive(b"keepsake/v1/root/signing"),
            encryption_root: derive(b"keepsake/v1/root/encryption"),
            device_root: derive(b"keepsake/v1/root/device"),
            receipt_root: derive(b"keepsake/v1/root/receipt"),
        })
    }

    /// A dedicated 256-bit key for full-database (SQLCipher) encryption at rest,
    /// domain-separated from the cell-encryption KEK.
    pub fn db_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.encryption_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/db-key", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        k
    }

    /// The root key for minting/verifying capability tokens, from `signing_root`.
    pub fn capability_root(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.signing_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/capability-root", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        k
    }

    /// The shared key that authenticates sync snapshots between a user's own devices.
    /// Derived from `device_root`, so every device holding the seed computes the same key —
    /// while a relay (which never sees the seed) cannot forge a snapshot's MAC.
    pub fn sync_mac_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.device_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/sync-mac", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        k
    }

    /// A public, unguessable per-vault **sync slot** id — where this vault's encrypted snapshots
    /// live on a relay. Derived from `device_root`, so every device with the seed computes the same
    /// slot while two different seeds never collide (a 256-bit secret address). Hex-encode for use.
    pub fn sync_slot(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.device_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/sync-slot", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        k
    }

    /// A secret **write token** authorizing writes to this vault's sync slot — so a relay (or
    /// anyone who learns the slot) cannot overwrite it without the seed. Derived from `device_root`.
    pub fn sync_write_token(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.device_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/sync-write-token", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        k
    }
}

/// Key-encryption-key (KEK): wraps per-cell DEKs. Derived from `encryption_root`.
///
/// Wiped from memory on drop (`ZeroizeOnDrop`): the KEK is the master that unwraps every cell, so it
/// must not survive in freed memory after a vault is locked.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kek([u8; 32]);

/// An encrypted cell payload. Inert without the matching [`WrappedDek`].
#[derive(Clone, Debug)]
pub struct SealedCell {
    /// AES-256-GCM nonce for the content encryption.
    pub nonce: [u8; 12],
    /// Ciphertext (AEAD output, includes the auth tag).
    pub ciphertext: Vec<u8>,
}

/// A per-cell DEK encrypted ("wrapped") under a [`Kek`].
///
/// This is the *only* recoverable copy of the random key that decrypts the cell.
/// Destroying every `WrappedDek` for a cell makes the cell permanently
/// undecryptable — even by someone who still holds the seed (§4a erasure).
#[derive(Clone, Debug)]
pub struct WrappedDek {
    /// AES-256-GCM nonce for the key wrapping.
    pub nonce: [u8; 12],
    /// The wrapped (encrypted) 32-byte DEK plus auth tag.
    pub bytes: Vec<u8>,
}

impl Kek {
    /// Derive the KEK from the `encryption_root`.
    pub fn from_root(encryption_root: &[u8; 32]) -> Kek {
        let hk = Hkdf::<Sha256>::new(None, encryption_root);
        let mut k = [0u8; 32];
        hk.expand(b"keepsake/v1/kek", &mut k)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Kek(k)
    }

    /// Encrypt `plaintext` under a fresh **random** DEK and return the sealed
    /// cell together with that DEK wrapped under this KEK.
    pub fn seal(&self, plaintext: &[u8]) -> (SealedCell, WrappedDek) {
        // Fresh random DEK — NEVER derived from the seed. This is what makes
        // erasure real: destroy the wrapping and the DEK is unrecoverable.
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);

        let mut cell_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut cell_nonce);
        let content = Aes256Gcm::new_from_slice(&dek).expect("DEK is 32 bytes");
        let ciphertext = content
            .encrypt(Nonce::from_slice(&cell_nonce), plaintext)
            .expect("AES-256-GCM encryption does not fail for valid inputs");

        let mut wrap_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut wrap_nonce);
        let kek = Aes256Gcm::new_from_slice(&self.0).expect("KEK is 32 bytes");
        let bytes = kek
            .encrypt(Nonce::from_slice(&wrap_nonce), dek.as_ref())
            .expect("AES-256-GCM encryption does not fail for valid inputs");

        dek.zeroize();

        (
            SealedCell {
                nonce: cell_nonce,
                ciphertext,
            },
            WrappedDek {
                nonce: wrap_nonce,
                bytes,
            },
        )
    }

    /// Recover the plaintext of a sealed cell, given its wrapped DEK.
    pub fn open(&self, cell: &SealedCell, wrapped: &WrappedDek) -> Result<Vec<u8>, CryptoError> {
        let kek = Aes256Gcm::new_from_slice(&self.0).expect("KEK is 32 bytes");
        let mut dek = kek
            .decrypt(Nonce::from_slice(&wrapped.nonce), wrapped.bytes.as_ref())
            .map_err(|_| CryptoError::Aead)?;
        let content = Aes256Gcm::new_from_slice(&dek).map_err(|_| CryptoError::Aead)?;
        let plaintext = content
            .decrypt(Nonce::from_slice(&cell.nonce), cell.ciphertext.as_ref())
            .map_err(|_| CryptoError::Aead)?;
        dek.zeroize();
        Ok(plaintext)
    }

    /// A seed-keyed tag of `data` for LOCAL exact-duplicate detection. HMAC-SHA256 under a key
    /// derived from this KEK, so the tag is meaningless to anyone without the seed and identical
    /// plaintext in two different vaults yields different tags — it is **not** a global fingerprint
    /// or a confirm-by-guess equality oracle. MUST stay local: never synced, never exported, or it
    /// would leak (see AGENTS.md "keyed-or-it-leaks").
    pub fn content_tag(&self, data: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut tag_key = [0u8; 32];
        hk.expand(b"keepsake/v1/dedup-tag", &mut tag_key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&tag_key)
            .expect("HMAC accepts a key of any length");
        Mac::update(&mut mac, data);
        let out = Mac::finalize(mac).into_bytes();
        tag_key.zeroize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out);
        tag
    }
}

/// An X25519 keypair for sharing — wrapping a DEK to a grantee's public key.
pub struct ShareKeypair {
    secret: StaticSecret,
    public: [u8; 32],
}

impl ShareKeypair {
    /// Derive a deterministic X25519 keypair from a 32-byte seed (e.g. `device_root`).
    pub fn from_seed(seed: &[u8; 32]) -> ShareKeypair {
        let secret = StaticSecret::from(*seed);
        let public = PublicKey::from(&secret).to_bytes();
        ShareKeypair { secret, public }
    }

    /// The public key to hand to others so they can seal data to you.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// Seal `plaintext` to a recipient's X25519 public key (anonymous sealed box:
/// ephemeral ECDH + HKDF + AES-256-GCM). Only the matching secret can open it.
///
/// Wire format: `ephemeral_public(32) || nonce(12) || ciphertext+tag`.
pub fn seal_to(recipient_public: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_public));
    if !shared_is_contributory(&shared) {
        return None;
    }
    let key = derive_share_key(shared.as_bytes());

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("share key is 32 bytes");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("AES-256-GCM encryption does not fail for valid inputs");

    let mut out = Vec::with_capacity(32 + 12 + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Open a box produced by [`seal_to`] with the recipient's keypair.
pub fn open_sealed(keypair: &ShareKeypair, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < 44 {
        return Err(CryptoError::Aead);
    }
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&sealed[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[32..44]);
    let ct = &sealed[44..];

    let shared = keypair.secret.diffie_hellman(&PublicKey::from(epk));
    if !shared_is_contributory(&shared) {
        return Err(CryptoError::Aead);
    }
    let key = derive_share_key(shared.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .map_err(|_| CryptoError::Aead)
}

/// X25519 maps every low-order public key to the all-zero shared secret (the scalar is
/// clamped to clear the cofactor, RFC 7748 §6.1). A non-zero shared secret therefore proves
/// the peer key was not low-order — rejecting the all-zero result blocks the classic
/// "encrypt to a key the attacker already knows" attack on the sealed box.
fn shared_is_contributory(shared: &x25519_dalek::SharedSecret) -> bool {
    shared.as_bytes() != &[0u8; 32]
}

fn derive_share_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut k = [0u8; 32];
    hk.expand(b"keepsake/v1/share", &mut k)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    k
}

/// A post-quantum **ML-DSA-65** (FIPS 204) signing identity, derived deterministically
/// from a 32-byte seed (e.g. `signing_root`). Signs operations/cells so a recipient can
/// verify provenance.
pub struct SigningIdentity {
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

impl SigningIdentity {
    /// Derive the signing key deterministically from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use ml_dsa::KeyInit;
        let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::new(&(*seed).into());
        SigningIdentity { signing_key }
    }

    /// The public verifying key, as bytes (hand to verifiers).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        use ml_dsa::Keypair;
        self.signing_key.verifying_key().encode().to_vec()
    }

    /// Sign a message, returning the encoded signature bytes.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::Signer;
        self.signing_key.sign(msg).encode().to_vec()
    }
}

/// A **hybrid X25519 + ML-KEM-768** keypair for post-quantum sharing. A grantee derives
/// it deterministically from a seed; senders seal to its public bytes so that breaking
/// *either* the classical or the PQ KEM alone does not reveal the data.
pub struct HybridShareKeypair {
    x_secret: StaticSecret,
    x_public: [u8; 32],
    kem_dk: <ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey,
    kem_ek_bytes: Vec<u8>,
}

/// ML-KEM-768 ciphertext length (FIPS 203).
const MLKEM768_CT_LEN: usize = 1088;

impl HybridShareKeypair {
    /// Derive the hybrid keypair deterministically from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use ml_kem::{EncodedSizeUser, KemCore};
        use rand_chacha::rand_core::SeedableRng;
        let x_secret = StaticSecret::from(*seed);
        let x_public = PublicKey::from(&x_secret).to_bytes();

        // Deterministic ML-KEM keypair via a seeded CSPRNG.
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut kem_seed = [0u8; 32];
        hk.expand(b"keepsake/v1/mlkem-seed", &mut kem_seed)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(kem_seed);
        let (kem_dk, kem_ek) = ml_kem::MlKem768::generate(&mut rng);

        HybridShareKeypair {
            x_secret,
            x_public,
            kem_dk,
            kem_ek_bytes: kem_ek.as_bytes().to_vec(),
        }
    }

    /// Public bytes to hand to senders: `x25519_public(32) || ml_kem_encapsulation_key`.
    pub fn public_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.kem_ek_bytes.len());
        out.extend_from_slice(&self.x_public);
        out.extend_from_slice(&self.kem_ek_bytes);
        out
    }

    /// Open a box produced by [`seal_to_hybrid`].
    pub fn open_hybrid(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        use ml_kem::kem::Decapsulate;
        if sealed.len() < 32 + MLKEM768_CT_LEN + 12 {
            return None;
        }
        let epk: [u8; 32] = sealed[..32].try_into().ok()?;
        let ct_bytes = &sealed[32..32 + MLKEM768_CT_LEN];
        let nonce = &sealed[32 + MLKEM768_CT_LEN..32 + MLKEM768_CT_LEN + 12];
        let body = &sealed[32 + MLKEM768_CT_LEN + 12..];

        let x_ss = self.x_secret.diffie_hellman(&PublicKey::from(epk));
        if !shared_is_contributory(&x_ss) {
            return None;
        }
        let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ct_bytes).ok()?;
        let kem_ss = self.kem_dk.decapsulate(&ct).ok()?;

        let key = derive_hybrid_key(x_ss.as_bytes(), kem_ss.as_slice());
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        cipher.decrypt(Nonce::from_slice(nonce), body).ok()
    }
}

/// Seal `plaintext` to a hybrid recipient (`public_bytes` from [`HybridShareKeypair`]).
///
/// Wire: `ephemeral_x25519(32) || ml_kem_ciphertext(1088) || nonce(12) || aes_gcm(body)`.
pub fn seal_to_hybrid(recipient_public: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncodedSizeUser, KemCore};
    if recipient_public.len() < 32 {
        return None;
    }
    let x_pub: [u8; 32] = recipient_public[..32].try_into().ok()?;
    let ek_bytes = &recipient_public[32..];
    let ek_enc =
        ml_kem::Encoded::<<ml_kem::MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_bytes)
            .ok()?;
    let ek = <ml_kem::MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);

    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral).to_bytes();
    let x_ss = ephemeral.diffie_hellman(&PublicKey::from(x_pub));
    if !shared_is_contributory(&x_ss) {
        return None;
    }

    let (ct, kem_ss) = ek.encapsulate(&mut OsRng).ok()?;

    let key = derive_hybrid_key(x_ss.as_bytes(), kem_ss.as_slice());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let body = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).ok()?;

    let mut out = Vec::with_capacity(32 + ct.len() + 12 + body.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Some(out)
}

fn derive_hybrid_key(x_ss: &[u8], kem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x_ss.len() + kem_ss.len());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(kem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut k = [0u8; 32];
    hk.expand(b"keepsake/v1/hybrid-share", &mut k)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    k
}

/// Verify an ML-DSA-65 signature of `msg` under `verifying_key`.
pub fn ml_dsa_verify(verifying_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::signature::Verifier;
    let Ok(vk_enc) = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(verifying_key) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&vk_enc);
    let Ok(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 of `data` under `key` — authenticates a sync snapshot so that only a holder
/// of the seed-derived [`RootKeys::sync_mac_key`] (one of the user's own devices) can produce
/// a valid tag. A relay, which never sees the seed, cannot forge one.
pub fn sync_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time verification of a [`sync_mac`] tag.
pub fn sync_mac_verify(key: &[u8; 32], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// SLIP-0039-style social recovery: Shamir Secret Sharing of the 32-byte master entropy
/// over GF(256), `threshold`-of-`shares`. (Raw shares; full SLIP-39 word mnemonics are a
/// follow-up.)
pub mod recovery {
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// One Shamir share: an x-index (1..=n) and the per-byte y-values.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Share {
        pub index: u8,
        pub bytes: Vec<u8>,
    }

    /// GF(2^8) multiply (AES reduction polynomial 0x11b).
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    fn gf_pow(mut a: u8, mut n: u32) -> u8 {
        let mut r = 1u8;
        while n > 0 {
            if n & 1 == 1 {
                r = gf_mul(r, a);
            }
            a = gf_mul(a, a);
            n >>= 1;
        }
        r
    }

    fn gf_inv(a: u8) -> u8 {
        gf_pow(a, 254) // a^(255-1); a^255 == 1 for a != 0
    }

    /// Split `secret` into `shares` shares; any `threshold` of them reconstruct it.
    pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Vec<Share> {
        assert!(threshold >= 1, "threshold must be >= 1");
        assert!(threshold <= shares, "threshold must be <= shares");
        assert!(shares < 255, "shares must be < 255");

        let mut rng = OsRng;
        let mut out: Vec<Share> = (1..=shares)
            .map(|i| Share {
                index: i,
                bytes: vec![0u8; secret.len()],
            })
            .collect();

        for (pos, &s) in secret.iter().enumerate() {
            let mut coeffs = vec![0u8; threshold as usize];
            coeffs[0] = s;
            if threshold > 1 {
                let mut rnd = vec![0u8; (threshold - 1) as usize];
                rng.fill_bytes(&mut rnd);
                coeffs[1..].copy_from_slice(&rnd);
            }
            for share in out.iter_mut() {
                let x = share.index;
                let mut y = 0u8;
                let mut xp = 1u8;
                for &c in &coeffs {
                    y ^= gf_mul(c, xp);
                    xp = gf_mul(xp, x);
                }
                share.bytes[pos] = y;
            }
        }
        out
    }

    /// Reconstruct a secret from `threshold` (or more) shares via Lagrange interpolation.
    pub fn combine(shares: &[Share]) -> Option<Vec<u8>> {
        let len = shares.first()?.bytes.len();
        if shares.iter().any(|s| s.bytes.len() != len) {
            return None;
        }
        // Lagrange interpolation needs distinct, non-zero x-indices. A repeated index makes
        // a denominator (x_i ^ x_j) zero -> GF inverse of zero -> a silently wrong secret;
        // index 0 collides with the secret's own x-coordinate. Reject both.
        for (i, si) in shares.iter().enumerate() {
            if si.index == 0 || shares[..i].iter().any(|s| s.index == si.index) {
                return None;
            }
        }
        let mut secret = vec![0u8; len];
        for (pos, byte) in secret.iter_mut().enumerate() {
            let mut acc = 0u8;
            for (i, si) in shares.iter().enumerate() {
                let (mut num, mut den) = (1u8, 1u8);
                for (j, sj) in shares.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    num = gf_mul(num, sj.index); // (0 - x_j) == x_j in GF(2^8)
                    den = gf_mul(den, si.index ^ sj.index); // (x_i - x_j) == x_i ^ x_j
                }
                acc ^= gf_mul(si.bytes[pos], gf_mul(num, gf_inv(den)));
            }
            *byte = acc;
        }
        Some(secret)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn three_of_five_recovers_from_any_three() {
            let secret: Vec<u8> = (0u8..32).collect();
            let shares = split(&secret, 3, 5);
            assert_eq!(shares.len(), 5);

            let s1 = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
            let s2 = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
            assert_eq!(combine(&s1).unwrap(), secret);
            assert_eq!(combine(&s2).unwrap(), secret);
            assert_ne!(shares[0].bytes, secret, "a single share is not the secret");
        }

        #[test]
        fn one_of_one_is_the_secret() {
            let secret = vec![7u8; 16];
            assert_eq!(combine(&split(&secret, 1, 1)).unwrap(), secret);
        }

        #[test]
        fn combine_rejects_duplicate_share_indices() {
            // Two shares carrying the same x-index is malformed input; combine must reject
            // it rather than silently returning a wrong secret (GF inverse of zero).
            let secret: Vec<u8> = (0u8..16).collect();
            let shares = split(&secret, 2, 3);
            let dup = vec![shares[0].clone(), shares[0].clone()];
            assert!(
                combine(&dup).is_none(),
                "combine must reject duplicate share indices"
            );
        }
    }
}

/// Device pairing: move the vault seed to a new device sealed to its one-time public key,
/// so multi-device setup needs no manual seed copy. Built on the X25519 sealed box.
pub mod pairing {
    use super::{open_sealed, seal_to, ShareKeypair};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    /// A new, unpaired device: holds a one-time keypair and shows a pairing code.
    pub struct NewDevice {
        keypair: ShareKeypair,
    }

    impl NewDevice {
        /// Generate a fresh one-time pairing keypair.
        pub fn generate() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            NewDevice::from_seed(&seed)
        }

        /// Reconstruct a pairing device from a saved secret seed (for a CLI flow that
        /// spans separate invocations).
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            NewDevice {
                keypair: ShareKeypair::from_seed(seed),
            }
        }

        /// The pairing code (X25519 public key) to display/scan on the existing device.
        pub fn pairing_code(&self) -> [u8; 32] {
            self.keypair.public()
        }

        /// Accept a sealed pairing offer, returning the vault mnemonic.
        pub fn accept(&self, sealed_offer: &[u8]) -> Option<String> {
            String::from_utf8(open_sealed(&self.keypair, sealed_offer).ok()?).ok()
        }

        /// The SAS this device computes for `offer` — the user compares it with the SAS shown
        /// on the offering device to detect a substituted code or tampered offer.
        pub fn sas(&self, offer: &[u8]) -> Option<String> {
            pairing_sas(&self.pairing_code(), offer)
        }
    }

    /// On the existing device: seal the vault `mnemonic` to a new device's `pairing_code`,
    /// returning the offer and the Short Authentication String the user MUST verify matches
    /// the new device before trusting the transfer (KS-012).
    pub fn make_offer(pairing_code: &[u8; 32], mnemonic: &str) -> Option<(Vec<u8>, String)> {
        let offer = seal_to(pairing_code, mnemonic.as_bytes())?;
        let sas = pairing_sas(pairing_code, &offer)?;
        Some((offer, sas))
    }

    /// A 6-digit Short Authentication String binding a pairing offer to a pairing code. Both
    /// devices compute it independently; the user compares them out of band. A substituted
    /// code or a tampered offer yields a different SAS, exposing a man-in-the-middle.
    pub fn pairing_sas(pairing_code: &[u8; 32], offer: &[u8]) -> Option<String> {
        if offer.len() < 32 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"keepsake/v1/pairing-sas");
        h.update(pairing_code);
        h.update(&offer[..32]); // the offer's ephemeral X25519 public key
        let d = h.finalize();
        let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
        Some(format!("{n:06}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        #[test]
        fn pairing_offer_carries_a_matching_sas_and_detects_substitution() {
            let device = NewDevice::generate();
            let code = device.pairing_code();
            let (offer, sas) = make_offer(&code, TEST_MNEMONIC).unwrap();

            // Honest transfer: the new device opens it and derives the SAME SAS.
            assert_eq!(device.accept(&offer).unwrap(), TEST_MNEMONIC);
            assert_eq!(device.sas(&offer).unwrap(), sas);

            // Only the paired device can open the offer.
            let attacker = NewDevice::generate();
            assert!(
                attacker.accept(&offer).is_none(),
                "only the paired device can open the offer"
            );
            // A different pairing code yields a different SAS, so a substituted code is caught.
            let (_atk_offer, atk_sas) =
                make_offer(&attacker.pairing_code(), TEST_MNEMONIC).unwrap();
            assert_ne!(atk_sas, sas, "a substituted pairing code yields a different SAS");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard BIP-39 256-bit test vector (zero entropy), 24 words.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    // Compile-time guarantee that the long-lived key types wipe themselves on drop.
    #[test]
    fn long_lived_key_types_zeroize_on_drop() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<Kek>();
        assert_zod::<RootKeys>();
    }

    #[test]
    fn ct_eq_matches_equality_but_in_constant_time() {
        assert!(ct_eq(b"123456", b"123456"));
        assert!(!ct_eq(b"123456", b"123450"));
        assert!(!ct_eq(b"12345", b"123456"), "different lengths are unequal");
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn content_tag_is_keyed_deterministic_and_not_a_global_fingerprint() {
        let kek_a = Kek::from_root(&RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap().encryption_root);
        // Same vault + same data → same tag (so an exact re-send can be detected).
        assert_eq!(kek_a.content_tag(b"my PIN is 1234"), kek_a.content_tag(b"my PIN is 1234"));
        // Different data → different tag.
        assert_ne!(kek_a.content_tag(b"my PIN is 1234"), kek_a.content_tag(b"my PIN is 5678"));
        // Different vault (different seed) → different tag for the SAME data: not a global oracle.
        let other = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let kek_b = Kek::from_root(&RootKeys::from_mnemonic(other, "").unwrap().encryption_root);
        assert_ne!(
            kek_a.content_tag(b"my PIN is 1234"),
            kek_b.content_tag(b"my PIN is 1234"),
            "the same plaintext must not produce the same tag across vaults"
        );
    }

    #[test]
    fn generated_mnemonic_is_24_unique_valid_words() {
        let phrase = generate_mnemonic();
        assert_eq!(phrase.split_whitespace().count(), 24, "24 words");
        // It must be a usable seed: derivation succeeds.
        assert!(RootKeys::from_mnemonic(&phrase, "").is_ok());
        // Fresh entropy each call (collision is astronomically unlikely).
        assert_ne!(phrase, generate_mnemonic(), "each seed is freshly random");
    }

    #[test]
    fn sync_slot_and_write_token_are_deterministic_and_separated() {
        let a = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let a2 = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Deterministic: every device holding the seed computes the same slot + token.
        assert_eq!(a.sync_slot(), a2.sync_slot());
        assert_eq!(a.sync_write_token(), a2.sync_write_token());
        // Domain-separated from each other and from the snapshot MAC key.
        assert_ne!(a.sync_slot(), a.sync_write_token());
        assert_ne!(a.sync_slot(), a.sync_mac_key());
        assert_ne!(a.sync_write_token(), a.sync_mac_key());
        // A different seed (here via a passphrase) yields a different slot — users never collide.
        let b = RootKeys::from_mnemonic(TEST_MNEMONIC, "another").unwrap();
        assert_ne!(a.sync_slot(), b.sync_slot());
    }

    #[test]
    fn root_derivation_is_deterministic_and_domain_separated() {
        let a = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let b = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();

        // Deterministic: same inputs -> same roots.
        assert_eq!(
            a.signing_root, b.signing_root,
            "derivation must be deterministic"
        );
        assert_eq!(a.encryption_root, b.encryption_root);

        // Domain separation: the four roots are pairwise distinct.
        let roots = [
            a.signing_root,
            a.encryption_root,
            a.device_root,
            a.receipt_root,
        ];
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "roots {i} and {j} must differ (domain separation)"
                );
            }
        }

        // The passphrase changes the derivation.
        let c = RootKeys::from_mnemonic(TEST_MNEMONIC, "passphrase").unwrap();
        assert_ne!(
            a.signing_root, c.signing_root,
            "passphrase must change derivation"
        );
    }

    #[test]
    fn db_key_is_deterministic_and_distinct_from_roots() {
        let a = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let b = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_eq!(a.db_key(), b.db_key());
        assert_ne!(a.db_key(), a.encryption_root);
    }

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    #[test]
    fn seal_open_roundtrips() {
        let kek = test_kek();
        let pt = b"my private memory";
        let (cell, wrapped) = kek.seal(pt);
        assert_eq!(kek.open(&cell, &wrapped).unwrap(), pt);
    }

    #[test]
    fn seal_uses_a_fresh_random_dek_each_time() {
        let kek = test_kek();
        let pt = b"same plaintext";
        let (c1, w1) = kek.seal(pt);
        let (c2, w2) = kek.seal(pt);
        assert_ne!(
            c1.ciphertext, c2.ciphertext,
            "ciphertext must differ (random DEK + nonce)"
        );
        assert_ne!(
            w1.bytes, w2.bytes,
            "wrapped DEKs must differ (fresh random DEK)"
        );
        assert_eq!(kek.open(&c1, &w1).unwrap(), pt);
        assert_eq!(kek.open(&c2, &w2).unwrap(), pt);
    }

    #[test]
    fn forget_destroys_decryptability_even_with_seed() {
        let kek = test_kek();
        let plaintext = b"erase me";
        let (cell, wrapped) = kek.seal(plaintext);

        // With the wrapped DEK, the holder can read the cell.
        assert_eq!(kek.open(&cell, &wrapped).unwrap(), plaintext);

        // forget(): destroy the only copy of the wrapping. The DEK was random and
        // never seed-derived, so re-deriving the seed roots cannot reconstruct it.
        drop(wrapped);
        let kek_from_seed = test_kek();

        // The holder still has the seed (-> KEK) and an old ciphertext backup, but
        // wrapping a fresh DEK yields a *different* key that cannot open the cell.
        let (_other, other_wrapped) = kek_from_seed.seal(plaintext);
        assert_eq!(
            kek_from_seed.open(&cell, &other_wrapped),
            Err(CryptoError::Aead),
            "after forget, no seed-derivable key can decrypt the cell"
        );
    }

    #[test]
    fn share_keypair_from_seed_is_deterministic() {
        let a = ShareKeypair::from_seed(&[7u8; 32]);
        let b = ShareKeypair::from_seed(&[7u8; 32]);
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), ShareKeypair::from_seed(&[8u8; 32]).public());
    }

    #[test]
    fn ml_dsa_sign_verify_and_deterministic_keygen() {
        let id = SigningIdentity::from_seed(&[3u8; 32]);
        let vk = id.verifying_key_bytes();
        let sig = id.sign(b"sign me");
        assert!(ml_dsa_verify(&vk, b"sign me", &sig));
        assert!(
            !ml_dsa_verify(&vk, b"tampered", &sig),
            "wrong message must fail"
        );

        let id2 = SigningIdentity::from_seed(&[3u8; 32]);
        assert_eq!(id2.verifying_key_bytes(), vk, "keygen is deterministic");
        let id3 = SigningIdentity::from_seed(&[4u8; 32]);
        assert_ne!(id3.verifying_key_bytes(), vk);
    }

    #[test]
    fn hybrid_seal_open_roundtrip_and_recipient_only() {
        let recipient = HybridShareKeypair::from_seed(&[1u8; 32]);
        let other = HybridShareKeypair::from_seed(&[2u8; 32]);
        let pub_bytes = recipient.public_bytes();

        let sealed = seal_to_hybrid(&pub_bytes, b"post-quantum secret").unwrap();
        assert_eq!(
            recipient.open_hybrid(&sealed).unwrap(),
            b"post-quantum secret"
        );
        assert!(
            other.open_hybrid(&sealed).is_none(),
            "a non-recipient must not open the hybrid box"
        );
        assert_eq!(
            HybridShareKeypair::from_seed(&[1u8; 32]).public_bytes(),
            pub_bytes,
            "hybrid keygen is deterministic"
        );
    }

    #[test]
    fn seal_to_opens_only_for_the_recipient() {
        let recipient = ShareKeypair::from_seed(&[1u8; 32]);
        let other = ShareKeypair::from_seed(&[2u8; 32]);
        let secret = b"this is a wrapped DEK";

        let sealed = seal_to(&recipient.public(), secret).unwrap();
        assert_eq!(open_sealed(&recipient, &sealed).unwrap(), secret);
        assert!(
            open_sealed(&other, &sealed).is_err(),
            "a non-recipient must not be able to open the box"
        );
    }

    #[test]
    fn seal_to_rejects_low_order_public_keys() {
        // The all-zero point is low-order: X25519 yields an all-zero shared secret the
        // attacker also knows, so a "sealed" box to it is not confidential. Reject it.
        assert!(
            seal_to(&[0u8; 32], b"secret").is_none(),
            "sealing to a low-order (all-zero) key must be rejected"
        );
    }

    #[test]
    fn open_sealed_rejects_low_order_ephemeral_key() {
        // An attacker using a low-order ephemeral key knows the shared secret is all-zero,
        // so they can craft a box the recipient would otherwise "successfully" open.
        let recipient = ShareKeypair::from_seed(&[1u8; 32]);
        let key = derive_share_key(&[0u8; 32]);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [0u8; 12];
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), b"attacker chosen".as_ref())
            .unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&[0u8; 32]); // low-order ephemeral public key
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        assert!(
            open_sealed(&recipient, &sealed).is_err(),
            "a box with a low-order ephemeral key must be rejected, not opened"
        );
    }
}
