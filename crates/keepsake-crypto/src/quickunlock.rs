//! Quick-unlock: wrap the 24-word mnemonic under a user PIN/passphrase so the app can
//! re-open without re-typing the words. `PIN -> Argon2id -> AES-256-GCM(mnemonic)`.
//!
//! The wrapped seed is a **local convenience artifact only** — never synced, never placed
//! in a Memory Receipt or the relay stream. Security rests on `Argon2id cost x PIN entropy`:
//! a short PIN is the real risk, so a minimum length is enforced at the call site and a
//! passphrase is offered. This wraps the **mnemonic** (the single root the app re-derives
//! everything from), never the KEK/db-key — and it never touches the random per-cell DEKs,
//! so `forget` stays cryptographically final.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

/// Default Argon2id cost: 64 MiB, 3 passes, 1 lane. Heavier than the backup default on
/// purpose — a PIN is low-entropy, so each offline guess must be expensive (~<150 ms here).
pub const QU_M_KIB: u32 = 65536;
pub const QU_T: u32 = 3;
pub const QU_P: u32 = 1;

/// A mnemonic wrapped under a PIN-derived key (the on-disk shape; the KDF params travel with
/// it so the cost can be raised later without breaking existing files).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedSeed {
    pub v: u8,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

impl WrappedSeed {
    /// Canonical KDF-parameter bytes bound into the AEAD as associated data, so a
    /// params-downgrade attack (rewriting `m_kib` from 64 MiB to 8 MiB to cheapen offline
    /// guessing) surfaces as a decryption failure rather than a cheaper crack.
    fn aad(&self) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[0] = self.v;
        a[1..5].copy_from_slice(&self.m_kib.to_le_bytes());
        a[5..9].copy_from_slice(&self.t.to_le_bytes());
        a[9..13].copy_from_slice(&self.p.to_le_bytes());
        a
    }
}

fn derive_key(pin: &str, salt: &[u8; 16], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|_| CryptoError::Aead)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a2.hash_password_into(pin.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Aead)?;
    Ok(key)
}

/// Wrap `mnemonic` under `pin`. Fresh random salt + nonce each call.
pub fn wrap_mnemonic(pin: &str, mnemonic: &str) -> WrappedSeed {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut w = WrappedSeed { v: 1, m_kib: QU_M_KIB, t: QU_T, p: QU_P, salt, nonce, ct: Vec::new() };
    let mut key = derive_key(pin, &salt, QU_M_KIB, QU_T, QU_P).expect("default argon2 params are valid");
    let cipher = Aes256Gcm::new_from_slice(&key).expect("argon2 output is 32 bytes");
    let aad = w.aad();
    w.ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: mnemonic.as_bytes(), aad: &aad })
        .expect("aes-256-gcm encryption does not fail");
    key.zeroize();
    w
}

/// Recover the mnemonic from `pin`. A wrong PIN or any tamper (ciphertext, salt, nonce, or a
/// downgraded KDF param) is `CryptoError::Aead`.
pub fn unwrap_mnemonic(pin: &str, w: &WrappedSeed) -> Result<Zeroizing<String>, CryptoError> {
    let mut key = derive_key(pin, &w.salt, w.m_kib, w.t, w.p)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Aead)?;
    let aad = w.aad();
    let pt = cipher
        .decrypt(Nonce::from_slice(&w.nonce), Payload { msg: &w.ct, aad: &aad })
        .map_err(|_| CryptoError::Aead);
    key.zeroize();
    let bytes = pt?;
    let s = String::from_utf8(bytes).map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const PIN: &str = "734512";

    #[test]
    fn round_trip() {
        let w = wrap_mnemonic(PIN, M);
        assert_eq!(&*unwrap_mnemonic(PIN, &w).unwrap(), M);
    }

    #[test]
    fn wrong_pin_fails() {
        let w = wrap_mnemonic(PIN, M);
        assert!(matches!(unwrap_mnemonic("000000", &w), Err(CryptoError::Aead)));
    }

    #[test]
    fn tamper_ct_fails() {
        let mut w = wrap_mnemonic(PIN, M);
        w.ct[0] ^= 0xff;
        assert!(matches!(unwrap_mnemonic(PIN, &w), Err(CryptoError::Aead)));
    }

    #[test]
    fn tamper_salt_fails() {
        let mut w = wrap_mnemonic(PIN, M);
        w.salt[0] ^= 0xff;
        assert!(matches!(unwrap_mnemonic(PIN, &w), Err(CryptoError::Aead)));
    }

    #[test]
    fn tamper_nonce_fails() {
        let mut w = wrap_mnemonic(PIN, M);
        w.nonce[0] ^= 0xff;
        assert!(matches!(unwrap_mnemonic(PIN, &w), Err(CryptoError::Aead)));
    }

    #[test]
    fn params_downgrade_fails() {
        let mut w = wrap_mnemonic(PIN, M);
        w.m_kib = 8192; // attacker tries to cheapen offline guessing
        assert!(matches!(unwrap_mnemonic(PIN, &w), Err(CryptoError::Aead)));
    }

    #[test]
    fn distinct_salt_and_ciphertext_each_time() {
        let a = wrap_mnemonic(PIN, M);
        let b = wrap_mnemonic(PIN, M);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ct, b.ct);
        assert_eq!(&*unwrap_mnemonic(PIN, &a).unwrap(), M);
        assert_eq!(&*unwrap_mnemonic(PIN, &b).unwrap(), M);
    }

    #[test]
    fn survives_json_roundtrip() {
        let w = wrap_mnemonic(PIN, M);
        let json = serde_json::to_string(&w).unwrap();
        let w2: WrappedSeed = serde_json::from_str(&json).unwrap();
        assert_eq!(&*unwrap_mnemonic(PIN, &w2).unwrap(), M);
    }
}
