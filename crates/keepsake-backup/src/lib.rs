//! `keepsake-backup` — OPAQUE-authenticated, zero-knowledge cloud backup.
//!
//! A self-hostable backup endpoint can validate the user's password and store an encrypted
//! backup **without ever seeing the password, the vault seed, or the plaintext**, and it
//! rate-limits *online* guesses while making *offline* brute-force impossible if its storage is
//! stolen (OPAQUE + Argon2). The protocol yields a password-derived **export key** that is blind
//! to the server; we use it to lock the [`keepsake_store_sqlite::Passport`] bytes before upload —
//! the "digital locker" pattern. The relay only ever holds an OPAQUE password file plus an opaque
//! ciphertext.
//!
//! This crate is the cryptographic core (handshake + locker), exercised end-to-end by tests. The
//! HTTP transport over the existing dumb relay is a thin, mechanical wrapper on top.

use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

/// The production cipher suite: Ristretto255 OPRF + Triple-DH (SHA-512) + **Argon2** as the key
/// stretching function. Argon2 is what makes an offline guess of the password infeasible even if
/// the server's stored password file is exfiltrated.
pub struct KeepsakeCipherSuite;

impl CipherSuite for KeepsakeCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

type Cs = KeepsakeCipherSuite;

/// A successful client login: `(finalization_bytes, session_key, export_key)`.
pub type ClientLoginOutput = (Vec<u8>, Vec<u8>, Vec<u8>);

/// A backup error: a failed OPAQUE step (e.g. wrong password) or a corrupt blob.
#[derive(Debug, PartialEq, Eq)]
pub enum BackupError {
    /// An OPAQUE protocol step failed — most commonly the password did not match.
    Protocol,
    /// The locked blob was malformed or its authentication tag did not verify.
    Blob,
}

// ---- Registration: the client enrols a password; the server stores only a blind password file.

/// Client step 1 — begin registration for `password`. Returns the in-progress client state and the
/// request bytes to send to the server.
pub fn client_register_start(password: &[u8]) -> (ClientRegistration<Cs>, Vec<u8>) {
    let res = ClientRegistration::<Cs>::start(&mut OsRng, password)
        .expect("client registration start is infallible for valid input");
    (res.state, res.message.serialize().to_vec())
}

/// Server step — respond to a registration request. `server_setup` is the server's long-term
/// secret; `credential_id` identifies the account (e.g. a fixed per-vault id).
pub fn server_register(
    server_setup: &[u8],
    request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let setup =
        ServerSetup::<Cs>::deserialize(server_setup).map_err(|_| BackupError::Protocol)?;
    let request = RegistrationRequest::<Cs>::deserialize(request).map_err(|_| BackupError::Protocol)?;
    let res = ServerRegistration::<Cs>::start(&setup, request, credential_id)
        .map_err(|_| BackupError::Protocol)?;
    Ok(res.message.serialize().to_vec())
}

/// Client step 2 — finish registration. Returns the upload bytes (for the server to store) and the
/// **export key** (kept on the client; the server never learns it).
pub fn client_register_finish(
    state: ClientRegistration<Cs>,
    password: &[u8],
    response: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), BackupError> {
    let response =
        RegistrationResponse::<Cs>::deserialize(response).map_err(|_| BackupError::Protocol)?;
    let res = state
        .finish(
            &mut OsRng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| BackupError::Protocol)?;
    Ok((res.message.serialize().to_vec(), res.export_key.to_vec()))
}

/// Server step — finalize and produce the password file to persist for this account.
pub fn server_register_finish(upload: &[u8]) -> Result<Vec<u8>, BackupError> {
    let upload = RegistrationUpload::<Cs>::deserialize(upload).map_err(|_| BackupError::Protocol)?;
    Ok(ServerRegistration::<Cs>::finish(upload).serialize().to_vec())
}

// ---- Login: the client proves the password; both sides derive a session key + the export key.

/// Client step 1 — begin login for `password`. Returns the client state and request bytes.
pub fn client_login_start(password: &[u8]) -> (ClientLogin<Cs>, Vec<u8>) {
    let res = ClientLogin::<Cs>::start(&mut OsRng, password)
        .expect("client login start is infallible for valid input");
    (res.state, res.message.serialize().to_vec())
}

/// Server step — respond to a login request using the stored `password_file`.
pub fn server_login_start(
    server_setup: &[u8],
    password_file: &[u8],
    request: &[u8],
    credential_id: &[u8],
) -> Result<(ServerLogin<Cs>, Vec<u8>), BackupError> {
    let setup =
        ServerSetup::<Cs>::deserialize(server_setup).map_err(|_| BackupError::Protocol)?;
    let password_file =
        ServerRegistration::<Cs>::deserialize(password_file).map_err(|_| BackupError::Protocol)?;
    let request = CredentialRequest::<Cs>::deserialize(request).map_err(|_| BackupError::Protocol)?;
    let res = ServerLogin::<Cs>::start(
        &mut OsRng,
        &setup,
        Some(password_file),
        request,
        credential_id,
        ServerLoginParameters::default(),
    )
    .map_err(|_| BackupError::Protocol)?;
    Ok((res.state, res.message.serialize().to_vec()))
}

/// Client step 2 — finish login. A wrong password fails here. Returns
/// `(finalization_bytes, session_key, export_key)`.
pub fn client_login_finish(
    state: ClientLogin<Cs>,
    password: &[u8],
    response: &[u8],
) -> Result<ClientLoginOutput, BackupError> {
    let response =
        CredentialResponse::<Cs>::deserialize(response).map_err(|_| BackupError::Protocol)?;
    let res = state
        .finish(
            &mut OsRng,
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| BackupError::Protocol)?;
    Ok((
        res.message.serialize().to_vec(),
        res.session_key.to_vec(),
        res.export_key.to_vec(),
    ))
}

/// Server step — verify the client's finalization and derive the matching session key.
pub fn server_login_finish(
    state: ServerLogin<Cs>,
    finalization: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let finalization =
        CredentialFinalization::<Cs>::deserialize(finalization).map_err(|_| BackupError::Protocol)?;
    let res = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| BackupError::Protocol)?;
    Ok(res.session_key.to_vec())
}

/// Create a fresh server long-term setup (serialized) — persist it on the backup server.
pub fn server_setup_new() -> Vec<u8> {
    ServerSetup::<Cs>::new(&mut OsRng).serialize().to_vec()
}

// ---- The locker: encrypt the backup with the (server-blind) export key before upload.

/// Lock `plaintext` (e.g. a serialized passport) under the password-derived `export_key`, so the
/// server stores only opaque ciphertext. Output = `nonce || ciphertext+tag`.
pub fn lock_blob(export_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
    if export_key.len() < 32 {
        return Err(BackupError::Blob);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&export_key[..32]));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| BackupError::Blob)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unlock a blob produced by [`lock_blob`]. Fails (`BackupError::Blob`) on the wrong key or any
/// tampering — the AEAD tag must verify.
pub fn unlock_blob(export_key: &[u8], blob: &[u8]) -> Result<Vec<u8>, BackupError> {
    if export_key.len() < 32 || blob.len() < 12 {
        return Err(BackupError::Blob);
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&export_key[..32]));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| BackupError::Blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &[u8] = b"vault@keepsake";

    /// Run a full register→login round-trip; returns the export keys from each phase.
    fn register_then_login(register_pw: &[u8], login_pw: &[u8]) -> (Vec<u8>, Result<Vec<u8>, BackupError>) {
        let setup = server_setup_new();

        // Registration.
        let (cstate, req) = client_register_start(register_pw);
        let resp = server_register(&setup, &req, ID).unwrap();
        let (upload, reg_export) = client_register_finish(cstate, register_pw, &resp).unwrap();
        let password_file = server_register_finish(&upload).unwrap();

        // Login (possibly with a different password).
        let (cstate, req) = client_login_start(login_pw);
        let (sstate, resp) = server_login_start(&setup, &password_file, &req, ID).unwrap();
        let login = client_login_finish(cstate, login_pw, &resp);
        // Drive the server side only when the client finished (a wrong password fails client-side).
        if let Ok((finalization, _client_session, login_export)) = &login {
            let server_session = server_login_finish(sstate, finalization).unwrap();
            assert_eq!(
                login.as_ref().unwrap().1,
                server_session,
                "client and server agree on the session key"
            );
            (reg_export, Ok(login_export.clone()))
        } else {
            (reg_export, Err(BackupError::Protocol))
        }
    }

    #[test]
    fn correct_password_yields_the_same_export_key_register_and_login() {
        let (reg, login) = register_then_login(b"correct horse battery", b"correct horse battery");
        assert_eq!(reg, login.unwrap(), "export key is stable across register and login");
    }

    #[test]
    fn wrong_password_fails_login() {
        let (_reg, login) = register_then_login(b"the-real-password", b"a-wrong-guess");
        assert_eq!(login, Err(BackupError::Protocol), "a wrong password must not authenticate");
    }

    #[test]
    fn export_key_locks_and_unlocks_the_backup_blob() {
        let (reg, login) = register_then_login(b"vault-pass-123", b"vault-pass-123");
        let export = login.unwrap();
        assert_eq!(reg, export);

        let secret = b"the serialized memory passport bytes";
        let blob = lock_blob(&export, secret).unwrap();
        assert_ne!(&blob[12..], &secret[..], "the blob is ciphertext, not plaintext");
        assert_eq!(unlock_blob(&export, &blob).unwrap(), secret, "the right key unlocks");

        // A different export key (wrong password) cannot unlock the blob.
        let wrong = vec![0u8; 64];
        assert_eq!(unlock_blob(&wrong, &blob), Err(BackupError::Blob));
    }
}
