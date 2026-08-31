//! OPAQUE (aPAKE) authentication via `opaque-ke`.
//!
//! The server never sees the master password or a password-equivalent hash. It
//! holds a global `ServerSetup` (persisted) and one per-account password file
//! (`ServerRegistration`). Registration is a two-round exchange with no server
//! state between rounds; login keeps short-lived `ServerLogin` state in memory
//! (see [`crate::state`]) between start and finish.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::error::{AppError, AppResult};

/// OPAQUE cipher suite: ristretto255 OPRF + 3DH key exchange. The password-
/// stretching KSF is `Identity` here because the vault's own Argon2id
/// (design.md Decision 3) already stretches the master password before it is
/// used; OPAQUE provides the augmented-PAKE property on top.
#[derive(Debug)]
pub struct CipherSuite;
impl opaque_ke::CipherSuite for CipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| AppError::BadRequest("invalid base64 in OPAQUE message".into()))
}

fn proto_err<E: std::fmt::Display>(_e: E) -> AppError {
    // Never leak protocol specifics that could aid an attacker.
    AppError::Unauthorized
}

/// Create a fresh server setup (OPRF seed etc.), returned base64 for persistence.
pub fn new_server_setup() -> String {
    let setup = ServerSetup::<CipherSuite>::new(&mut OsRng);
    b64(setup.serialize().as_slice())
}

fn load_setup(setup_b64: &str) -> AppResult<ServerSetup<CipherSuite>> {
    let bytes = unb64(setup_b64)?;
    ServerSetup::<CipherSuite>::deserialize(&bytes)
        .map_err(|e| AppError::Internal(format!("bad server setup: {e}")))
}

/// Round 1 of registration: given the client's `RegistrationRequest`, produce the
/// `RegistrationResponse`. `credential_identifier` is the account username.
pub fn register_start(
    setup_b64: &str,
    credential_identifier: &[u8],
    registration_request_b64: &str,
) -> AppResult<String> {
    let setup = load_setup(setup_b64)?;
    let req_bytes = unb64(registration_request_b64)?;
    let request = RegistrationRequest::<CipherSuite>::deserialize(&req_bytes).map_err(proto_err)?;
    let result = ServerRegistration::<CipherSuite>::start(&setup, request, credential_identifier)
        .map_err(proto_err)?;
    Ok(b64(result.message.serialize().as_slice()))
}

/// Round 2 of registration: finish the client's `RegistrationUpload` into the
/// stored password file (base64), which the caller persists on the account.
pub fn register_finish(registration_upload_b64: &str) -> AppResult<String> {
    let bytes = unb64(registration_upload_b64)?;
    let upload = RegistrationUpload::<CipherSuite>::deserialize(&bytes).map_err(proto_err)?;
    let password_file = ServerRegistration::<CipherSuite>::finish(upload);
    Ok(b64(password_file.serialize().as_slice()))
}

/// Round 1 of login: start the server side, returning the in-memory
/// `ServerLogin` state (to stash keyed by a flow id) and the base64
/// `CredentialResponse` for the client.
/// `password_file_b64` is `None` for an unknown username: opaque-ke returns a
/// decoy `CredentialResponse` so the caller cannot enumerate accounts (the
/// finish will simply fail).
pub fn login_start(
    setup_b64: &str,
    password_file_b64: Option<&str>,
    credential_identifier: &[u8],
    credential_request_b64: &str,
) -> AppResult<(ServerLogin<CipherSuite>, String)> {
    let setup = load_setup(setup_b64)?;
    let password_file = match password_file_b64 {
        Some(pf) => {
            let pf_bytes = unb64(pf)?;
            Some(ServerRegistration::<CipherSuite>::deserialize(&pf_bytes).map_err(proto_err)?)
        }
        None => None,
    };
    let req_bytes = unb64(credential_request_b64)?;
    let request = CredentialRequest::<CipherSuite>::deserialize(&req_bytes).map_err(proto_err)?;
    let result = ServerLogin::start(
        &mut OsRng,
        &setup,
        password_file,
        request,
        credential_identifier,
        ServerLoginStartParameters::default(),
    )
    .map_err(proto_err)?;
    Ok((result.state, b64(result.message.serialize().as_slice())))
}

/// Round 2 of login: verify the client's `CredentialFinalization`. On success the
/// shared session key proves the client knew the password. We do not return the
/// key; success/failure is the signal.
pub fn login_finish(
    state: ServerLogin<CipherSuite>,
    credential_finalization_b64: &str,
) -> AppResult<()> {
    let bytes = unb64(credential_finalization_b64)?;
    let finalization =
        CredentialFinalization::<CipherSuite>::deserialize(&bytes).map_err(proto_err)?;
    state.finish(finalization).map_err(proto_err)?;
    Ok(())
}
