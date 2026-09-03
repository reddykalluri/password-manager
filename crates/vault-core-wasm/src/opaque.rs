//! OPAQUE client bindings (browser side of the PAKE).
//!
//! The ciphersuite MUST match `vault-server`'s exactly, or registration/login
//! will fail. Ceremony state is serialized and handed to JS between the start
//! and finish round trips.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Must be identical to `vault_server::auth::opaque::CipherSuite`.
struct CipherSuite;
impl opaque_ke::CipherSuite for CipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, JsError> {
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| JsError::new("invalid base64"))
}

fn opaque_err() -> JsError {
    // Deliberately generic; never reveal protocol specifics.
    JsError::new("OPAQUE protocol error")
}

#[derive(Serialize)]
struct StartResult {
    /// Serialized client ceremony state (opaque to JS; hand back on finish).
    state: String,
    /// Message to send to the server.
    message: String,
}

/// Begin OPAQUE registration. Returns `{ state, message }` (both base64).
#[wasm_bindgen(js_name = opaqueRegisterStart)]
pub fn register_start(password: &str) -> Result<String, JsError> {
    let mut rng = OsRng;
    let result =
        ClientRegistration::<CipherSuite>::start(&mut rng, password.as_bytes()).map_err(|_| opaque_err())?;
    Ok(serde_json::to_string(&StartResult {
        state: b64(result.state.serialize().as_slice()),
        message: b64(result.message.serialize().as_slice()),
    })?)
}

/// Finish OPAQUE registration, returning the base64 upload for the server.
#[wasm_bindgen(js_name = opaqueRegisterFinish)]
pub fn register_finish(
    state_b64: &str,
    password: &str,
    response_b64: &str,
) -> Result<String, JsError> {
    let state =
        ClientRegistration::<CipherSuite>::deserialize(&unb64(state_b64)?).map_err(|_| opaque_err())?;
    let response = RegistrationResponse::<CipherSuite>::deserialize(&unb64(response_b64)?)
        .map_err(|_| opaque_err())?;
    let mut rng = OsRng;
    let result = state
        .finish(
            &mut rng,
            password.as_bytes(),
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| opaque_err())?;
    Ok(b64(result.message.serialize().as_slice()))
}

/// Begin OPAQUE login. Returns `{ state, message }` (both base64).
#[wasm_bindgen(js_name = opaqueLoginStart)]
pub fn login_start(password: &str) -> Result<String, JsError> {
    let mut rng = OsRng;
    let result =
        ClientLogin::<CipherSuite>::start(&mut rng, password.as_bytes()).map_err(|_| opaque_err())?;
    Ok(serde_json::to_string(&StartResult {
        state: b64(result.state.serialize().as_slice()),
        message: b64(result.message.serialize().as_slice()),
    })?)
}

/// Finish OPAQUE login, returning the base64 finalization. Errors on a wrong
/// master password.
#[wasm_bindgen(js_name = opaqueLoginFinish)]
pub fn login_finish(state_b64: &str, password: &str, response_b64: &str) -> Result<String, JsError> {
    let state =
        ClientLogin::<CipherSuite>::deserialize(&unb64(state_b64)?).map_err(|_| opaque_err())?;
    let response = CredentialResponse::<CipherSuite>::deserialize(&unb64(response_b64)?)
        .map_err(|_| opaque_err())?;
    let result = state
        .finish(
            password.as_bytes(),
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| opaque_err())?;
    Ok(b64(result.message.serialize().as_slice()))
}
