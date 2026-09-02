//! OPAQUE client (native, for mobile). Ciphersuite MUST match vault-server.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde::Serialize;

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
fn unb64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s.as_bytes()).map_err(|_| "invalid base64".to_string())
}
fn err() -> String {
    "OPAQUE protocol error".to_string()
}

#[derive(Serialize)]
struct StartResult {
    state: String,
    message: String,
}

pub fn register_start(password: &str) -> Result<String, String> {
    let mut rng = OsRng;
    let r = ClientRegistration::<CipherSuite>::start(&mut rng, password.as_bytes()).map_err(|_| err())?;
    serde_json::to_string(&StartResult {
        state: b64(r.state.serialize().as_slice()),
        message: b64(r.message.serialize().as_slice()),
    })
    .map_err(|e| e.to_string())
}

pub fn register_finish(state_b64: &str, password: &str, response_b64: &str) -> Result<String, String> {
    let state = ClientRegistration::<CipherSuite>::deserialize(&unb64(state_b64)?).map_err(|_| err())?;
    let response =
        RegistrationResponse::<CipherSuite>::deserialize(&unb64(response_b64)?).map_err(|_| err())?;
    let mut rng = OsRng;
    let r = state
        .finish(&mut rng, password.as_bytes(), response, ClientRegistrationFinishParameters::default())
        .map_err(|_| err())?;
    Ok(b64(r.message.serialize().as_slice()))
}

pub fn login_start(password: &str) -> Result<String, String> {
    let mut rng = OsRng;
    let r = ClientLogin::<CipherSuite>::start(&mut rng, password.as_bytes()).map_err(|_| err())?;
    serde_json::to_string(&StartResult {
        state: b64(r.state.serialize().as_slice()),
        message: b64(r.message.serialize().as_slice()),
    })
    .map_err(|e| e.to_string())
}

pub fn login_finish(state_b64: &str, password: &str, response_b64: &str) -> Result<String, String> {
    let state = ClientLogin::<CipherSuite>::deserialize(&unb64(state_b64)?).map_err(|_| err())?;
    let response =
        CredentialResponse::<CipherSuite>::deserialize(&unb64(response_b64)?).map_err(|_| err())?;
    let r = state
        .finish(password.as_bytes(), response, ClientLoginFinishParameters::default())
        .map_err(|_| err())?;
    Ok(b64(r.message.serialize().as_slice()))
}
