//! End-to-end API tests: OPAQUE register/login, token auth, delta sync with
//! versioned writes and 409 conflicts, and multi-account isolation.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

use vault_core::crypto::SealedBlob;
use vault_core::store::ItemRecord;
use vault_server::auth::opaque::CipherSuite;
use vault_server::config::{Config, Registration};
use vault_server::db::Db;
use vault_server::routes;
use vault_server::state::AppState;

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

async fn build_state(registration: Registration) -> vault_server::state::SharedState {
    let path = std::env::temp_dir().join(format!("vault-test-{}.db", Uuid::new_v4()));
    let url = format!("sqlite://{}", path.display());
    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: url,
        web_root: None,
        registration,
        access_token_ttl: std::time::Duration::from_secs(900),
        refresh_token_ttl: std::time::Duration::from_secs(3600),
        public_origin: "http://localhost".into(),
        login_backoff_threshold: 10,
    };
    let db = Db::connect(&config.database_url).await.unwrap();
    AppState::bootstrap(config, db).await.unwrap()
}

async fn build_app(registration: Registration) -> Router {
    routes::router(build_state(registration).await)
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Drive the OPAQUE client registration + finish, returning AuthTokens JSON.
async fn register(
    app: &Router,
    username: &str,
    password: &str,
    invite: Option<&str>,
) -> (StatusCode, Value) {
    let mut rng = OsRng;
    let start = ClientRegistration::<CipherSuite>::start(&mut rng, password.as_bytes()).unwrap();
    let (st, resp) = call(
        app,
        "POST",
        "/api/v1/auth/register/start",
        None,
        json!({"username": username, "registration_request": b64(start.message.serialize().as_slice())}),
    )
    .await;
    if st != StatusCode::OK {
        return (st, resp);
    }
    let reg_resp = RegistrationResponse::<CipherSuite>::deserialize(&unb64(
        resp["registration_response"].as_str().unwrap(),
    ))
    .unwrap();
    let finish = start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            reg_resp,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let mut body = json!({
        "username": username,
        "registration_upload": b64(finish.message.serialize().as_slice()),
        "account_crypto": {"marker": username},
        "device_name": "test-device",
    });
    if let Some(code) = invite {
        body["invite_code"] = json!(code);
    }
    call(app, "POST", "/api/v1/auth/register/finish", None, body).await
}

/// Drive the OPAQUE login, returning (status, body). `totp` optional.
async fn login(
    app: &Router,
    username: &str,
    password: &str,
    totp: Option<&str>,
) -> (StatusCode, Value) {
    let mut rng = OsRng;
    let start = ClientLogin::<CipherSuite>::start(&mut rng, password.as_bytes()).unwrap();
    let (st, resp) = call(
        app,
        "POST",
        "/api/v1/auth/login/start",
        None,
        json!({"username": username, "credential_request": b64(start.message.serialize().as_slice())}),
    )
    .await;
    if st != StatusCode::OK {
        return (st, resp);
    }
    let flow_id = resp["flow_id"].as_str().unwrap().to_string();
    let cred_resp = CredentialResponse::<CipherSuite>::deserialize(&unb64(
        resp["credential_response"].as_str().unwrap(),
    ))
    .unwrap();
    let finish = match start.state.finish(
        password.as_bytes(),
        cred_resp,
        ClientLoginFinishParameters::default(),
    ) {
        Ok(f) => f,
        // Wrong password: the client aborts. Emulate a finalization the server
        // will reject by sending an empty message is not possible; instead we
        // report unauthorized to mirror the server's decision.
        Err(_) => return (StatusCode::UNAUTHORIZED, Value::Null),
    };
    let mut body = json!({
        "flow_id": flow_id,
        "credential_finalization": b64(finish.message.serialize().as_slice()),
        "device_name": "test-device",
    });
    if let Some(code) = totp {
        body["totp_code"] = json!(code);
    }
    call(app, "POST", "/api/v1/auth/login/finish", None, body).await
}

fn sample_record(vault_id: Uuid) -> ItemRecord {
    ItemRecord {
        id: Uuid::new_v4(),
        vault_id,
        version: 1,
        modified_at: OffsetDateTime::now_utc(),
        deleted: false,
        sealed: Some(SealedBlob {
            nonce: vec![0u8; 24],
            ciphertext: vec![1, 2, 3, 4],
        }),
        history: vec![],
    }
}

#[tokio::test]
async fn health_and_readiness() {
    let app = build_app(Registration::Open).await;
    let (st, body) = call(&app, "GET", "/health", None, Value::Null).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    let (st, body) = call(&app, "GET", "/ready", None, Value::Null).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn register_login_and_wrong_password() {
    let app = build_app(Registration::Open).await;
    let (st, tokens) = register(&app, "alice", "correct-horse", None).await;
    assert_eq!(st, StatusCode::OK, "register: {tokens}");
    assert!(tokens["access_token"].is_string());

    // Correct password logs in.
    let (st, body) = login(&app, "alice", "correct-horse", None).await;
    assert_eq!(st, StatusCode::OK, "login: {body}");
    assert!(body["access_token"].is_string());

    // Wrong password is rejected.
    let (st, _) = login(&app, "alice", "wrong-password", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Unknown user is rejected without revealing existence.
    let (st, _) = login(&app, "nobody", "whatever", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_crypto_roundtrip_and_auth_required() {
    let app = build_app(Registration::Open).await;
    let (_, tokens) = register(&app, "bob", "pw12345", None).await;
    let access = tokens["access_token"].as_str().unwrap();

    // Authenticated read returns what was stored at registration.
    let (st, body) = call(
        &app,
        "GET",
        "/api/v1/account/crypto",
        Some(access),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["marker"], "bob");

    // No token → 401.
    let (st, _) = call(&app, "GET", "/api/v1/account/crypto", None, Value::Null).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sync_push_pull_and_stale_write_conflict() {
    let app = build_app(Registration::Open).await;
    let (_, tokens) = register(&app, "carol", "pw-carol", None).await;
    let access = tokens["access_token"].as_str().unwrap();
    let vault = Uuid::new_v4();
    let rec = sample_record(vault);

    // Push a new item (base_version 0 → accepted as version 1).
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(access),
        json!({"record": rec, "base_version": 0}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "push: {body}");
    assert_eq!(body["new_version"], 1);

    // Pull from cursor 0 returns the item.
    let (st, body) = call(
        &app,
        "GET",
        "/api/v1/sync?cursor=0",
        Some(access),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["id"], rec.id.to_string());

    // Stale write (base_version 0 again, but server is at 1) → 409 with current.
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(access),
        json!({"record": rec, "base_version": 0}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "expected 409: {body}");
    assert_eq!(body["current"]["version"], 1);

    // Fast-forward (base_version 1) → accepted as version 2.
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(access),
        json!({"record": rec, "base_version": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["new_version"], 2);
}

#[tokio::test]
async fn cross_account_isolation() {
    let app = build_app(Registration::Open).await;
    let (_, a) = register(&app, "acct-a", "pw-a", None).await;
    let (_, b) = register(&app, "acct-b", "pw-b", None).await;
    let a_access = a["access_token"].as_str().unwrap();
    let b_access = b["access_token"].as_str().unwrap();

    // B creates an item.
    let rec = sample_record(Uuid::new_v4());
    let (st, _) = call(
        &app,
        "POST",
        "/api/v1/sync/push",
        Some(b_access),
        json!({"record": rec, "base_version": 0}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // A requests B's item id → 404 (no existence confirmation).
    let (st, _) = call(
        &app,
        "GET",
        &format!("/api/v1/sync/item/{}", rec.id),
        Some(a_access),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // A's own pull does not see B's item.
    let (st, body) = call(
        &app,
        "GET",
        "/api/v1/sync?cursor=0",
        Some(a_access),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn webauthn_second_factor_end_to_end() {
    use url::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    let app = build_app(Registration::Open).await;
    let (_, tokens) = register(&app, "wauser", "pw-wa", None).await;
    let access = tokens["access_token"].as_str().unwrap().to_string();

    // A software authenticator that persists its credential across ceremonies.
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let origin = Url::parse("http://localhost").unwrap();

    // --- enrol a WebAuthn credential ---
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/account/2fa/webauthn/register/start",
        Some(&access),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "reg start: {body}");
    let reg_flow = body["flow_id"].as_str().unwrap().to_string();
    let ccr: CreationChallengeResponse = serde_json::from_value(body["challenge"].clone()).unwrap();
    let reg_cred = authenticator.do_registration(origin.clone(), ccr).unwrap();
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/account/2fa/webauthn/register/finish",
        Some(&access),
        json!({"flow_id": reg_flow, "credential": reg_cred}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "reg finish: {body}");
    assert_eq!(body["status"], "enrolled");

    // --- login now demands the WebAuthn second factor ---
    let (st, body) = login(&app, "wauser", "pw-wa", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        body.get("access_token").is_none(),
        "expected a 2FA challenge, not tokens: {body}"
    );
    let wa_flow = body["second_factor"]["webauthn_flow_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(body["second_factor"]["webauthn_challenge"].clone()).unwrap();
    let assertion = authenticator
        .do_authentication(origin.clone(), rcr)
        .unwrap();
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/auth/login/webauthn/finish",
        None,
        json!({"webauthn_flow_id": wa_flow, "credential": assertion, "device_name": "wa-device"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login webauthn finish: {body}");
    let access2 = body["access_token"].as_str().unwrap().to_string();

    // --- sensitive op requires step-up: blocked without it, allowed with it ---
    let (st, _) = call(
        &app,
        "PUT",
        "/api/v1/account/crypto",
        Some(&access2),
        json!({"account_crypto": {"marker": "updated"}}),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "sensitive op must require 2FA"
    );

    // Step-up assertion → token.
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/account/2fa/webauthn/stepup/start",
        Some(&access2),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "stepup start: {body}");
    let su_flow = body["flow_id"].as_str().unwrap().to_string();
    let rcr: RequestChallengeResponse = serde_json::from_value(body["challenge"].clone()).unwrap();
    let assertion = authenticator
        .do_authentication(origin.clone(), rcr)
        .unwrap();
    let (st, body) = call(
        &app,
        "POST",
        "/api/v1/account/2fa/webauthn/stepup/finish",
        Some(&access2),
        json!({"flow_id": su_flow, "credential": assertion}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "stepup finish: {body}");
    let stepup = body["stepup_token"].as_str().unwrap().to_string();

    // Now the sensitive op succeeds.
    let (st, body) = call(
        &app,
        "PUT",
        "/api/v1/account/crypto",
        Some(&access2),
        json!({"account_crypto": {"marker": "updated"}, "stepup_token": stepup}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "sensitive op with stepup: {body}");
    assert_eq!(body["status"], "updated");
}

#[tokio::test]
async fn backup_produces_consistent_snapshot() {
    let dir = std::env::temp_dir().join(format!("vault-backup-{}", Uuid::new_v4()));
    std::env::set_var("VAULT_BACKUP_DIR", &dir);
    let state = build_state(Registration::Open).await;

    // A backup of a fresh, migrated database succeeds and is a real SQLite file.
    let path = vault_server::backup::run_backup(&state).await.unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"SQLite format 3\0"));

    std::env::remove_var("VAULT_BACKUP_DIR");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn invite_gated_registration() {
    let app = build_app(Registration::InviteOnly).await;

    // Without an invite, registration is closed.
    let (st, _) = register(&app, "dave", "pw-dave", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Create an invite via the operator endpoint.
    std::env::set_var("VAULT_OPERATOR_TOKEN", "op-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/invite")
        .header("x-operator-token", "op-secret")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let inv: Value = serde_json::from_slice(&bytes).unwrap();
    let code = inv["code"].as_str().unwrap().to_string();

    // With the invite, registration succeeds; reusing it fails.
    let (st, _) = register(&app, "dave", "pw-dave", Some(&code)).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = register(&app, "erin", "pw-erin", Some(&code)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    std::env::remove_var("VAULT_OPERATOR_TOKEN");
}
