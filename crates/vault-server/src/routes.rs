//! Router assembly.

use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers::{account, admin, auth, health, sync, webauthn};
use crate::state::SharedState;

/// Build the application router. Health/readiness live at the root; everything
/// else is under `/api/v1`. If a web root is configured, it is served as an SPA
/// fallback so the self-hosted instance serves its own client.
pub fn router(state: SharedState) -> Router {
    let api = Router::new()
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route(
            "/auth/login/webauthn/finish",
            post(auth::login_webauthn_finish),
        )
        .route("/auth/refresh", post(auth::refresh))
        .route("/account/2fa/totp", post(auth::enroll_totp))
        .route(
            "/account/2fa/webauthn/register/start",
            post(webauthn::register_start),
        )
        .route(
            "/account/2fa/webauthn/register/finish",
            post(webauthn::register_finish),
        )
        .route(
            "/account/2fa/webauthn/stepup/start",
            post(webauthn::stepup_start),
        )
        .route(
            "/account/2fa/webauthn/stepup/finish",
            post(webauthn::stepup_finish),
        )
        .route(
            "/account/crypto",
            get(sync::get_account_crypto).put(sync::update_account_crypto),
        )
        .route("/account/activity", get(account::security_activity))
        .route("/account/devices", get(account::list_devices))
        .route("/sync", get(sync::pull))
        .route("/sync/push", post(sync::push))
        .route("/sync/item/:id", get(sync::get_item))
        .route("/admin/invite", post(admin::create_invite))
        .route("/admin/activity", get(admin::operator_activity))
        .route("/admin/backup", post(admin::trigger_backup));

    let mut app = Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready))
        .nest("/api/v1", api);

    // Serve the bundled web client, if present, as an SPA fallback.
    if let Some(web_root) = state.config.web_root.clone() {
        use tower_http::services::ServeDir;
        app = app.fallback_service(ServeDir::new(web_root));
    }

    app.layer(TraceLayer::new_for_http()).with_state(state)
}
