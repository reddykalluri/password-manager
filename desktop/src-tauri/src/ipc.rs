//! Local IPC server for the native-messaging host (spec: extension unlock
//! delegation). Line-delimited JSON over a per-user Unix socket; the desktop is
//! the source of truth for unlock state and fills.

#[cfg(unix)]
pub fn spawn(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        if let Err(e) = serve(app) {
            eprintln!("ipc server stopped: {e}");
        }
    });
}

#[cfg(not(unix))]
pub fn spawn(_app: tauri::AppHandle) {
    // Windows would use a named pipe; not wired in this build.
}

#[cfg(unix)]
fn socket_path() -> std::path::PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("vault-desktop.sock")
}

#[cfg(unix)]
fn serve(app: tauri::AppHandle) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    // Owner-only access to the socket.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let app = app.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            let req: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => return,
            };
            let resp = handle(&app, &req);
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let _ = writer.write_all(&out);
        });
    }
    Ok(())
}

#[cfg(unix)]
fn handle(app: &tauri::AppHandle, req: &serde_json::Value) -> serde_json::Value {
    use serde_json::json;
    use tauri::Manager;

    use crate::state::{now, VaultState};

    let state = app.state::<VaultState>();
    match req.get("type").and_then(|v| v.as_str()) {
        Some("unlock_state") => json!({ "unlocked": state.is_unlocked() }),
        Some("get_candidates") => {
            let url = req.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let mut guard = state.0.lock();
            let items = match guard.as_mut() {
                Some(session) => session
                    .vault
                    .candidates_for(url)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|id| {
                        let c = session.vault.get(id).ok()?;
                        let username = match &c.data {
                            vault_core::item::ItemData::Login(l) => l.username.clone(),
                            _ => String::new(),
                        };
                        Some(json!({ "id": id.to_string(), "title": c.title, "username": username }))
                    })
                    .collect::<Vec<_>>(),
                None => Vec::new(),
            };
            json!({ "items": items })
        }
        Some("request_fill") => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut guard = state.0.lock();
            let item = guard.as_mut().and_then(|session| {
                let uuid = uuid::Uuid::parse_str(id).ok()?;
                session.vault.touch(now());
                let c = session.vault.get(uuid).ok()?;
                match &c.data {
                    vault_core::item::ItemData::Login(l) => Some(json!({
                        "username": l.username,
                        "password": l.password,
                        "totp": l.totp,
                    })),
                    _ => None,
                }
            });
            match item {
                Some(item) => json!({ "item": item }),
                None => json!({ "error": "not_found" }),
            }
        }
        // Biometric unlock is not implemented in this build; report current state.
        Some("unlock_biometric") => json!({ "unlocked": state.is_unlocked() }),
        _ => json!({ "error": "unknown_request" }),
    }
}
