//! Production [`DesktopBackend`]: a line-delimited JSON request/response over a
//! per-user local socket the desktop app listens on. If the desktop app is not
//! running the extension simply sees a locked vault.

use serde_json::{json, Value};

use crate::handler::DesktopBackend;

/// Default socket path the desktop app serves (must match the desktop side).
pub fn default_socket_path() -> std::path::PathBuf {
    // A per-user location; not world-accessible.
    let base = std::env::var_os("TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("vault-desktop.sock")
}

#[derive(Debug)]
pub struct SocketBackend {
    path: std::path::PathBuf,
}

impl SocketBackend {
    pub fn connect_default() -> Self {
        Self {
            path: default_socket_path(),
        }
    }

    #[cfg(unix)]
    fn call(&self, request: Value) -> Option<Value> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(&self.path).ok()?;
        let line = serde_json::to_string(&request).ok()?;
        stream.write_all(line.as_bytes()).ok()?;
        stream.write_all(b"\n").ok()?;
        stream.flush().ok()?;
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).ok()?;
        serde_json::from_str(&response).ok()
    }

    #[cfg(not(unix))]
    fn call(&self, _request: Value) -> Option<Value> {
        // Windows uses a named pipe; not wired in this build.
        None
    }
}

impl DesktopBackend for SocketBackend {
    fn unlock_state(&mut self) -> bool {
        self.call(json!({ "type": "unlock_state" }))
            .and_then(|v| v["unlocked"].as_bool())
            .unwrap_or(false)
    }

    fn candidates(&mut self, url: &str) -> Vec<Value> {
        self.call(json!({ "type": "get_candidates", "url": url }))
            .and_then(|v| v["items"].as_array().cloned())
            .unwrap_or_default()
    }

    fn fill(&mut self, id: &str) -> Option<Value> {
        let resp = self.call(json!({ "type": "request_fill", "id": id }))?;
        resp.get("item").cloned()
    }

    fn request_biometric_unlock(&mut self) -> bool {
        self.call(json!({ "type": "unlock_biometric" }))
            .and_then(|v| v["unlocked"].as_bool())
            .unwrap_or(false)
    }
}
