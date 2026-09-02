//! Request dispatch. The host proxies extension requests to the desktop app via
//! a [`DesktopBackend`]; the extension never gets secrets unless the desktop
//! vault is unlocked.

use std::io::{Read, Write};

use serde_json::{json, Value};

use crate::protocol::{read_message, write_message};

/// The desktop app the host talks to (a local socket in production; a mock in
/// tests).
pub trait DesktopBackend {
    fn unlock_state(&mut self) -> bool;
    fn candidates(&mut self, url: &str) -> Vec<Value>;
    fn fill(&mut self, id: &str) -> Option<Value>;
    fn request_biometric_unlock(&mut self) -> bool;
}

/// Handle a single request, returning the response to frame back.
pub fn handle(req: &Value, backend: &mut dyn DesktopBackend) -> Value {
    match req.get("type").and_then(|v| v.as_str()) {
        Some("ping") => json!({ "type": "pong" }),
        Some("unlock_state") => json!({ "type": "unlock_state", "unlocked": backend.unlock_state() }),
        Some("get_candidates") => {
            let url = req.get("url").and_then(|v| v.as_str()).unwrap_or("");
            json!({ "type": "candidates", "items": backend.candidates(url) })
        }
        Some("request_fill") => {
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            match backend.fill(id) {
                Some(item) => json!({ "type": "fill", "item": item }),
                None => json!({ "type": "error", "error": "not_found" }),
            }
        }
        Some("unlock_biometric") => {
            json!({ "type": "unlock_biometric", "unlocked": backend.request_biometric_unlock() })
        }
        _ => json!({ "type": "error", "error": "unknown_request" }),
    }
}

/// Serve framed requests until the browser closes the port.
pub fn serve<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    backend: &mut dyn DesktopBackend,
) -> std::io::Result<()> {
    while let Some(req) = read_message(&mut reader)? {
        let resp = handle(&req, backend);
        write_message(&mut writer, &resp)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::write_message;

    #[derive(Default)]
    struct Mock {
        unlocked: bool,
    }
    impl DesktopBackend for Mock {
        fn unlock_state(&mut self) -> bool {
            self.unlocked
        }
        fn candidates(&mut self, url: &str) -> Vec<Value> {
            if self.unlocked && url.contains("example.com") {
                vec![json!({ "id": "1", "title": "Example" })]
            } else {
                vec![]
            }
        }
        fn fill(&mut self, id: &str) -> Option<Value> {
            (self.unlocked && id == "1")
                .then(|| json!({ "username": "u", "password": "p" }))
        }
        fn request_biometric_unlock(&mut self) -> bool {
            self.unlocked = true;
            true
        }
    }

    #[test]
    fn locked_backend_yields_no_secrets() {
        let mut b = Mock::default();
        let resp = handle(&json!({ "type": "request_fill", "id": "1" }), &mut b);
        assert_eq!(resp["error"], "not_found");
        let resp = handle(&json!({ "type": "unlock_state" }), &mut b);
        assert_eq!(resp["unlocked"], false);
    }

    #[test]
    fn unlocked_backend_serves_candidates_and_fill() {
        let mut b = Mock { unlocked: true };
        let resp = handle(
            &json!({ "type": "get_candidates", "url": "https://example.com/login" }),
            &mut b,
        );
        assert_eq!(resp["items"].as_array().unwrap().len(), 1);
        let resp = handle(&json!({ "type": "request_fill", "id": "1" }), &mut b);
        assert_eq!(resp["item"]["password"], "p");
    }

    #[test]
    fn serve_processes_a_stream_of_framed_requests() {
        let mut input: Vec<u8> = Vec::new();
        write_message(&mut input, &json!({ "type": "ping" })).unwrap();
        write_message(&mut input, &json!({ "type": "unlock_state" })).unwrap();

        let mut output: Vec<u8> = Vec::new();
        let mut b = Mock::default();
        serve(std::io::Cursor::new(input), &mut output, &mut b).unwrap();

        let mut cursor = std::io::Cursor::new(output);
        let first = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(first["type"], "pong");
        let second = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(second["type"], "unlock_state");
    }
}
