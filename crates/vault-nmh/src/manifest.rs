//! Native-messaging host manifest generation and per-browser install paths.

use serde_json::{json, Value};

/// The host name browsers use to launch this binary.
pub const HOST_NAME: &str = "au.com.rodoskosmos.vault";

/// Chromium (Chrome/Edge) manifest: gated by `allowed_origins`.
pub fn chromium_manifest(exe_path: &str) -> Value {
    let origins: Vec<String> = super::allowlist::ALLOWED_CHROMIUM_IDS
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    json!({
        "name": HOST_NAME,
        "description": "Vault native messaging host",
        "path": exe_path,
        "type": "stdio",
        "allowed_origins": origins
    })
}

/// Firefox manifest: gated by `allowed_extensions`.
pub fn firefox_manifest(exe_path: &str) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Vault native messaging host",
        "path": exe_path,
        "type": "stdio",
        "allowed_extensions": super::allowlist::ALLOWED_FIREFOX_IDS
    })
}

/// Directory a browser reads user-scoped host manifests from (macOS paths).
#[cfg(target_os = "macos")]
pub fn install_dir(browser: Browser) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let base = std::path::Path::new(&home).join("Library/Application Support");
    Some(match browser {
        Browser::Chrome => base.join("Google/Chrome/NativeMessagingHosts"),
        Browser::Edge => base.join("Microsoft Edge/NativeMessagingHosts"),
        Browser::Firefox => base.join("Mozilla/NativeMessagingHosts"),
    })
}

#[cfg(target_os = "linux")]
pub fn install_dir(browser: Browser) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let cfg = std::path::Path::new(&home).join(".config");
    Some(match browser {
        Browser::Chrome => cfg.join("google-chrome/NativeMessagingHosts"),
        Browser::Edge => cfg.join("microsoft-edge/NativeMessagingHosts"),
        Browser::Firefox => std::path::Path::new(&home)
            .join(".mozilla/native-messaging-hosts"),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn install_dir(_browser: Browser) -> Option<std::path::PathBuf> {
    // Windows registers via the registry, not a directory; handled elsewhere.
    None
}

#[derive(Debug, Clone, Copy)]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
}

/// Write host manifests for every supported browser found on this machine.
pub fn install_all(exe_path: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut written = Vec::new();
    for browser in [Browser::Chrome, Browser::Edge, Browser::Firefox] {
        let Some(dir) = install_dir(browser) else {
            continue;
        };
        std::fs::create_dir_all(&dir)?;
        let manifest = match browser {
            Browser::Firefox => firefox_manifest(exe_path),
            _ => chromium_manifest(exe_path),
        };
        let path = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_manifest_has_stdio_and_origins() {
        let m = chromium_manifest("/opt/vault/host");
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["path"], "/opt/vault/host");
        assert!(m["allowed_origins"][0]
            .as_str()
            .unwrap()
            .starts_with("chrome-extension://"));
    }

    #[test]
    fn firefox_manifest_lists_allowed_extensions() {
        let m = firefox_manifest("/opt/vault/host");
        assert!(m["allowed_extensions"].is_array());
    }
}
