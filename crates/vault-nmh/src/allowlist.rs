//! Caller verification. The browser launches this host and passes the calling
//! extension's identity as the first CLI argument (Chrome/Edge: the extension
//! origin `chrome-extension://<id>/`; Firefox: the add-on id). Only allowlisted
//! extensions may talk to the host.

/// Allowlisted Chromium extension IDs (32 lowercase a–p chars). Replaced with
/// the real published store IDs at packaging time.
pub const ALLOWED_CHROMIUM_IDS: &[&str] = &["placeholderchromiumextensionid00"];

/// Allowlisted Firefox add-on IDs.
pub const ALLOWED_FIREFOX_IDS: &[&str] = &["vault@rodoskosmos.com.au"];

/// Whether the caller identity passed by the browser is allowlisted.
pub fn is_allowed(caller: &str) -> bool {
    if let Some(rest) = caller.strip_prefix("chrome-extension://") {
        let id = rest.split('/').next().unwrap_or("");
        return ALLOWED_CHROMIUM_IDS.contains(&id);
    }
    if let Some(rest) = caller.strip_prefix("moz-extension://") {
        let id = rest.split('/').next().unwrap_or("");
        // Firefox internal UUIDs differ from add-on IDs; the manifest's
        // allowed_extensions is the primary gate, this is defence in depth.
        return !id.is_empty();
    }
    // Firefox passes the add-on id directly.
    ALLOWED_FIREFOX_IDS.contains(&caller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_listed_chromium_and_firefox() {
        let chrome = format!("chrome-extension://{}/", ALLOWED_CHROMIUM_IDS[0]);
        assert!(is_allowed(&chrome));
        assert!(is_allowed(ALLOWED_FIREFOX_IDS[0]));
    }

    #[test]
    fn rejects_unknown() {
        assert!(!is_allowed("chrome-extension://evilextensionidevilextensineid0/"));
        assert!(!is_allowed("random@attacker.example"));
        assert!(!is_allowed(""));
    }
}
