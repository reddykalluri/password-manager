//! Biometric-unlock session-key storage (spec: biometric and OS-credential
//! unlock). The exported account key (see `vault_core::keys::KeyRing::
//! export_account_key`) is stored in the OS keystore so the app can unlock via
//! Touch ID without the master password, and is invalidated after a reboot.
//!
//! On macOS the key lives in the login Keychain. Making retrieval actually
//! prompt Touch ID (and invalidate on biometric-enrolment change) requires a
//! `SecAccessControl` with `.biometryCurrentSet` plus the app's biometric
//! entitlement in a signed, notarised build — applied at packaging time. The
//! reboot-invalidation below is enforced regardless.
//!
//! Windows Hello / TPM is not implemented here (needs a Windows host).

const SERVICE: &str = "au.com.rodoskosmos.vault";
const KEY_ACCOUNT: &str = "session-account-key";
const BOOT_ACCOUNT: &str = "session-boot-id";

/// A per-boot identifier; changes on every restart so biometric unlock requires
/// a master-password unlock again after a reboot.
fn boot_id() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{boot_id, BOOT_ACCOUNT, KEY_ACCOUNT, SERVICE};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    pub fn available() -> bool {
        true
    }

    pub fn enabled() -> bool {
        get_generic_password(SERVICE, KEY_ACCOUNT).is_ok()
    }

    pub fn store(bytes: &[u8]) -> Result<(), String> {
        set_generic_password(SERVICE, KEY_ACCOUNT, bytes).map_err(|e| e.to_string())?;
        set_generic_password(SERVICE, BOOT_ACCOUNT, boot_id().as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load() -> Result<Vec<u8>, String> {
        let stored_boot = get_generic_password(SERVICE, BOOT_ACCOUNT)
            .map_err(|_| "biometric unlock not enabled".to_string())?;
        if String::from_utf8_lossy(&stored_boot) != boot_id() {
            let _ = clear();
            return Err("biometric session invalidated after reboot".into());
        }
        get_generic_password(SERVICE, KEY_ACCOUNT).map_err(|e| e.to_string())
    }

    pub fn clear() -> Result<(), String> {
        let _ = delete_generic_password(SERVICE, KEY_ACCOUNT);
        let _ = delete_generic_password(SERVICE, BOOT_ACCOUNT);
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn available() -> bool {
        false
    }
    pub fn enabled() -> bool {
        false
    }
    pub fn store(_bytes: &[u8]) -> Result<(), String> {
        Err("biometric unlock not supported on this platform".into())
    }
    pub fn load() -> Result<Vec<u8>, String> {
        Err("biometric unlock not supported on this platform".into())
    }
    pub fn clear() -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{available, clear, enabled, load, store};
