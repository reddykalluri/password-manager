//! Biometric-unlock session-key storage (spec: biometric and OS-credential
//! unlock). The exported account key (`vault_core::keys::KeyRing::
//! export_account_key`) is protected by the OS so the app can unlock without the
//! master password, and is invalidated after a reboot.
//!
//! - macOS: the key lives in the login Keychain. Making retrieval actually
//!   prompt Touch ID (and invalidate on enrolment change) needs a
//!   `SecAccessControl` biometry flag + the app's biometric entitlement in a
//!   signed, notarised build.
//! - Windows: Windows Hello via `KeyCredentialManager` (TPM-backed). The account
//!   key is sealed under a key derived from a deterministic Hello signature, so
//!   unwrapping requires a Hello prompt. This path is compile-checked for the
//!   `x86_64-pc-windows-gnu` target but not run here (needs a Windows host and a
//!   signed build for the Hello prompt).

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
    #[cfg(target_os = "windows")]
    {
        // Approximate boot epoch (seconds): stable within a boot, changes across
        // reboots.
        let uptime_ms = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        (now_ms.saturating_sub(uptime_ms) / 1000).to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
        set_generic_password(SERVICE, BOOT_ACCOUNT, boot_id().as_bytes()).map_err(|e| e.to_string())?;
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

#[cfg(target_os = "windows")]
mod imp {
    use super::boot_id;
    use sha2::{Digest, Sha256};
    use vault_core::crypto::{open, seal, Key256, SealedBlob};
    use windows::core::{Array, HSTRING};
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Storage::Streams::IBuffer;

    const CRED_NAME: &str = "au.com.rodoskosmos.vault.session";
    const CHALLENGE: &[u8] = b"vault-hello-challenge-v1";
    const AAD: &[u8] = b"vault-core:v1:winhello";

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Stored {
        blob: SealedBlob,
        boot: String,
    }

    fn file() -> std::path::PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join("Vault").join("session.json")
    }

    pub fn available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.get())
            .unwrap_or(false)
    }

    pub fn enabled() -> bool {
        file().exists()
    }

    /// Derive a stable AES key from a Hello-gated deterministic signature.
    fn hello_key(create: bool) -> Result<Key256, String> {
        let name = HSTRING::from(CRED_NAME);
        let result = if create {
            KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::ReplaceExisting)
        } else {
            KeyCredentialManager::OpenAsync(&name)
        }
        .and_then(|op| op.get())
        .map_err(|e| e.to_string())?;

        if result.Status().map_err(|e| e.to_string())? != KeyCredentialStatus::Success {
            return Err("Windows Hello not available or cancelled".into());
        }
        let credential = result.Credential().map_err(|e| e.to_string())?;
        let challenge = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(|e| e.to_string())?;
        let sign = credential
            .RequestSignAsync(&challenge)
            .and_then(|op| op.get())
            .map_err(|e| e.to_string())?;
        if sign.Status().map_err(|e| e.to_string())? != KeyCredentialStatus::Success {
            return Err("Hello signature failed".into());
        }
        let signature = buffer_to_vec(&sign.Result().map_err(|e| e.to_string())?)?;
        let digest = Sha256::digest(&signature);
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        Ok(Key256::new(key))
    }

    pub fn store(bytes: &[u8]) -> Result<(), String> {
        let key = hello_key(true)?;
        let blob = seal(&key, bytes, AAD).map_err(|e| e.to_string())?;
        let stored = Stored { blob, boot: boot_id() };
        let path = file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, serde_json::to_vec(&stored).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    pub fn load() -> Result<Vec<u8>, String> {
        let data = std::fs::read(file()).map_err(|_| "biometric unlock not enabled".to_string())?;
        let stored: Stored = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
        if stored.boot != boot_id() {
            let _ = clear();
            return Err("biometric session invalidated after reboot".into());
        }
        let key = hello_key(false)?;
        open(&key, &stored.blob, AAD).map_err(|e| e.to_string())
    }

    pub fn clear() -> Result<(), String> {
        let _ = std::fs::remove_file(file());
        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(CRED_NAME)).and_then(|op| op.get());
        Ok(())
    }

    fn buffer_to_vec(buffer: &IBuffer) -> Result<Vec<u8>, String> {
        let mut array = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(buffer, &mut array).map_err(|e| e.to_string())?;
        Ok(array.as_slice().to_vec())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
