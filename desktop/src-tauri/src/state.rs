//! Managed vault session state. The unlocked vault lives natively in Rust; the
//! webview UI drives it through Tauri commands.

use parking_lot::Mutex;
use time::OffsetDateTime;

use vault_core::keys::AccountCrypto;
use vault_core::store::Vault;

/// An unlocked session: the native vault plus the account crypto material.
pub struct Session {
    pub vault: Vault,
    pub crypto: AccountCrypto,
    pub recovery: Option<String>,
}

/// Tauri-managed state; `None` while locked.
#[derive(Default)]
pub struct VaultState(pub Mutex<Option<Session>>);

impl VaultState {
    pub fn is_unlocked(&self) -> bool {
        self.0.lock().is_some()
    }

    pub fn lock_now(&self) {
        // Dropping the Session drops the Vault → keyring zeroised.
        *self.0.lock() = None;
    }
}

/// Current wall-clock time (the core is otherwise clock-free).
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
