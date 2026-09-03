//! Desktop app entry: native vault-core commands, tray, and global shortcut.

mod biometric;
mod commands;
mod hygiene;
mod ipc;
mod opaque;
mod state;
mod tray;

use state::VaultState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    hygiene::harden_process();

    tauri::Builder::default()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(VaultState::default())
        .setup(|app| {
            tray::setup_tray(app)?;
            tray::register_quick_shortcut(app)?;
            ipc::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::kdf_benchmark,
            commands::default_kdf_params,
            commands::gen_password,
            commands::gen_passphrase,
            commands::strength,
            commands::opaque_register_start,
            commands::opaque_register_finish,
            commands::opaque_login_start,
            commands::opaque_login_finish,
            commands::vault_enroll,
            commands::vault_unlock,
            commands::vault_unlock_recovery,
            commands::vault_lock,
            commands::vault_unlocked,
            commands::account_crypto,
            commands::take_recovery_code,
            commands::records,
            commands::apply_record,
            commands::create_item,
            commands::get_item,
            commands::update_item,
            commands::move_to_bin,
            commands::restore_from_bin,
            commands::delete_permanent,
            commands::list_active,
            commands::list_bin,
            commands::search,
            commands::candidates_for,
            commands::folders,
            commands::tags,
            commands::history,
            commands::restore_revision,
            commands::change_master_password,
            commands::regenerate_recovery_code,
            commands::import_preview,
            commands::import_commit,
            commands::export_encrypted,
            commands::export_csv_gated,
            commands::set_lock_timeout_secs,
            commands::touch,
            commands::should_lock,
            commands::biometric_available,
            commands::biometric_enabled,
            commands::biometric_enable,
            commands::biometric_disable,
            commands::biometric_unlock,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
