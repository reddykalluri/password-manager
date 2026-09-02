//! Native-messaging host binary.
//!
//! Launched by a browser (which passes the calling extension identity as the
//! first CLI argument), or run as `… install` to register host manifests.

mod allowlist;
mod handler;
mod manifest;
mod protocol;
mod socket;

use std::io;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // `install` writes the per-browser host manifests pointing at this binary.
    if args.get(1).map(String::as_str) == Some("install") {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_default();
        match manifest::install_all(&exe) {
            Ok(paths) => {
                for p in paths {
                    eprintln!("installed {}", p.display());
                }
            }
            Err(e) => {
                eprintln!("install failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Otherwise the browser launched us: verify the caller before serving.
    let caller = args.get(1).cloned().unwrap_or_default();
    if !allowlist::is_allowed(&caller) {
        eprintln!("caller not allowlisted: {caller}");
        std::process::exit(1);
    }

    let mut backend = socket::SocketBackend::connect_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    if let Err(e) = handler::serve(stdin.lock(), stdout.lock(), &mut backend) {
        eprintln!("host error: {e}");
        std::process::exit(1);
    }
}
