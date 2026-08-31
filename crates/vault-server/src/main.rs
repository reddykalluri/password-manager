//! vault-server binary entry point.

#[tokio::main]
async fn main() {
    if let Err(e) = vault_server::run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
