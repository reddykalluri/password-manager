//! Process hardening: keep secret-bearing memory out of swap, and keep secrets
//! out of crash reports (spec: local data protection).

/// Apply best-effort hardening at startup.
pub fn harden_process() {
    lock_memory();
    install_scrubbing_panic_hook();
}

/// Ask the OS to keep resident pages out of swap. Best-effort: on a hardened
/// machine this may be denied without elevated limits, which is fine — vault
/// keys are still zeroised on lock.
#[cfg(unix)]
fn lock_memory() {
    // SAFETY: mlockall has no memory-safety implications; we ignore failure.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc != 0 {
        eprintln!("note: mlockall unavailable; secret pages may be swappable");
    }
}

#[cfg(not(unix))]
fn lock_memory() {
    // Windows uses SetProcessWorkingSetSize / VirtualLock on specific buffers;
    // handled per-allocation by the OS keystore path there.
}

/// Replace the default panic hook so panic payloads (which could reference
/// secret-adjacent data) never reach stderr, logs, or OS crash reporters.
fn install_scrubbing_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".into());
        // Deliberately omit the panic message/payload.
        eprintln!("panic at {location} (details suppressed to avoid leaking secrets)");
    }));
}
