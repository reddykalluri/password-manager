# Mobile clients

The Android (Kotlin/Compose) and iOS (Swift/SwiftUI) apps sit on top of
**`vault-core` via UniFFI** — the same audited Rust crypto/vault logic as every
other surface, exposed to Kotlin and Swift.

## UniFFI bindings (implemented)

`crates/vault-mobile` wraps vault-core with a UniFFI interface: stateless
functions (KDF benchmark, generator, strength, OPAQUE client) and an opaque
`VaultHandle` object (enrol/unlock, item CRUD, search, history, import/export)
— the same JSON-string facade as the WASM and Tauri layers, so all clients share
one implementation.

Generate the bindings and run the Swift binding test against the real library:

```bash
./scripts/swift-binding-test.sh          # macOS + swiftc
```

Generate for either language directly:

```bash
cargo build -p vault-mobile
cargo run -p vault-mobile --bin uniffi-bindgen -- \
  generate --library target/debug/libvault_mobile.dylib \
  --language swift --out-dir crates/vault-mobile/bindings/swift
cargo run -p vault-mobile --bin uniffi-bindgen -- \
  generate --library target/debug/libvault_mobile.dylib \
  --language kotlin --out-dir crates/vault-mobile/bindings/kotlin
```

For device/app builds, cross-compile the library to the mobile targets
(`aarch64-apple-ios`, `aarch64-linux-android`, plus simulator/emulator targets)
and bundle it with the generated bindings. CI cross-builds vault-core for these
targets; the app targets need the platform SDKs (Xcode, Android SDK/NDK).

## Apps (not yet built here)

The Compose and SwiftUI apps, biometric unlock (BiometricPrompt / Face ID via
Keystore/Secure Enclave), offline cache + sync status, live TOTP, and app-level
privacy (FLAG_SECURE, switcher masking, backup exclusion) are specified but not
implemented in this environment: building and testing them needs the Android
SDK/NDK and Xcode, and store/TestFlight distribution needs developer accounts.
The UniFFI layer above is the foundation they build on.
