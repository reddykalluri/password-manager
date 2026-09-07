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

## Apps

The Android (`mobile/android`) and iOS (`mobile/ios`) apps are implemented on top
of the UniFFI bindings:

- **Android** (Kotlin/Compose) — adaptive list/detail (`NavigableListDetailPane`),
  biometric unlock (`BiometricPrompt` + Android Keystore-wrapped session key,
  invalidated on new enrolment / reboot), encrypted offline cache
  (`EncryptedFile`) + sync status, `AutofillService` with save capture and
  **Digital Asset Links** verification, a Credential Manager passkey provider
  (skeleton), and app privacy (`FLAG_SECURE`, backup exclusion).
- **iOS** (Swift/SwiftUI) — adaptive `NavigationSplitView`, Face ID unlock
  (`LocalAuthentication` + Secure-Enclave-gated Keychain), offline cache with
  complete file protection + backup exclusion, an AutoFill **Credential Provider**
  extension (skeleton), and app-switcher masking.

### Building the apps

They are **not built in this repo** — that needs Android Studio / Xcode and the
device-target native library, neither of which is available in the CI/dev sandbox
here. To build:

```bash
# 1. Generate the UniFFI bindings into the app trees.
./scripts/mobile-bindings.sh

# 2a. Android: cross-compile the native lib into jniLibs, then open in Studio.
cargo install cargo-ndk
cargo ndk -t arm64-v8a -o mobile/android/app/src/main/jniLibs build -p vault-mobile --release
#    open mobile/android in Android Studio and Run.

# 2b. iOS: build a static lib for the device/simulator, then generate the project.
cargo build -p vault-mobile --release --target aarch64-apple-ios
cp target/aarch64-apple-ios/release/libvault_mobile.a mobile/ios/VaultCore/
brew install xcodegen && (cd mobile/ios && xcodegen && open Vault.xcodeproj)
```

Passkey provider ceremonies (Android Credential Manager, iOS Credential Provider)
are integration **skeletons** wired to the vault; completing the FIDO2 flows is
done with on-device testing. Store/TestFlight distribution (6.7) needs developer
accounts and is out of scope here.

### Verification boundary

Only the UniFFI layer is verified in this repo (the Swift binding test). The apps
compile and run in Android Studio / Xcode with the native library present; they
are not built or tested in this environment.
