#!/usr/bin/env bash
# Generate the UniFFI bindings into the mobile app source trees:
#   Kotlin → mobile/android/app/src/main/java/uniffi/
#   Swift  → mobile/ios/VaultCore/
# The developer also cross-compiles the native library for the device targets
# (see docs/mobile.md) and places it in jniLibs (Android) / VaultCore (iOS).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p vault-mobile
LIB="target/debug/libvault_mobile.dylib"

cargo run -q -p vault-mobile --bin uniffi-bindgen -- \
  generate --library "$LIB" --language kotlin \
  --out-dir mobile/android/app/src/main/java

cargo run -q -p vault-mobile --bin uniffi-bindgen -- \
  generate --library "$LIB" --language swift \
  --out-dir mobile/ios/VaultCore

echo "generated Kotlin + Swift bindings into the mobile app trees"
