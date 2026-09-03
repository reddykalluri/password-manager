#!/usr/bin/env bash
# Build vault-mobile, generate Swift UniFFI bindings, and run the Swift binding
# test against the real native library (mobile-clients spec 6.1). Requires
# swiftc (macOS). Kotlin bindings are generated the same way but need a JVM +
# ktlint/JNA to test, so they are not exercised here.
set -euo pipefail
cd "$(dirname "$0")/.."

LIB_DIR="target/debug"
LIB="$LIB_DIR/libvault_mobile.dylib"
OUT="crates/vault-mobile/bindings/swift"

echo "==> building vault-mobile"
cargo build -p vault-mobile

echo "==> generating Swift bindings"
cargo run -q -p vault-mobile --bin uniffi-bindgen -- \
  generate --library "$LIB" --language swift --out-dir "$OUT"

echo "==> compiling Swift binding test"
swiftc \
  -I "$OUT" \
  -L "$LIB_DIR" -lvault_mobile \
  -Xcc -fmodule-map-file="$OUT/vault_mobileFFI.modulemap" \
  "$OUT/vault_mobile.swift" \
  crates/vault-mobile/tests/swift/main.swift \
  -o /tmp/vault_swift_test

echo "==> running"
DYLD_LIBRARY_PATH="$LIB_DIR" /tmp/vault_swift_test
