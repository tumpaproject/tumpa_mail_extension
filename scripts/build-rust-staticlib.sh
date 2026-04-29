#!/usr/bin/env bash
# build-rust-staticlib.sh — produce a universal (aarch64 + x86_64)
# libtumpa_uniffi.a for linking into the macOS XPC service.
#
# Output: openpgp/tumpa-uniffi/target/universal-apple-darwin/release/libtumpa_uniffi.a
#
# Invoked by `just rust`. The Xcode project's TumpaCryptoXPC target
# adds the universal directory to LIBRARY_SEARCH_PATHS and links
# `-ltumpa_uniffi`.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MAIL_DIR="$(cd "$HERE/.." && pwd)"
CRATE_DIR="$(cd "$MAIL_DIR/../tumpa-uniffi" && pwd)"

cd "$CRATE_DIR"

# Cross-compile for both Apple architectures. Both targets must be
# installed via `rustup target add aarch64-apple-darwin x86_64-apple-darwin`.
for triple in aarch64-apple-darwin x86_64-apple-darwin; do
    if ! rustup target list --installed | grep -q "^${triple}$"; then
        echo "error: rust target ${triple} not installed."
        echo "  run: rustup target add ${triple}"
        exit 1
    fi
done

echo "==> cargo build --release --target aarch64-apple-darwin"
cargo build --release --target aarch64-apple-darwin

echo "==> cargo build --release --target x86_64-apple-darwin"
cargo build --release --target x86_64-apple-darwin

UNIVERSAL_DIR="$CRATE_DIR/target/universal-apple-darwin/release"
mkdir -p "$UNIVERSAL_DIR"

echo "==> lipo -create -> $UNIVERSAL_DIR/libtumpa_uniffi.a"
lipo -create \
    "$CRATE_DIR/target/aarch64-apple-darwin/release/libtumpa_uniffi.a" \
    "$CRATE_DIR/target/x86_64-apple-darwin/release/libtumpa_uniffi.a" \
    -output "$UNIVERSAL_DIR/libtumpa_uniffi.a"

# Print final size + arches as a sanity check.
echo
echo "Universal lib produced:"
ls -lh "$UNIVERSAL_DIR/libtumpa_uniffi.a"
lipo -info "$UNIVERSAL_DIR/libtumpa_uniffi.a"
