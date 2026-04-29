#!/usr/bin/env bash
# regen-uniffi-bindings.sh — regenerate the Swift binding files
# (tumpa.swift, tumpaFFI.h, tumpaFFI.modulemap) from the Rust crate.
#
# Output dir: tumpa_mail_extension/TumpaCryptoXPC/Generated/
#
# These files are committed to the repo so a fresh checkout doesn't
# need uniffi-bindgen installed locally — only run this script when
# the Rust API surface changes (sig changes / new exports / etc.).
#
# Invoked by `just bindings`.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MAIL_DIR="$(cd "$HERE/.." && pwd)"
CRATE_DIR="$(cd "$MAIL_DIR/../tumpa-uniffi" && pwd)"
OUT_DIR="$MAIL_DIR/TumpaCryptoXPC/Generated"

cd "$CRATE_DIR"

# Build the cdylib first — uniffi-bindgen reads exported symbols
# from the dynamic library to discover the FFI surface. We use the
# host arch's release build because it's small/fast; the Swift output
# is arch-independent.
echo "==> cargo build --release (cdylib for bindgen introspection)"
cargo build --release

DYLIB="$CRATE_DIR/target/release/libtumpa_uniffi.dylib"
[ -f "$DYLIB" ] || { echo "error: $DYLIB not found"; exit 1; }

mkdir -p "$OUT_DIR"

echo "==> cargo run --release --bin uniffi-bindgen -- generate --library $DYLIB --language swift"
cargo run --release --bin uniffi-bindgen -- \
    generate \
    --library "$DYLIB" \
    --language swift \
    --out-dir "$OUT_DIR"

echo
echo "Generated:"
ls -l "$OUT_DIR"

echo
echo "Reminder: commit the regenerated files so fresh checkouts pick them up."
