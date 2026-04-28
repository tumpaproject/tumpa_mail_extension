#!/usr/bin/env bash
# make-dmg.sh — build a DMG from a staging directory.
#
# Usage:
#     make-dmg.sh <stage_dir> <dmg_path> <volume_name> <app_basename>
#
# stage_dir     directory containing the .app to ship (and only that)
# dmg_path      output .dmg path
# volume_name   what Finder shows as the mounted volume name
# app_basename  basename of the .app inside stage_dir (e.g. "Tumpa Mail.app")
#
# Uses `create-dmg` for the nicer drag-to-Applications layout when
# available; falls back to plain `hdiutil create` otherwise. Both paths
# produce a UDZO-compressed read-only DMG.

set -euo pipefail

if [ $# -ne 4 ]; then
    echo "usage: $0 <stage_dir> <dmg_path> <volume_name> <app_basename>" >&2
    exit 2
fi

STAGE="$1"
DMG="$2"
VOLNAME="$3"
APP_BASENAME="$4"

if [ ! -d "$STAGE/$APP_BASENAME" ]; then
    echo "error: $STAGE/$APP_BASENAME not found" >&2
    exit 1
fi

if command -v create-dmg >/dev/null 2>&1; then
    create-dmg \
        --volname "$VOLNAME" \
        --window-pos 200 120 \
        --window-size 600 380 \
        --icon-size 110 \
        --icon "$APP_BASENAME" 160 190 \
        --hide-extension "$APP_BASENAME" \
        --app-drop-link 440 190 \
        --no-internet-enable \
        "$DMG" \
        "$STAGE"
else
    echo "(create-dmg not found — falling back to hdiutil; install via 'brew install create-dmg' for a polished DMG layout)"
    hdiutil create \
        -volname "$VOLNAME" \
        -srcfolder "$STAGE" \
        -ov \
        -format UDZO \
        "$DMG"
fi
