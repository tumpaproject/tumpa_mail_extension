#!/usr/bin/env bash
# render-icons.sh — render TumpaMail/AppIcon.svg into all the macOS
# AppIcon.appiconset PNG sizes Xcode's actool expects.
#
# Usage:
#     render-icons.sh
#
# Requires `rsvg-convert` (preferred) or ImageMagick `magick`/`convert`.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SVG="$ROOT/TumpaMail/AppIcon.svg"
ICONSET="$ROOT/Shared/Assets.xcassets/AppIcon.appiconset"

[ -f "$SVG" ] || { echo "error: $SVG not found" >&2; exit 1; }
mkdir -p "$ICONSET"

# Pick a renderer.
if command -v rsvg-convert >/dev/null 2>&1; then
    render() { rsvg-convert -w "$1" -h "$1" "$SVG" -o "$2"; }
elif command -v magick >/dev/null 2>&1; then
    render() { magick -background none "$SVG" -resize "${1}x${1}" "PNG32:$2"; }
elif command -v convert >/dev/null 2>&1; then
    render() { convert -background none "$SVG" -resize "${1}x${1}" "PNG32:$2"; }
else
    echo "error: need 'rsvg-convert' (brew install librsvg) or ImageMagick" >&2
    exit 1
fi

# (filename, pixel size)
specs=(
    "icon_16x16.png:16"
    "icon_16x16@2x.png:32"
    "icon_32x32.png:32"
    "icon_32x32@2x.png:64"
    "icon_128x128.png:128"
    "icon_128x128@2x.png:256"
    "icon_256x256.png:256"
    "icon_256x256@2x.png:512"
    "icon_512x512.png:512"
    "icon_512x512@2x.png:1024"
)

for spec in "${specs[@]}"; do
    name="${spec%:*}"
    size="${spec#*:}"
    render "$size" "$ICONSET/$name"
    echo "  rendered $name (${size}x${size})"
done

echo "done — wrote 10 PNGs into $ICONSET"
