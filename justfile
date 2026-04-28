# Tumpa Mail — build / DMG packaging recipes.
#
# Common targets:
#   just generate          — regenerate TumpaMail.xcodeproj from project.yml
#   just build             — xcodebuild Release of TumpaMail.app
#   just test              — run TumpaMailTests
#   just build-dmg         — UNSIGNED DMG (local smoke tests / dev installs)
#   just build-dmg-signed  — Developer-ID-signed + notarized + stapled DMG
#   just clean             — wipe build/, dist/, and the generated .xcodeproj

set shell := ["bash", "-euo", "pipefail", "-c"]

project_dir     := justfile_directory()
build_dir       := project_dir / "build"
dmg_out_dir     := project_dir / "dist"
xcodeproj       := project_dir / "TumpaMail.xcodeproj"
make_dmg        := project_dir / "scripts" / "make-dmg.sh"

scheme          := "TumpaMail"
product_name    := "TumpaMail"
display_name    := "Tumpa Mail"
configuration   := "Release"
team_id         := "A7WGUTKMK6"
# Override with NOTARY_PROFILE=... if you stored credentials under a different name.
notary_profile  := env_var_or_default("NOTARY_PROFILE", "tugpgp")
# Override with APPLE_SIGNING_IDENTITY=... to force a specific Developer ID cert.
# Default matches the team-id-based identity Xcode picks via Automatic signing.
signing_identity := env_var_or_default("APPLE_SIGNING_IDENTITY", "Developer ID Application: Kushal Das (" + team_id + ")")
dmg_volume_name := display_name
dmg_basename    := "TumpaMail"

default:
    @just --list --unsorted

# Regenerate the AppIcon PNG set from TumpaMail/AppIcon.svg.
# Run this whenever the SVG changes; the rendered PNGs are committed
# so a fresh checkout can build without rsvg/imagemagick installed.
icons:
    "{{project_dir}}/scripts/render-icons.sh"

# Regenerate TumpaMail.xcodeproj from project.yml.
generate:
    @command -v xcodegen >/dev/null || { echo "error: xcodegen not installed (brew install xcodegen)"; exit 1; }
    cd "{{project_dir}}" && xcodegen generate

# Release build of the host app + XPC service + .appex.
build: generate
    rm -rf "{{build_dir}}"
    xcodebuild \
      -project "{{xcodeproj}}" \
      -scheme {{scheme}} \
      -configuration {{configuration}} \
      -derivedDataPath "{{build_dir}}" \
      build

# Run the PGPMimeBuilder / PGPMimeParser unit tests.
test: generate
    xcodebuild \
      -project "{{xcodeproj}}" \
      -scheme TumpaMailTests \
      -destination 'platform=macOS' \
      test

clean:
    rm -rf "{{build_dir}}" "{{dmg_out_dir}}" "{{xcodeproj}}"

# ============================================================
# DMG packaging
# ============================================================

# Unsigned DMG built from the standard Release build. Good for local
# smoke installs on this machine; Gatekeeper will reject it elsewhere
# (use `just build-dmg-signed` for anything you hand to another user).
build-dmg: build
    #!/usr/bin/env bash
    set -euo pipefail
    APP_SRC="{{build_dir}}/Build/Products/{{configuration}}/{{product_name}}.app"
    [ -d "$APP_SRC" ] || { echo "error: $APP_SRC not found — did 'just build' succeed?"; exit 1; }

    STAGE="{{build_dir}}/dmg-stage"
    rm -rf "$STAGE" && mkdir -p "$STAGE"
    # Rename inside the DMG so Finder shows "Tumpa Mail.app"
    # rather than the Xcode product name.
    ditto "$APP_SRC" "$STAGE/{{display_name}}.app"

    mkdir -p "{{dmg_out_dir}}"
    DMG_PATH="{{dmg_out_dir}}/{{dmg_basename}}-unsigned.dmg"
    rm -f "$DMG_PATH"
    "{{make_dmg}}" "$STAGE" "$DMG_PATH" "{{dmg_volume_name}}" "{{display_name}}.app"

    echo
    echo "DMG: $DMG_PATH"
    echo "  (unsigned — Gatekeeper will block this on other machines)"

# Developer-ID-signed, notarized, stapled DMG — distribution-ready.
#
# One-time prerequisites:
#   1. Developer ID Application certificate for team {{team_id}} in the
#      login keychain (Xcode → Settings → Accounts → Manage Certificates,
#      or download from developer.apple.com).
#   2. A notarytool keychain profile so we don't have to pass an
#      app-specific password every run:
#        xcrun notarytool store-credentials {{notary_profile}} \
#            --apple-id you@example.com \
#            --team-id {{team_id}} \
#            --password <app-specific-password>
#      Override the profile name with NOTARY_PROFILE=... if you
#      already have one stored under a different name.
build-dmg-signed: generate
    #!/usr/bin/env bash
    set -euo pipefail

    # --- preflight ---
    if ! security find-identity -v -p codesigning \
         | grep -q "Developer ID Application.*({{team_id}})"; then
        echo "error: no 'Developer ID Application: ... ({{team_id}})' identity in the login keychain."
        echo "       Install it from developer.apple.com or via Xcode → Settings → Accounts."
        exit 1
    fi
    if ! xcrun notarytool history --keychain-profile "{{notary_profile}}" >/dev/null 2>&1; then
        echo "error: notarytool keychain profile '{{notary_profile}}' was not found or is not usable."
        echo "       Create it once with:"
        echo "       xcrun notarytool store-credentials {{notary_profile}} --apple-id you@example.com --team-id {{team_id}} --password <app-specific-password>"
        echo "       Or rerun with NOTARY_PROFILE=name if you already stored credentials under another profile."
        exit 69
    fi

    rm -rf "{{build_dir}}"
    mkdir -p "{{build_dir}}"

    ARCHIVE="{{build_dir}}/{{product_name}}.xcarchive"
    EXPORT_DIR="{{build_dir}}/export"
    EXPORT_OPTIONS="{{build_dir}}/ExportOptions.plist"

    # ExportOptions for a Developer ID export. Automatic signing picks
    # the Developer ID Application identity from the login keychain.
    cat > "$EXPORT_OPTIONS" <<PLIST
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>method</key>
      <string>developer-id</string>
      <key>teamID</key>
      <string>{{team_id}}</string>
      <key>signingStyle</key>
      <string>automatic</string>
    </dict>
    </plist>
    PLIST

    echo "==> archiving..."
    xcodebuild archive \
        -project "{{xcodeproj}}" \
        -scheme {{scheme}} \
        -configuration {{configuration}} \
        -archivePath "$ARCHIVE" \
        -allowProvisioningUpdates \
        DEVELOPMENT_TEAM={{team_id}} \
        CODE_SIGN_STYLE=Automatic

    echo "==> exporting Developer ID build..."
    xcodebuild -exportArchive \
        -archivePath "$ARCHIVE" \
        -exportPath "$EXPORT_DIR" \
        -exportOptionsPlist "$EXPORT_OPTIONS" \
        -allowProvisioningUpdates

    APP_OUT="$EXPORT_DIR/{{product_name}}.app"
    [ -d "$APP_OUT" ] || { echo "error: exportArchive did not produce $APP_OUT"; exit 1; }

    echo "==> verifying signature..."
    codesign --verify --deep --strict --verbose=2 "$APP_OUT"

    echo "==> submitting .app for notarization (this uploads to Apple and waits)..."
    APP_ZIP="{{build_dir}}/{{product_name}}.zip"
    rm -f "$APP_ZIP"
    ditto -c -k --keepParent "$APP_OUT" "$APP_ZIP"
    xcrun notarytool submit "$APP_ZIP" \
        --keychain-profile "{{notary_profile}}" \
        --wait

    echo "==> stapling the .app..."
    xcrun stapler staple "$APP_OUT"
    xcrun stapler validate "$APP_OUT"

    # Stage and rename for the DMG.
    STAGE="{{build_dir}}/dmg-stage"
    rm -rf "$STAGE" && mkdir -p "$STAGE"
    ditto "$APP_OUT" "$STAGE/{{display_name}}.app"

    mkdir -p "{{dmg_out_dir}}"
    DMG_PATH="{{dmg_out_dir}}/{{dmg_basename}}.dmg"
    rm -f "$DMG_PATH"
    "{{make_dmg}}" "$STAGE" "$DMG_PATH" "{{dmg_volume_name}}" "{{display_name}}.app"

    # Pick the actual identity string for codesign (find-identity prints
    # the full CN; codesign --sign accepts either CN or hash).
    echo "==> signing DMG with: {{signing_identity}}"
    codesign --force --sign "{{signing_identity}}" --options runtime --timestamp "$DMG_PATH"

    echo "==> submitting DMG for notarization..."
    xcrun notarytool submit "$DMG_PATH" \
        --keychain-profile "{{notary_profile}}" \
        --wait

    echo "==> stapling the DMG..."
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"

    echo
    echo "DMG: $DMG_PATH"
    echo "  signed, notarized, stapled — ready to distribute."
