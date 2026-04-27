# Tumpa Mail

Apple Mail extension that adds OpenPGP (PGP/MIME, RFC 3156) backed by the
`tumpa-cli` keystore and the running `tcli` agent.

The deliverable is a single notarized DMG that drops `Tumpa Mail.app`
into `/Applications`. `tumpa-cli` itself is **not** bundled — install
it separately via Homebrew (`brew install tumpa-cli`, ≥ 0.5.0).

## Architecture

```
Apple Mail.app
└── PlugIns/TumpaMailExtension.appex     (sandboxed by Apple)
        │
        │ NSXPCConnection(serviceName: "in.kushaldas.tumpamail.crypto")
        ▼
Tumpa Mail.app
├── MacOS/TumpaMail                       (SwiftUI UI: status, key picker)
└── XPCServices/TumpaCryptoXPC.xpc        (unsandboxed; spawns tclig)
        │
        ▼
    /opt/homebrew/bin/tclig                (from Homebrew)
        │
        ▼
    ~/.tumpa/keys.db + agent.sock + PCSC card
```

The `.appex` is hard-sandboxed by Apple's MailKit runtime — it cannot
spawn processes, open `~/.tumpa/agent.sock`, or talk to PCSC. All crypto
is done by **TumpaCryptoXPC**, an embedded XPC service that runs
unsandboxed and is the only place `tclig` is invoked. The host UI and
the `.appex` both reach it via `NSXPCConnection(serviceName:)`.

## Phase status

| Phase | Status   | Notes |
|-------|----------|-------|
| 0     | ✅ done  | `tumpa-cli` 0.5.0 + `libtumpa` 0.2.4 + `wecanencrypt` 0.14.2 ship `--digest-algo`, `--clearsign`, `--sign`, `--decrypt --verify-decrypt`, `INV_RECP` lines, `decrypt_and_verify`, `sign_and_encrypt_to_multiple`. |
| 1     | ✅ done  | XPC contract, `TclibRunner`, status-line parser, host UI shell. `.appex` is a placeholder that loads but doesn't yet handle messages. |
| 2     | ⏳ todo  | `MEMessageSecurityHandler` (outgoing sign/encrypt) + `PGPMimeBuilder`. |
| 3     | ⏳ todo  | `MEMessageDecoder` (incoming decrypt/verify) + `PGPMimeParser`. |
| 4     | partial | Welcome / Status / Keys / Settings panes are scaffolded. |
| 5     | ⏳ todo  | DMG packaging script (`scripts/build-dmg.sh`) — see stub. |

## Building locally (developer flow)

Prerequisites: macOS 12+, Xcode 15+, Homebrew, `xcodegen`.

```bash
brew install xcodegen
brew install tumpa-cli                         # ≥ 0.5.0
brew services start tumpa-cli

cd tumpa_mail_extension
xcodegen generate
open TumpaMail.xcodeproj                       # set DEVELOPMENT_TEAM
xcodebuild -scheme TumpaMail -configuration Debug build
```

Then install the built `.app`:

```bash
cp -R build/Debug/TumpaMail.app /Applications/
open /Applications/TumpaMail.app               # registers the .appex with Mail
# Mail → Settings → Extensions → enable "Tumpa Mail"
```

## Building the release DMG

```bash
export DEVELOPMENT_TEAM=YOUR_TEAM_ID
export NOTARY_PROFILE=tumpa-notarize           # configured via `xcrun notarytool store-credentials`
./scripts/build-dmg.sh
```

Result: `dist/TumpaMail-<version>.dmg`, signed and notarized.

## Layout

```
tumpa_mail_extension/
├── project.yml                  # XcodeGen input
├── README.md                    # this file
├── scripts/
│   └── build-dmg.sh             # release packaging
├── Shared/
│   └── TumpaCryptoXPC.swift     # @objc protocol + Codable models
├── TumpaMail/                   # host app (SwiftUI)
│   ├── TumpaMailApp.swift
│   ├── WelcomeView.swift
│   ├── StatusView.swift
│   ├── KeysView.swift
│   ├── SettingsView.swift
│   ├── XPCClient.swift
│   ├── Info.plist
│   └── TumpaMail.entitlements
├── TumpaCryptoXPC/              # XPC service (unsandboxed, spawns tclig)
│   ├── main.swift
│   ├── TumpaCryptoService.swift
│   ├── TclibRunner.swift
│   ├── StatusLineParser.swift
│   ├── Info.plist
│   └── TumpaCryptoXPC.entitlements
└── TumpaMailExtension/          # MailKit extension (.appex, sandboxed)
    ├── Placeholder.swift        # → real handlers in Phase 2 / 3
    ├── Info.plist
    └── TumpaMailExtension.entitlements
```
