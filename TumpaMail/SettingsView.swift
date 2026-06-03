// SPDX-License-Identifier: GPL-3.0-or-later
//
// Stub settings pane. Tumpa Mail v1 is intentionally light on
// preferences — defaults are sensible, the user picks signing key in
// the Keys pane, and everything else flows from `tumpa-cli` itself.

import SwiftUI

struct SettingsView: View {

    // All four prefs live in the App Group suite so the .appex sees
    // them. Using `UserDefaults.standard` here would silently leave
    // the extension stuck on its compiled-in defaults.
    @AppStorage(
        TumpaMailDefaults.defaultDigest,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var defaultDigest: String = "SHA256"

    @AppStorage(
        TumpaMailDefaults.alwaysSign,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var alwaysSign: Bool = false

    @AppStorage(
        TumpaMailDefaults.preferEncryptedReplies,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var preferEncryptedReplies: Bool = true

    // F1 / F2 / F3 — default-on; the .appex's accessors fall back to
    // `true` for unset keys via `object(forKey:) as? Bool ?? true`, so
    // a fresh install with no `register(defaults:)` call still picks
    // up the right behavior. @AppStorage's default-value parameter
    // here only governs the initial UI render (off → toggle off,
    // first-paint mismatch).
    @AppStorage(
        TumpaMailDefaults.attachPubkeyOnSign,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var attachPubkeyOnSign: Bool = true

    @AppStorage(
        TumpaMailDefaults.autocryptHeader,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var autocryptHeader: Bool = true

    @AppStorage(
        TumpaMailDefaults.encryptSubject,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var encryptSubject: Bool = true

    var body: some View {
        Form {
            Section("Outgoing mail") {
                Toggle("Sign every outgoing message by default", isOn: $alwaysSign)
                Picker("Hash algorithm for signatures", selection: $defaultDigest) {
                    Text("SHA-256").tag("SHA256")
                    Text("SHA-384").tag("SHA384")
                    Text("SHA-512").tag("SHA512")
                }
                Toggle(
                    "Attach my public key when signing",
                    isOn: $attachPubkeyOnSign
                )
                Toggle(
                    "Add Autocrypt header to outgoing messages",
                    isOn: $autocryptHeader
                )
                Toggle(
                    "Encrypt subject lines (protected headers)",
                    isOn: $encryptSubject
                )
            }
            Section("Incoming mail") {
                Toggle(
                    "Reply encrypted when the original was encrypted",
                    isOn: $preferEncryptedReplies
                )
            }
            Section {
                LabeledContent("Keystore", value: "~/.tumpa/keys.db")
                LabeledContent("Agent socket", value: "~/.tumpa/agent.sock")
            } footer: {
                Text("Tumpa Mail uses the same keystore as `tcli`. Manage keys with `tcli import` / `tcli export` / `tumpa.app`.")
                    .font(.footnote)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
    }
}
