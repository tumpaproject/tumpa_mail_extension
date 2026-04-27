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

    var body: some View {
        Form {
            Section("Outgoing mail") {
                Toggle("Sign every outgoing message by default", isOn: $alwaysSign)
                Picker("Hash algorithm for signatures", selection: $defaultDigest) {
                    Text("SHA-256").tag("SHA256")
                    Text("SHA-384").tag("SHA384")
                    Text("SHA-512").tag("SHA512")
                }
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
