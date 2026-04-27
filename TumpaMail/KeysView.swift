// SPDX-License-Identifier: GPL-3.0-or-later
//
// Read-only key picker. Lists what `tclig --list-keys --with-colons`
// returns. The user does key management in `tcli` (import / export /
// generate); the host UI just shows what's there and lets the user
// pick a default signing key.

import SwiftUI

// `TumpaKeyInfo` is `@objc` (so it can cross XPC); we add SwiftUI's
// `Identifiable` here so it can drive a `Table` directly. The
// fingerprint is unique per key in any sensible keystore.
extension TumpaKeyInfo: Identifiable {
    public var id: String { fingerprint }
}

struct KeysView: View {

    @State private var keys: [TumpaKeyInfo] = []
    @State private var loadingError: String?
    @State private var loading = true
    // Stored in the App Group suite so the sandboxed .appex sees the
    // same value. `UserDefaults.standard` would only live in the host
    // process and the extension would never read it.
    @AppStorage(
        TumpaMailDefaults.defaultSignerFingerprint,
        store: UserDefaults(suiteName: TumpaMailSharedSuite)
    )
    private var defaultSigner: String = ""

    var body: some View {
        VStack(spacing: 0) {
            if loading {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let err = loadingError {
                emptyState(
                    icon: "exclamationmark.triangle",
                    title: "Could not load keys",
                    detail: err
                )
            } else if keys.isEmpty {
                emptyState(
                    icon: "key.slash",
                    title: "No keys in keystore",
                    detail: "Import a key with `tcli import`, or generate one with the tumpa app, then refresh."
                )
            } else {
                // SwiftUI's `Table` on macOS treats cell clicks as row
                // selection and routinely swallows embedded Button
                // events. A plain List of custom HStack rows behaves
                // exactly the way users expect.
                List {
                    ForEach(keys) { key in
                        keyRow(key)
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }

            Divider()
            HStack {
                Spacer()
                Button("Refresh") { Task { await load() } }.disabled(loading)
            }
            .padding(8)
        }
        .navigationTitle("Keys")
        .task { await load() }
    }

    /// One row in the Keys list. Click anywhere on the leading icon
    /// or the "Set as default" link to toggle. Whole row is also
    /// click-friendly via `.contentShape(.rect)` so users don't have
    /// to pixel-hunt the icon.
    @ViewBuilder
    private func keyRow(_ key: TumpaKeyInfo) -> some View {
        let isDefault = key.fingerprint == defaultSigner
        let disabled = key.isRevoked || key.isExpired

        HStack(alignment: .center, spacing: 14) {
            Button {
                defaultSigner = isDefault ? "" : key.fingerprint
            } label: {
                Image(systemName: isDefault ? "checkmark.circle.fill" : "circle")
                    .imageScale(.large)
                    .foregroundStyle(isDefault ? Color.accentColor : .secondary)
            }
            .buttonStyle(.plain)
            .disabled(disabled)

            VStack(alignment: .leading, spacing: 2) {
                Text(key.primaryUid).font(.body)
                Text(key.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            Spacer()

            if key.isRevoked {
                Text("revoked").foregroundStyle(.red)
            } else if key.isExpired {
                Text("expired").foregroundStyle(.orange)
            } else if isDefault {
                Text("default signer").foregroundStyle(Color.accentColor)
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    /// macOS-13 friendly stand-in for `ContentUnavailableView` (which
    /// is macOS 14+). A vertical Spacer-padded VStack with an SF Symbol
    /// icon, a headline, and a body line.
    private func emptyState(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @MainActor
    private func load() async {
        loading = true
        defer { loading = false }
        loadingError = nil
        do {
            keys = try await XPCClient.shared.listKeys()
        } catch {
            keys = []
            loadingError = error.localizedDescription
        }
    }
}
