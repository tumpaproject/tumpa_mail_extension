// SPDX-License-Identifier: GPL-3.0-or-later
//
// Read-only, informational key list. Shows what
// `tclig --list-keys --with-colons` returns. The user does key
// management in `tcli` (import / export / generate); the host UI
// just shows what's there. Signing-key selection is automatic —
// outgoing messages are signed with the keystore key whose UID
// matches the message's From address.

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
    /// The key whose detail sheet is currently shown. SwiftUI's
    /// `.sheet(item:)` modal is driven off this — set it to a key to
    /// open, set it back to nil to close.
    @State private var selectedKey: TumpaKeyInfo?
    /// Filter text. Empty = show all. Matches case-insensitively
    /// against `primaryUid` (covers name + email) and `fingerprint`
    /// (so power users can paste a hex prefix and find a key fast).
    @State private var searchText: String = ""

    /// Keys filtered by `searchText`. Returns the full list when the
    /// query is empty; otherwise keeps every key whose UID or
    /// fingerprint contains the query (case-insensitive).
    private var filteredKeys: [TumpaKeyInfo] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return keys }
        return keys.filter { key in
            key.primaryUid.range(of: q, options: .caseInsensitive) != nil ||
            key.fingerprint.range(of: q, options: .caseInsensitive) != nil
        }
    }

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
                searchField
                Divider()
                if filteredKeys.isEmpty {
                    emptyState(
                        icon: "magnifyingglass",
                        title: "No matches",
                        detail: "No keys match \"\(searchText)\". Try a different name, email, or fingerprint prefix."
                    )
                } else {
                    // SwiftUI's `Table` on macOS treats cell clicks as row
                    // selection and routinely swallows embedded Button
                    // events. A plain List of custom HStack rows behaves
                    // exactly the way users expect.
                    List {
                        ForEach(filteredKeys) { key in
                            keyRow(key)
                                .onTapGesture { selectedKey = key }
                        }
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
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
        .sheet(item: $selectedKey) { key in
            KeyDetailSheet(key: key) { selectedKey = nil }
        }
    }

    /// Top-of-view search box. Magnifying-glass icon, clear-button
    /// when non-empty.
    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Search by name, email, or fingerprint", text: $searchText)
                .textFieldStyle(.plain)
            if !searchText.isEmpty {
                Button {
                    searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Clear search")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// One row in the Keys list. Informational only — outgoing mail
    /// is signed with whichever key's UID matches the From address,
    /// so there's no per-row picker.
    @ViewBuilder
    private func keyRow(_ key: TumpaKeyInfo) -> some View {
        HStack(alignment: .center, spacing: 14) {
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

/// Modal sheet showing `tcli describe <fp>`-shaped output for one key.
/// The text is rendered by `libtumpa::describe::format_key_info` in
/// the XPC service so it matches `tcli describe` byte-for-byte.
private struct KeyDetailSheet: View {

    let key: TumpaKeyInfo
    let onClose: () -> Void

    @State private var details: String?
    @State private var loadError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(key.primaryUid).font(.headline)
                    Text(key.fingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                Button("Close", action: onClose)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            if let text = details {
                ScrollView {
                    Text(text)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(20)
                }
            } else if let err = loadError {
                VStack(spacing: 10) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 32))
                        .foregroundStyle(.orange)
                    Text("Could not load key details")
                        .font(.headline)
                    Text(err)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(40)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ProgressView("Loading details…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 560, minHeight: 380)
        .task { await load() }
    }

    @MainActor
    private func load() async {
        do {
            details = try await XPCClient.shared.describeKey(key.fingerprint)
        } catch {
            loadError = error.localizedDescription
        }
    }
}
