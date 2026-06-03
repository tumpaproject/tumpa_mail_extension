// SPDX-License-Identifier: GPL-3.0-or-later
//
// Per-address key picker. When two or more certs in the keystore carry
// a UID for the same email, signing / encryption is ambiguous —
// `resolve_recipients` would silently pick the first match. This pane
// lets the user pin which cert to SIGN AS (for their own From
// addresses) and which to ENCRYPT TO (for recipients) on each such
// address. The choice is written to the App Group suite
// (`signingKeyOverrides` / `encryptionKeyOverrides`) and the sandboxed
// .appex honors it at send time via `OutgoingSecurityHandler`.
//
// Only addresses with more than one usable cert show up here — single
// key addresses need no choice and resolve automatically.

import SwiftUI

struct KeySelectionView: View {

    /// One ambiguous address plus the candidate certs for it. Both
    /// pickers list every usable cert for the address; the "Sign as"
    /// picker annotates certs with no local secret material / card as
    /// "(no secret key)" since you can't sign with those — but it still
    /// shows them so an ambiguous address never looks like it has only
    /// one choice.
    private struct AddressOptions: Identifiable {
        let email: String
        let keys: [TumpaKeyInfo]
        var id: String { email }
    }

    @State private var rows: [AddressOptions] = []
    @State private var loading = true
    @State private var loadError: String?

    /// "Automatic" sentinel for the Pickers — distinct from any real
    /// 40-char hex fingerprint, so an empty / cleared override renders
    /// as the first-match default.
    private static let automaticTag = ""

    private var sharedDefaults: UserDefaults? {
        UserDefaults(suiteName: TumpaMailSharedSuite)
    }

    var body: some View {
        VStack(spacing: 0) {
            if loading {
                ProgressView("Loading addresses…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let err = loadError {
                emptyState(
                    icon: "exclamationmark.triangle",
                    title: "Could not load addresses",
                    detail: err
                )
            } else if rows.isEmpty {
                emptyState(
                    icon: "checkmark.seal",
                    title: "No addresses need a choice",
                    detail: "Signing and encryption keys are chosen automatically. This pane only lists addresses that have more than one usable key in the keystore."
                )
            } else {
                Form {
                    Section {
                        Text("These addresses have more than one usable key. Pick which key to sign as and which to encrypt to. \"Automatic\" uses the first matching key.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(rows) { row in
                        addressSection(row)
                    }
                }
                .formStyle(.grouped)
            }

            Divider()
            HStack {
                Spacer()
                Button("Refresh") { Task { await load() } }.disabled(loading)
            }
            .padding(8)
        }
        .navigationTitle("Key Selection")
        .task { await load() }
    }

    @ViewBuilder
    private func addressSection(_ row: AddressOptions) -> some View {
        Section(row.email) {
            picker(
                title: "Sign as",
                candidates: row.keys,
                current: TumpaKeyOverrides.signingFingerprint(forEmail: row.email, in: sharedDefaults),
                markNonSigning: true
            ) { newValue in
                TumpaKeyOverrides.setSigning(
                    newValue.isEmpty ? nil : newValue,
                    forEmail: row.email,
                    in: sharedDefaults
                )
            }

            picker(
                title: "Encrypt to",
                candidates: row.keys,
                current: TumpaKeyOverrides.encryptionFingerprint(forEmail: row.email, in: sharedDefaults),
                markNonSigning: false
            ) { newValue in
                TumpaKeyOverrides.setEncryption(
                    newValue.isEmpty ? nil : newValue,
                    forEmail: row.email,
                    in: sharedDefaults
                )
            }
        }
    }

    /// A labeled Picker over `candidates` plus an "Automatic" option.
    /// `current` is the stored override fingerprint (or nil). Writes go
    /// through `onChange` immediately — there's no Save button; the
    /// override map is the source of truth. `markNonSigning` annotates
    /// public-only / cardless certs (the "Sign as" picker), which can't
    /// actually sign.
    @ViewBuilder
    private func picker(
        title: String,
        candidates: [TumpaKeyInfo],
        current: String?,
        markNonSigning: Bool,
        onChange: @escaping (String) -> Void
    ) -> some View {
        // Selection binding stored locally so SwiftUI redraws the
        // Picker; the persistent write happens via onChange. Seed from
        // the stored override, falling back to Automatic when it's unset
        // or no longer a candidate.
        let initial: String = {
            guard let c = current,
                  candidates.contains(where: { $0.fingerprint.caseInsensitiveCompare(c) == .orderedSame })
            else { return Self.automaticTag }
            return c
        }()
        PickerRow(
            title: title,
            candidates: candidates,
            initial: initial,
            automaticTag: Self.automaticTag,
            markNonSigning: markNonSigning,
            onChange: onChange
        )
    }

    private func emptyState(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(title).font(.headline)
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
        loadError = nil
        do {
            let addresses = try await XPCClient.shared.ambiguousAddresses()
            var built: [AddressOptions] = []
            for email in addresses {
                let candidates = try await XPCClient.shared.keysForEmail(email)
                built.append(AddressOptions(email: email, keys: candidates))
            }
            rows = built
        } catch {
            rows = []
            loadError = error.localizedDescription
        }
    }
}

/// A single Picker row with its own `@State` selection so SwiftUI
/// tracks changes; persists every change via `onChange`. Split into its
/// own view because `@State` can't live inside a `@ViewBuilder` helper.
private struct PickerRow: View {
    let title: String
    let candidates: [TumpaKeyInfo]
    let automaticTag: String
    let markNonSigning: Bool
    let onChange: (String) -> Void

    @State private var selection: String

    init(
        title: String,
        candidates: [TumpaKeyInfo],
        initial: String,
        automaticTag: String,
        markNonSigning: Bool,
        onChange: @escaping (String) -> Void
    ) {
        self.title = title
        self.candidates = candidates
        self.automaticTag = automaticTag
        self.markNonSigning = markNonSigning
        self.onChange = onChange
        _selection = State(initialValue: initial)
    }

    var body: some View {
        Picker(title, selection: $selection) {
            Text("Automatic").tag(automaticTag)
            ForEach(candidates) { key in
                Text(label(for: key)).tag(key.fingerprint)
            }
        }
        .onChange(of: selection) { newValue in
            onChange(newValue)
        }
    }

    /// "Alice <alice@x> · 1A2B3C4D5E6F7A8B" — UID plus the 16-char key
    /// id (last 16 hex of the fingerprint) so two certs sharing a UID
    /// are still distinguishable. Appends a revoked/expired tag, plus
    /// "(no secret key)" in the signing picker for certs with no local
    /// secret material or linked card (you can't sign with those — the
    /// .appex would fall back to first-match if one were pinned).
    private func label(for key: TumpaKeyInfo) -> String {
        let keyId = String(key.fingerprint.suffix(16))
        var s = "\(key.primaryUid) · \(keyId)"
        if key.isRevoked { s += " (revoked)" }
        else if key.isExpired { s += " (expired)" }
        if markNonSigning && !key.isSecret && !key.hasCard { s += " (no secret key)" }
        return s
    }
}
