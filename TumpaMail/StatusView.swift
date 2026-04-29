// SPDX-License-Identifier: GPL-3.0-or-later
//
// Diagnostic panel: probes the XPC service for the agent socket and
// keystore reachability. The user opens this when something doesn't
// work to figure out which layer is broken.
//
// As of the libtumpa-via-UniFFI cutover, the crypto code is part of
// the XPC binary itself — there is no separate `tclig` binary on
// PATH to version-check. The "tumpa-cli on PATH" row is gone.

import SwiftUI

struct StatusView: View {

    @State private var keyCount: Int?
    @State private var keystoreError: String?
    @State private var agentSocketExists: Bool?
    @State private var loading = true

    var body: some View {
        Form {
            Section("Keystore") {
                row(label: "~/.tumpa/keys.db",
                    ok: keyCount != nil && keystoreError == nil,
                    detail: detailForKeystore())
            }
            Section("Agent") {
                row(label: "~/.tumpa/agent.sock",
                    ok: agentSocketExists == true,
                    detail: agentSocketExists == true
                        ? "reachable — cached secrets will be reused"
                        : "not running — passphrase / PIN prompts every op")
            }
            Section {
                Button("Re-check") { Task { await refresh() } }
                    .disabled(loading)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Status")
        .task { await refresh() }
    }

    private func row(label: String, ok: Bool, detail: String) -> some View {
        LabeledContent(label) {
            HStack(spacing: 8) {
                Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(ok ? .green : .orange)
                Text(detail).foregroundStyle(.secondary)
            }
        }
    }

    private func detailForKeystore() -> String {
        if let err = keystoreError { return err }
        if let n = keyCount {
            return "\(n) key\(n == 1 ? "" : "s")"
        }
        return "checking…"
    }

    @MainActor
    private func refresh() async {
        loading = true
        defer { loading = false }

        do {
            let keys = try await XPCClient.shared.listKeys()
            keyCount = keys.count
            keystoreError = nil
        } catch {
            keyCount = nil
            keystoreError = error.localizedDescription
        }

        // Sandboxed host can't reach `~/.tumpa/`; the unsandboxed XPC
        // service performs the file probe and reports back.
        do {
            agentSocketExists = try await XPCClient.shared.agentSocketExists()
        } catch {
            agentSocketExists = false
        }
    }
}
