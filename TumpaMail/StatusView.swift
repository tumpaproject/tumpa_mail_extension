// SPDX-License-Identifier: GPL-3.0-or-later
//
// Diagnostic panel: probes the XPC service for `tclig` version,
// agent socket reachability, and connected card. The user opens this
// when something doesn't work to figure out which layer is broken.

import SwiftUI

struct StatusView: View {

    @State private var tcligVersion: String?
    @State private var tcligError: String?
    @State private var agentSocketExists: Bool?
    @State private var loading = true

    var body: some View {
        Form {
            Section("tumpa-cli") {
                row(label: "tclig version",
                    ok: tcligVersion != nil && tcligError == nil,
                    detail: tcligVersion ?? tcligError ?? "checking…")
            }
            Section("Agent") {
                row(label: "~/.tumpa/agent.sock",
                    ok: agentSocketExists == true,
                    detail: agentSocketExists == true
                        ? "reachable"
                        : "not running — `brew services start tumpa-cli`")
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

    @MainActor
    private func refresh() async {
        loading = true
        defer { loading = false }

        do {
            tcligVersion = try await XPCClient.shared.tcligVersion()
            tcligError = nil
        } catch {
            tcligVersion = nil
            tcligError = error.localizedDescription
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
