// SPDX-License-Identifier: GPL-3.0-or-later
//
// SwiftUI App entry. The host app is intentionally tiny: a
// welcome + status + keys + default-signer pane. Heavy lifting is in
// the XPC service.

import SwiftUI

@main
struct TumpaMailApp: App {

    init() {
        MailExtensionRegistration.refresh()
    }

    var body: some Scene {
        WindowGroup("Tumpa Mail") {
            RootView()
                .frame(minWidth: 640, minHeight: 460)
        }
        .windowResizability(.contentSize)
    }
}

struct RootView: View {

    enum Tab: Hashable {
        case welcome, status, unlock, keys, settings
    }

    @State private var selection: Tab = .welcome

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                NavigationLink(value: Tab.welcome) {
                    Label("Welcome", systemImage: "envelope.badge.shield.half.filled")
                }
                NavigationLink(value: Tab.status) {
                    Label("Status", systemImage: "stethoscope")
                }
                NavigationLink(value: Tab.unlock) {
                    Label("Unlock", systemImage: "lock.open")
                }
                NavigationLink(value: Tab.keys) {
                    Label("Keys", systemImage: "key")
                }
                NavigationLink(value: Tab.settings) {
                    Label("Settings", systemImage: "gear")
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("Tumpa Mail")
        } detail: {
            switch selection {
            case .welcome:  WelcomeView()
            case .status:   StatusView()
            case .unlock:   UnlockKeysView()
            case .keys:     KeysView()
            case .settings: SettingsView()
            }
        }
    }
}
