// SPDX-License-Identifier: GPL-3.0-or-later

import SwiftUI

struct WelcomeView: View {

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Tumpa Mail")
                    .font(.largeTitle).bold()
                Text("OpenPGP for Apple Mail, backed by your tumpa keystore.")
                    .font(.title3).foregroundStyle(.secondary)

                stepBlock(
                    n: 1,
                    title: "Install tumpa-cli",
                    body: "If you haven't already:\n\n  brew tap tumpaproject/tumpa-cli\n  brew install tumpa-cli\n\nTumpa Mail needs tumpa-cli ≥ 0.5.0."
                )
                stepBlock(
                    n: 2,
                    title: "Start the agent",
                    body: "  brew services start tumpa-cli\n\nThe agent caches passphrases / PINs across sign and decrypt operations so you aren't prompted on every email."
                )
                stepBlock(
                    n: 3,
                    title: "Enable the extension in Mail",
                    body: "Open Mail → Settings → Extensions, then turn on \"Tumpa Mail\" under both Compose and Reading."
                )
                stepBlock(
                    n: 4,
                    title: "Send a signed test email",
                    body: "Compose a new mail, click the lock icon and pick \"Sign\". Tumpa Mail produces a PGP/MIME multipart/signed message your recipient can verify in any standard PGP-aware client."
                )

                Spacer(minLength: 8)
                Text("More on the project: https://github.com/tumpaproject")
                    .font(.footnote).foregroundStyle(.tertiary)
            }
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func stepBlock(n: Int, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Circle().fill(Color.accentColor.opacity(0.15))
                    .frame(width: 32, height: 32)
                Text("\(n)").font(.headline).foregroundStyle(.tint)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.headline)
                Text(body)
                    .font(.system(.body, design: .default))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }
}
