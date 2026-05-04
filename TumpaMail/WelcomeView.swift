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
                    body: "  brew tap tumpaproject/tumpa-cli\n  brew install tumpa-cli\n\nFor agent setup, key import, smartcard provisioning, and everything else, see the tumpa-cli README."
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
