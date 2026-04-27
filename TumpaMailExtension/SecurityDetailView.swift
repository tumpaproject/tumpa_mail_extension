// SPDX-License-Identifier: GPL-3.0-or-later
//
// `MEExtensionViewController` shown when the user clicks the
// puzzle-piece icon on an inbound PGP/MIME message. The signer info
// lands here via the `context: Data` slot we set on
// `MEDecodedMessage` / `MEMessageSigner` — JSON-encoded, decoded back
// on click. Modeled after MailGPG's SecurityDetailView.

import AppKit
import MailKit
import SwiftUI

/// JSON payload carried in `MEDecodedMessage.context` /
/// `MEMessageSigner.context`. Has to be simple Codable since it
/// crosses the MailKit serialization boundary.
struct TumpaSecurityContext: Codable {
    enum Status: String, Codable {
        case signed
        case signedAndEncrypted
        case encrypted
        case signedUnknown   // signer's public key not in the keystore
        case signedBad       // signature did not verify
        case decryptFailed
    }

    let status: Status
    let signerEmail: String?
    let signerLabel: String?    // UID or fingerprint, whichever is human-readable
    let fingerprint: String?
    let keyId: String?
    let errorMessage: String?

    static func encode(_ ctx: TumpaSecurityContext) -> Data {
        (try? JSONEncoder().encode(ctx)) ?? Data()
    }

    static func decode(_ data: Data) -> TumpaSecurityContext? {
        guard !data.isEmpty else { return nil }
        return try? JSONDecoder().decode(TumpaSecurityContext.self, from: data)
    }
}

/// SwiftUI view rendered inside the `MEExtensionViewController`.
struct SecurityDetailView: View {
    let context: TumpaSecurityContext

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: glyph)
                    .font(.title2)
                    .foregroundStyle(glyphColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(headline).font(.headline)
                    Text(subhead).font(.caption).foregroundStyle(.secondary)
                }
            }

            Divider()

            if let label = context.signerLabel, !label.isEmpty {
                row("Signed by", label)
            }
            if let email = context.signerEmail, !email.isEmpty,
               email != context.signerLabel {
                row("Email", email)
            }
            if let fp = context.fingerprint, !fp.isEmpty {
                row("Fingerprint", fp)
            } else if let kid = context.keyId, !kid.isEmpty {
                row("Key ID", kid)
            }
            if let msg = context.errorMessage, !msg.isEmpty {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .frame(minWidth: 320)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            Text(value)
                .font(.caption)
                .textSelection(.enabled)
        }
    }

    private var glyph: String {
        switch context.status {
        case .signed, .signedAndEncrypted: return "checkmark.seal.fill"
        case .encrypted:                   return "lock.fill"
        case .signedUnknown:               return "questionmark.circle.fill"
        case .signedBad:                   return "xmark.seal.fill"
        case .decryptFailed:               return "lock.slash.fill"
        }
    }

    private var glyphColor: Color {
        switch context.status {
        case .signed, .signedAndEncrypted: return .green
        case .encrypted:                   return .green
        case .signedUnknown:               return .orange
        case .signedBad, .decryptFailed:   return .red
        }
    }

    private var headline: String {
        switch context.status {
        case .signed:              return "Signed"
        case .signedAndEncrypted:  return "Signed & Encrypted"
        case .encrypted:           return "Encrypted"
        case .signedUnknown:       return "Signed by an unknown key"
        case .signedBad:           return "Invalid signature"
        case .decryptFailed:       return "Decryption failed"
        }
    }

    private var subhead: String {
        switch context.status {
        case .signed:
            return "OpenPGP signature verified."
        case .signedAndEncrypted:
            return "Signed and encrypted with OpenPGP."
        case .encrypted:
            return "Decrypted with your OpenPGP key."
        case .signedUnknown:
            return "Import the signer's public key to verify."
        case .signedBad:
            return "The signature does not match the message content."
        case .decryptFailed:
            return "You may not have the right private key."
        }
    }
}

/// `MEExtensionViewController` host for `SecurityDetailView`. Mail
/// invokes us via `OutgoingSecurityHandler.extensionViewController(...)`;
/// we wrap a SwiftUI hosting view and hand it back.
final class TumpaSecurityDetailViewController: MEExtensionViewController {

    private let context: TumpaSecurityContext

    init(context: TumpaSecurityContext) {
        self.context = context
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not used")
    }

    override func loadView() {
        let host = NSHostingView(rootView: SecurityDetailView(context: context))
        host.translatesAutoresizingMaskIntoConstraints = true
        host.autoresizingMask = [.width, .height]
        // A minimum frame helps when Mail presents us inside a popover
        // before SwiftUI has measured intrinsic content size.
        host.frame = NSRect(x: 0, y: 0, width: 360, height: 200)
        view = host
    }
}
