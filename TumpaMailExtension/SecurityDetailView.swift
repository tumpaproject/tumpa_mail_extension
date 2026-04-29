// SPDX-License-Identifier: GPL-3.0-or-later
//
// `MEExtensionViewController` shown when the user clicks the
// puzzle-piece icon on an inbound PGP/MIME message. The signer info
// lands here via the `context: Data` slot we set on
// `MEDecodedMessage` / `MEMessageSigner` — JSON-encoded, decoded back
// on click. Modeled after MailGPG's SecurityDetailView.
//
// Beyond the read-only signer/encrypted info, this view ALSO drives
// the in-Mail unlock flow: when libtumpa needed a passphrase / PIN
// that wasn't in the agent cache, the .appex parks a
// `TumpaSecurityContext` with `.lockedWaiting` here. We render a
// SecureField, the user types, we call back to the XPC service to
// write the secret into `~/.tumpa/agent.sock`, and the user clicks
// the message again to redecode (Mail caches MEDecodedMessage and
// won't auto-redecode without re-selecting).

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
        /// Decryption can't proceed because libtumpa's
        /// `SecretProvider` had nothing in the agent cache and no
        /// `TUMPA_PASSPHRASE` env var. The popover renders a
        /// SecureField; on submit we write to the agent and the user
        /// re-selects the message. `fingerprint` and `signerLabel`
        /// (UID) identify which key needs unlocking.
        case lockedWaiting
    }

    let status: Status
    let signerEmail: String?
    let signerLabel: String?    // UID or fingerprint, whichever is human-readable
    let fingerprint: String?
    let keyId: String?
    let errorMessage: String?
    /// True iff we need a smartcard PIN (vs a software-key passphrase).
    /// Only meaningful when status == .lockedWaiting.
    let isPin: Bool

    init(
        status: Status,
        signerEmail: String? = nil,
        signerLabel: String? = nil,
        fingerprint: String? = nil,
        keyId: String? = nil,
        errorMessage: String? = nil,
        isPin: Bool = false
    ) {
        self.status = status
        self.signerEmail = signerEmail
        self.signerLabel = signerLabel
        self.fingerprint = fingerprint
        self.keyId = keyId
        self.errorMessage = errorMessage
        self.isPin = isPin
    }

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

    @State private var passphrase: String = ""
    @State private var unlocking: Bool = false
    @State private var unlockError: String?
    @State private var unlockSucceeded: Bool = false

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
                row(context.status == .lockedWaiting ? "Key" : "Signed by", label)
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

            if context.status == .lockedWaiting {
                unlockForm()
            }

            if let msg = context.errorMessage, !msg.isEmpty {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .frame(minWidth: 360)
    }

    @ViewBuilder
    private func unlockForm() -> some View {
        Divider()
        if unlockSucceeded {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Unlocked").font(.subheadline).bold()
                    Text("Click the message again to decrypt it.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                SecureField(
                    context.isPin ? "Smartcard PIN" : "Passphrase",
                    text: $passphrase
                )
                .textFieldStyle(.roundedBorder)
                .disabled(unlocking)
                .onSubmit { Task { await submit() } }

                HStack {
                    Spacer()
                    Button {
                        Task { await submit() }
                    } label: {
                        if unlocking {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Unlock")
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(passphrase.isEmpty || unlocking)
                }

                if let err = unlockError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @MainActor
    private func submit() async {
        guard let fingerprint = context.fingerprint, !fingerprint.isEmpty else {
            unlockError = "Missing key fingerprint — cannot verify."
            return
        }
        unlocking = true
        unlockError = nil
        defer { unlocking = false }

        // Step 1: queue the typed secret in the XPC service's
        // in-memory transient slot. cachePassphrase NEVER writes to
        // ~/.tumpa/agent.sock directly — that would let an unverified
        // wrong PIN burn smartcard attempt counter slots on every
        // subsequent indexer-driven decrypt call.
        do {
            try await XPCClient.shared.cachePassphrase(
                fingerprint: fingerprint,
                isPin: context.isPin,
                secret: Data(passphrase.utf8)
            )
        } catch {
            unlockError = error.localizedDescription
            return
        }

        // Step 2: verify the queued secret with a real libtumpa op.
        // We do a tiny detached sign over a sentinel payload — wrong
        // passphrase / wrong PIN fails fast; right passphrase
        // succeeds and `LibtumpaRunner.signDetached` promotes the
        // transient slot to the agent via its promote-on-success
        // hook. After this, every future decode/sign/encrypt call
        // hits the agent cache without re-prompting.
        //
        // Cost calculus for cards: this consumes 1 attempt counter
        // slot — exactly the same as letting `decryptVerify` use the
        // transient secret directly would have. Net cost is
        // identical; UX is much better because the user gets
        // instant feedback instead of "click the message and pray".
        do {
            _ = try await XPCClient.shared.signDetached(
                canonicalizedBody: Data("tumpa-mail-unlock-verify".utf8),
                signerFingerprint: fingerprint,
                digest: "SHA256"
            )
            unlockSucceeded = true
            passphrase = "" // zeroize the View state
        } catch {
            // libtumpa rejected the secret. The runner has already
            // wiped the transient slot, so there's nothing left to
            // burn another attempt slot on. Tell the user.
            unlockError = context.isPin
                ? "Wrong PIN. Please try again."
                : "Wrong passphrase. Please try again."
            // Don't clear `passphrase` — let the user edit and retry.
        }
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
        case .lockedWaiting:               return "lock.fill"
        }
    }

    private var glyphColor: Color {
        switch context.status {
        case .signed, .signedAndEncrypted: return .green
        case .encrypted:                   return .green
        case .signedUnknown:               return .orange
        case .signedBad, .decryptFailed:   return .red
        case .lockedWaiting:               return .orange
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
        case .lockedWaiting:
            return context.isPin ? "Smartcard locked" : "Key locked"
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
        case .lockedWaiting:
            return context.isPin
                ? "Enter the smartcard PIN to decrypt this and future messages."
                : "Enter the key passphrase to decrypt this and future messages."
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
        // before SwiftUI has measured intrinsic content size. The
        // unlock state needs more vertical room for the SecureField +
        // button than the read-only states.
        let height: CGFloat = context.status == .lockedWaiting ? 280 : 200
        host.frame = NSRect(x: 0, y: 0, width: 380, height: height)
        view = host
    }
}
