// SPDX-License-Identifier: GPL-3.0-or-later
//
// In-process replacement for `TclibRunner`. Each method calls into
// the UniFFI-bound `libtumpa` (linked statically into the XPC binary)
// instead of spawning the `tclig` shell binary.
//
// Same return shapes as `TclibRunner` had so `TumpaCryptoService`
// only needs trivial swap-overs; the .appex side and the XPC
// protocol surface are unchanged.

import Foundation
import os.log

private let log = Logger(
    subsystem: "in.kushaldas.tumpamail.crypto",
    category: "libtumpa-runner"
)

public enum LibtumpaError: Error, LocalizedError {
    case invalidRecipients([String])
    case crypto(String)
    case card(String)
    case keystore(String)
    /// `SecretProvider` failed (no agent cache, no env var, popover
    /// dismissed). Carries the fingerprint + UID of the key that
    /// needed unlocking and `isPin` (smartcard PIN vs software-key
    /// passphrase) so the .appex's popover can render the right
    /// "needs-unlock for Alice <a@example.com>" UI.
    case secretUnavailable(fingerprint: String, uid: String, isPin: Bool, message: String)

    public var errorDescription: String? {
        switch self {
        case .invalidRecipients(let r):
            return "no usable key for recipient(s): \(r.joined(separator: ", "))"
        case .crypto(let msg): return msg
        case .card(let msg): return "smartcard: \(msg)"
        case .keystore(let msg): return "keystore: \(msg)"
        case .secretUnavailable(_, let uid, let isPin, _):
            return isPin
                ? "smartcard PIN required for \(uid)"
                : "passphrase required for \(uid)"
        }
    }
}

/// Translate a Rust `TumpaError` (the UniFFI-thrown enum) into the
/// Swift error shape `TumpaCryptoService` already knows how to
/// handle. The structured `.invalidRecipients([String])` case is
/// what the .appex's compose UI inspects to mark failing chips —
/// that semantic carryover is the whole point of having a typed
/// error here instead of a string.
private func translate(_ error: Error) -> Error {
    if let t = error as? TumpaError {
        switch t {
        case .InvalidRecipients(let recipients):
            return LibtumpaError.invalidRecipients(recipients)
        case .Card(let message):
            return LibtumpaError.card(message)
        case .Keystore(let message):
            return LibtumpaError.keystore(message)
        case .Crypto(let message):
            return LibtumpaError.crypto(message)
        case .SecretUnavailable(let fingerprint, let uid, let isPin, let message):
            return LibtumpaError.secretUnavailable(
                fingerprint: fingerprint,
                uid: uid,
                isPin: isPin,
                message: message
            )
        }
    }
    return error
}

public final class LibtumpaRunner {

    /// Concrete `TumpaSecretProvider` (not the UniFFI protocol) so we
    /// can call the non-FFI `promoteLastServedIfTransient` /
    /// `clearLastServedIfTransient` after each crypto op. UniFFI
    /// happily accepts a concrete type that conforms to its
    /// `SecretProvider` protocol when the function expects
    /// `Arc<dyn SecretProvider>`.
    private let secretProvider: TumpaSecretProvider

    init(secretProvider: TumpaSecretProvider? = nil) {
        self.secretProvider = secretProvider ?? TumpaSecretProvider()
    }

    // MARK: - Sign (detached)

    public struct DetachedSignOutput {
        public let armoredSignature: Data
        public let hashAlgorithm: String
    }

    public func signDetached(
        body: Data,
        signerFingerprint: String,
        digest: String
    ) throws -> DetachedSignOutput {
        do {
            let result = try tumpa_uniffi_signDetached(
                body: body,
                signerFingerprint: signerFingerprint,
                digest: digest,
                provider: secretProvider
            )
            // The signing op succeeded → if the secret came from the
            // transient slot, promote it to the agent so future ops
            // reuse it. Idempotent / no-op when the secret was
            // already cached or didn't need a secret at all.
            secretProvider.promoteLastServedIfTransient()
            return DetachedSignOutput(
                armoredSignature: Data(result.armored),
                hashAlgorithm: result.hashAlgorithm
            )
        } catch {
            // Crypto op failed (likely wrong passphrase / PIN) → wipe
            // the transient secret so we don't replay it on the next
            // call. Critical for smartcards: this caps a wrong-PIN
            // event at 1 card attempt counter slot, not the whole
            // flood of indexer-driven re-signs.
            secretProvider.clearLastServedIfTransient()
            log.error("signDetached failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }

    // MARK: - Encrypt (with optional sign)

    public func encrypt(
        plaintext: Data,
        recipients: [String],
        signerFingerprint: String?,
        armor: Bool
    ) throws -> Data {
        do {
            let ct = try tumpa_uniffi_encrypt(
                plaintext: plaintext,
                recipients: recipients,
                signerFingerprint: signerFingerprint,
                armor: armor,
                // Only pass the SecretProvider when signing — the
                // encrypt-only path never needs a secret.
                provider: signerFingerprint == nil ? nil : secretProvider
            )
            // Sign+encrypt verified the signing secret end-to-end.
            // Promote it to the agent. (Encrypt-only path doesn't
            // touch the SecretProvider; promote is a no-op there.)
            secretProvider.promoteLastServedIfTransient()
            return Data(ct)
        } catch {
            secretProvider.clearLastServedIfTransient()
            log.error("encrypt failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }

    // MARK: - Decrypt + verify

    public struct DecryptVerifyOutput {
        public let plaintext: Data
        public let signatureStatus: String
        public let signerFingerprint: String?
        public let signerKeyId: String?
        public let signerUid: String?
    }

    public func decryptVerify(ciphertext: Data) throws -> DecryptVerifyOutput {
        do {
            let result = try tumpa_uniffi_decryptAndVerify(
                ciphertext: ciphertext,
                provider: secretProvider
            )
            // Decrypt succeeded → the secret used to unlock the
            // decryption key was correct. Promote it from the
            // transient slot to the agent so subsequent decrypt
            // calls (Mail's library indexer fans these out) hit the
            // cache without re-prompting.
            secretProvider.promoteLastServedIfTransient()
            let status: String
            var signerFp: String?
            var signerKid: String?
            var signerUid: String?

            switch result.outcome {
            case .unsigned:
                status = TumpaSignatureStatus.unsigned
            case .good(let signer, let verifierFingerprint):
                status = TumpaSignatureStatus.good
                // The decrypt+verify path uses a 16-char keyid for
                // the `signerKeyId` reply slot (matching the
                // existing tclig-stderr semantics) and the 40-char
                // `verifierFingerprint` for `signerFingerprint`.
                signerFp = verifierFingerprint
                signerKid = String(verifierFingerprint.suffix(16))
                signerUid = signer.primaryUid
            case .bad(let signer):
                status = TumpaSignatureStatus.bad
                signerFp = signer.fingerprint
                signerKid = String(signer.fingerprint.suffix(16))
                signerUid = signer.primaryUid
            case .unknownKey(let issuerIds):
                status = TumpaSignatureStatus.unknown
                // Pick the most precise issuer ID we got. 40-char
                // fingerprint preferred; otherwise a 16-char key ID.
                signerKid = issuerIds.first(where: { $0.count == 40 })
                    ?? issuerIds.first(where: { $0.count == 16 })
                if let v = signerKid, v.count == 40 {
                    signerFp = v
                    signerKid = String(v.suffix(16))
                }
            }

            return DecryptVerifyOutput(
                plaintext: Data(result.plaintext),
                signatureStatus: status,
                signerFingerprint: signerFp,
                signerKeyId: signerKid,
                signerUid: signerUid
            )
        } catch {
            // Decrypt failed (typically wrong passphrase / PIN) →
            // wipe the transient slot. Critical for smartcards: if
            // we left the wrong PIN sitting in the transient slot,
            // the next indexer-driven decryptVerify would replay it
            // and consume another card attempt. With this clear,
            // worst case is 1 attempt counter slot per popover
            // submission.
            secretProvider.clearLastServedIfTransient()
            log.error("decryptVerify failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }

    // MARK: - Verify detached

    public struct VerifyDetachedOutput {
        public let status: String
        public let signerFingerprint: String?
        public let signerKeyId: String?
        public let signerUid: String?
    }

    public func verifyDetached(
        signedBytes: Data,
        signature: Data
    ) throws -> VerifyDetachedOutput {
        do {
            let result = try tumpa_uniffi_verifyDetached(
                signedBytes: signedBytes,
                signature: signature
            )
            switch result {
            case .good(let signer, let verifierFingerprint):
                return VerifyDetachedOutput(
                    status: TumpaSignatureStatus.good,
                    // Full 40-char (the value the security popover
                    // wants to display).
                    signerFingerprint: verifierFingerprint,
                    // 16-char trailing key ID — what GOODSIG used to carry.
                    signerKeyId: String(verifierFingerprint.suffix(16)),
                    signerUid: signer.primaryUid
                )
            case .bad(let signer):
                return VerifyDetachedOutput(
                    status: TumpaSignatureStatus.bad,
                    signerFingerprint: signer.fingerprint,
                    signerKeyId: String(signer.fingerprint.suffix(16)),
                    signerUid: signer.primaryUid
                )
            case .unknownKey(let keyId):
                return VerifyDetachedOutput(
                    status: TumpaSignatureStatus.unknown,
                    signerFingerprint: nil,
                    signerKeyId: keyId,
                    signerUid: nil
                )
            }
        } catch {
            log.error("verifyDetached failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }

    // MARK: - List keys

    public func listKeys() throws -> [TumpaKeyInfo] {
        do {
            let keys = try tumpa_uniffi_listKeys()
            return keys.map { k in
                TumpaKeyInfo(
                    fingerprint: k.fingerprint,
                    primaryUid: k.primaryUid,
                    isSecret: k.isSecret,
                    hasCard: false, // libtumpa list-keys doesn't surface card status today
                    isRevoked: k.isRevoked,
                    isExpired: k.isExpired
                )
            }
        } catch {
            log.error("listKeys failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }

    // MARK: - Resolve recipients

    public func resolveRecipients(emails: [String]) throws -> [String: String] {
        do {
            return try tumpa_uniffi_resolveRecipients(emails: emails)
        } catch {
            log.error("resolveRecipients failed: \(String(describing: error), privacy: .public)")
            throw translate(error)
        }
    }
}

// MARK: - Free-function shims

// The UniFFI-generated functions live in the global Swift namespace as
// `signDetached`, `encrypt`, etc. — names that collide with our
// instance methods on `LibtumpaRunner`. These thin wrappers give them
// distinct names so the call sites read clearly. They forward to the
// generated functions verbatim.

private func tumpa_uniffi_signDetached(
    body: Data,
    signerFingerprint: String,
    digest: String?,
    provider: SecretProvider
) throws -> DetachedSignResult {
    try signDetached(body: body, signerFingerprint: signerFingerprint, digest: digest, provider: provider)
}

private func tumpa_uniffi_encrypt(
    plaintext: Data,
    recipients: [String],
    signerFingerprint: String?,
    armor: Bool,
    provider: SecretProvider?
) throws -> Data {
    try encrypt(
        plaintext: plaintext,
        recipients: recipients,
        signerFingerprint: signerFingerprint,
        armor: armor,
        provider: provider
    )
}

private func tumpa_uniffi_decryptAndVerify(
    ciphertext: Data,
    provider: SecretProvider
) throws -> DecryptVerifyResult {
    try decryptAndVerify(ciphertext: ciphertext, provider: provider)
}

private func tumpa_uniffi_verifyDetached(
    signedBytes: Data,
    signature: Data
) throws -> VerifyResult {
    try verifyDetached(signedBytes: signedBytes, signature: signature)
}

private func tumpa_uniffi_listKeys() throws -> [KeyInfo] {
    try listKeys()
}

private func tumpa_uniffi_resolveRecipients(emails: [String]) throws -> [String: String] {
    try resolveRecipients(emails: emails)
}
