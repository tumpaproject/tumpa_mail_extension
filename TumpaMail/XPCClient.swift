// SPDX-License-Identifier: GPL-3.0-or-later
//
// Thin wrapper around `NSXPCConnection(serviceName:)` for the host
// UI. The .appex has its own copy of this file so it can use the same
// pattern from inside Apple Mail.
//
// This is the only place in the host app that touches XPC; views call
// the typed async methods on `XPCClient` and don't see NSXPC types.

import Foundation

/// Errors surfaced from XPC calls. The XPC service signals trouble via
/// `NSError` reply; we wrap that in this enum so the UI can pattern-
/// match without typing `NSError.code` raw.
///
/// `needsUnlock` is the structured form of the "smartcard PIN required
/// for X" / "passphrase required for X" error libtumpa returns when
/// neither the agent nor the transient store has a usable secret. The
/// host's UnlockKeysView pattern-matches on this to drive its
/// probe-then-prompt UX (vs. a generic `.remote(String)` it would
/// otherwise have to scrape the localized string for).
enum XPCClientError: Error, LocalizedError {
    case connectionInvalidated
    case remote(String)
    case needsUnlock(fingerprint: String, uid: String, isPin: Bool)
    case noResult

    var errorDescription: String? {
        switch self {
        case .connectionInvalidated:
            return "Connection to the Tumpa Crypto XPC service was lost."
        case .remote(let msg):
            return msg
        case .needsUnlock(_, let uid, let isPin):
            return isPin
                ? "Smartcard PIN required for \(uid)"
                : "Passphrase required for \(uid)"
        case .noResult:
            return "XPC reply carried no result."
        }
    }
}

@MainActor
final class XPCClient: ObservableObject {

    static let shared = XPCClient()

    private var connection: NSXPCConnection?

    private init() {}

    private func proxy() throws -> TumpaCryptoXPC {
        if connection == nil {
            let conn = NSXPCConnection(serviceName: TumpaCryptoXPCServiceName)
            conn.remoteObjectInterface = NSXPCInterface(with: TumpaCryptoXPC.self)

            // Allow-list collection element classes for the
            // listKeys / resolveRecipients reply payloads, mirroring
            // the service-side configuration.
            conn.remoteObjectInterface!.setClasses(
                NSSet(array: [NSArray.self, TumpaKeyInfo.self, NSString.self]) as! Set<AnyHashable>,
                for: #selector(TumpaCryptoXPC.listKeys(reply:)),
                argumentIndex: 0,
                ofReply: true
            )
            conn.remoteObjectInterface!.setClasses(
                NSSet(array: [NSDictionary.self, NSString.self]) as! Set<AnyHashable>,
                for: #selector(TumpaCryptoXPC.resolveRecipients(emails:reply:)),
                argumentIndex: 0,
                ofReply: true
            )

            conn.invalidationHandler = { [weak self] in
                Task { @MainActor in self?.connection = nil }
            }
            conn.interruptionHandler = { [weak self] in
                Task { @MainActor in self?.connection = nil }
            }
            conn.resume()
            connection = conn
        }
        guard let p = connection?.remoteObjectProxy as? TumpaCryptoXPC else {
            throw XPCClientError.connectionInvalidated
        }
        return p
    }

    // MARK: - Typed async wrappers

    func listKeys() async throws -> [TumpaKeyInfo] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().listKeys { keys, error in
                    if let e = error {
                        cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                    } else {
                        cont.resume(returning: keys)
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func resolveRecipients(_ emails: [String]) async throws -> [String: String] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().resolveRecipients(emails: emails) { resolved, error in
                    if let e = error {
                        cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                    } else {
                        cont.resume(returning: resolved)
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func describeKey(_ fingerprint: String) async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().describeKey(fingerprint: fingerprint) { details, error in
                    if let e = error {
                        cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                    } else if let d = details {
                        cont.resume(returning: d)
                    } else {
                        cont.resume(throwing: XPCClientError.remote("empty describe reply"))
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func agentSocketExists() async throws -> Bool {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().agentSocketExists { exists in
                    cont.resume(returning: exists)
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    // MARK: - Unlock flow

    /// Detached signature over `canonicalizedBody`. The Unlock pane
    /// uses this with a sentinel payload (`"tumpa-mail-unlock-verify"`)
    /// to probe whether a key is currently usable: a successful
    /// signature means the agent (or transient store, after the user
    /// just typed a PIN/passphrase) has the secret; an
    /// `XPCClientError.needsUnlock` means it's locked and identifies
    /// whether to ask for a PIN vs a passphrase.
    func signDetached(
        canonicalizedBody: Data,
        signerFingerprint: String,
        digest: String
    ) async throws -> (signature: Data, actualDigest: String) {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().signDetached(
                    canonicalizedBody: canonicalizedBody,
                    signerFingerprint: signerFingerprint,
                    digest: digest
                ) { sig, actual, needsFp, needsUid, needsIsPin, error in
                    if let needsFp = needsFp, let needsUid = needsUid {
                        cont.resume(throwing: XPCClientError.needsUnlock(
                            fingerprint: needsFp,
                            uid: needsUid,
                            isPin: needsIsPin
                        ))
                    } else if let e = error {
                        cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                    } else if let sig = sig, let actual = actual {
                        cont.resume(returning: (sig, actual))
                    } else {
                        cont.resume(throwing: XPCClientError.noResult)
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    /// Queue a popover-typed secret in the XPC service's in-memory
    /// transient slot. The next `signDetached` call consumes it via
    /// libtumpa's SecretProvider; success promotes it to
    /// `~/.tumpa/agent.sock`, failure wipes it.
    ///
    /// CRITICAL: this method MUST NOT be used to write the secret
    /// straight to the agent without a verifying op in between — the
    /// agent has no way to know whether a passphrase / PIN is right,
    /// and a wrong cached PIN would burn smartcard attempt counters
    /// across the next several Mail decode operations. The caller
    /// (UnlockKeysView / SecurityDetailView) always pairs this with
    /// `signDetached` to verify before promotion.
    func cachePassphrase(
        fingerprint: String,
        isPin: Bool,
        secret: Data
    ) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            do {
                try proxy().cachePassphrase(
                    fingerprint: fingerprint,
                    isPin: isPin,
                    secret: secret
                ) { success, error in
                    if let e = error {
                        cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                    } else if success {
                        cont.resume(returning: ())
                    } else {
                        cont.resume(throwing: XPCClientError.remote("agent rejected the secret"))
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }
}
