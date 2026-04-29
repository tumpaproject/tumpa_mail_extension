// SPDX-License-Identifier: GPL-3.0-or-later
//
// XPC client used inside the .appex (the MailKit extension). Mirror of
// `TumpaMail/XPCClient.swift` — both modules link against
// `Shared/TumpaCryptoXPC.swift` for the protocol definition but
// otherwise live in separate Swift modules and can't share Swift
// files without compiling them twice. Keeping a parallel copy here
// is simpler than introducing a Swift framework just for this.
//
// All work goes to `in.kushaldas.tumpamail.crypto`, the XPC service
// bundle embedded in `Tumpa Mail.app/Contents/XPCServices/`.

import Foundation
import os.log

private let xpcLog = Logger(
    subsystem: "in.kushaldas.tumpamail.extension",
    category: "xpc"
)

enum XPCClientError: Error, LocalizedError {
    case connectionInvalidated
    case remote(String)
    case noResult
    /// libtumpa needed a passphrase / PIN that wasn't in the agent
    /// cache. The .appex's `OutgoingSecurityHandler` translates this
    /// into a `TumpaSecurityContext.lockedWaiting` so Mail's
    /// puzzle-piece popover prompts the user inline.
    case needsUnlock(fingerprint: String, uid: String, isPin: Bool)

    var errorDescription: String? {
        switch self {
        case .needsUnlock(_, let uid, let isPin):
            return isPin
                ? "Smartcard PIN required for \(uid)"
                : "Passphrase required for \(uid)"
        case .connectionInvalidated:
            return "Connection to Tumpa Crypto XPC service was lost."
        case .remote(let msg):
            return msg
        case .noResult:
            return "Tumpa Crypto XPC service returned no result."
        }
    }
}

/// One client instance per `MEMessageSecurityHandler` lifecycle.
/// Apple Mail keeps the handler around for the duration of a compose
/// session, so the connection reuses across `getEncodingStatus` and
/// `encode` calls.
final class XPCClient {

    /// Process-wide shared instance. The popover unlock flow uses
    /// this so the SwiftUI view doesn't have to plumb an XPCClient
    /// through `MEExtensionViewController` init. Fine to share — the
    /// class internally does its own connection management with a lock.
    static let shared = XPCClient()

    private var connection: NSXPCConnection?
    private let lock = NSLock()

    func proxy() throws -> TumpaCryptoXPC {
        lock.lock()
        defer { lock.unlock() }

        if connection == nil {
            xpcLog.info("creating NSXPCConnection serviceName=\(TumpaCryptoXPCServiceName, privacy: .public)")
            let conn = NSXPCConnection(serviceName: TumpaCryptoXPCServiceName)
            conn.remoteObjectInterface = makeInterface()
            conn.invalidationHandler = { [weak self] in
                xpcLog.error("XPC connection invalidated (service not found, signature mismatch, or crashed)")
                self?.lock.lock()
                self?.connection = nil
                self?.lock.unlock()
            }
            conn.interruptionHandler = { [weak self] in
                xpcLog.error("XPC connection interrupted (service crashed mid-call)")
                self?.lock.lock()
                self?.connection = nil
                self?.lock.unlock()
            }
            conn.resume()
            connection = conn
            xpcLog.info("NSXPCConnection resumed")
        }
        // The errorHandler version of remoteObjectProxy surfaces a
        // synchronous error (instead of silently dropping the call)
        // when the service can't be reached — without it a missing
        // service-name lookup just hangs forever on the reply.
        let proxyOrNil = connection?.remoteObjectProxyWithErrorHandler { error in
            xpcLog.error("XPC proxy error: \(error.localizedDescription, privacy: .public)")
        }
        guard let p = proxyOrNil as? TumpaCryptoXPC else {
            xpcLog.error("remoteObjectProxy is not TumpaCryptoXPC — interface mismatch?")
            throw XPCClientError.connectionInvalidated
        }
        return p
    }

    private func makeInterface() -> NSXPCInterface {
        let iface = NSXPCInterface(with: TumpaCryptoXPC.self)

        // Allow-list the collection element classes that cross XPC for
        // listKeys / resolveRecipients. NSDictionary / NSArray /
        // NSString / TumpaKeyInfo all need to be on the list.
        iface.setClasses(
            NSSet(array: [NSArray.self, TumpaKeyInfo.self, NSString.self]) as! Set<AnyHashable>,
            for: #selector(TumpaCryptoXPC.listKeys(reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        iface.setClasses(
            NSSet(array: [NSDictionary.self, NSString.self]) as! Set<AnyHashable>,
            for: #selector(TumpaCryptoXPC.resolveRecipients(emails:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        return iface
    }

    // MARK: - Async wrappers

    func listKeys() async throws -> [TumpaKeyInfo] {
        try await call { proxy, cont in
            proxy.listKeys { keys, e in
                if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(returning: keys)
                }
            }
        }
    }

    func resolveRecipients(_ emails: [String]) async throws -> [String: String] {
        try await call { proxy, cont in
            proxy.resolveRecipients(emails: emails) { resolved, e in
                if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(returning: resolved)
                }
            }
        }
    }

    func signDetached(
        canonicalizedBody: Data,
        signerFingerprint: String,
        digest: String
    ) async throws -> (signature: Data, actualDigest: String) {
        try await call { proxy, cont in
            proxy.signDetached(
                canonicalizedBody: canonicalizedBody,
                signerFingerprint: signerFingerprint,
                digest: digest
            ) { sig, actual, e in
                if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else if let sig = sig, let actual = actual {
                    cont.resume(returning: (sig, actual))
                } else {
                    cont.resume(throwing: XPCClientError.noResult)
                }
            }
        }
    }

    /// Decrypt + verify in one pass for inbound `multipart/encrypted`.
    /// `signatureStatus` is one of the `TumpaSignatureStatus.*`
    /// constants (`unsigned` / `good` / `bad` / `unknown`).
    func decryptVerify(
        ciphertext: Data
    ) async throws -> (
        plaintext: Data,
        signatureStatus: String,
        signerFingerprint: String?,
        signerKeyId: String?,
        signerUid: String?
    ) {
        try await call { proxy, cont in
            proxy.decryptVerify(armoredCiphertext: ciphertext) {
                pt, status, fp, kid, uid, needsFp, needsUid, needsIsPin, e in
                if let pt = pt {
                    cont.resume(returning: (pt, status, fp, kid, uid))
                } else if let needsFp = needsFp, let needsUid = needsUid {
                    cont.resume(throwing: XPCClientError.needsUnlock(
                        fingerprint: needsFp,
                        uid: needsUid,
                        isPin: needsIsPin
                    ))
                } else if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(throwing: XPCClientError.noResult)
                }
            }
        }
    }

    /// Verify a detached signature for inbound `multipart/signed`.
    /// `status` is `unsigned` / `good` / `bad` / `unknown`. (`unsigned`
    /// only appears if the caller hands us a payload with no signature
    /// — for `multipart/signed` it should always be one of the other
    /// three.)
    func verifyDetached(
        signedBytes: Data,
        signature: Data
    ) async throws -> (
        status: String,
        signerFingerprint: String?,
        signerKeyId: String?,
        signerUid: String?
    ) {
        try await call { proxy, cont in
            proxy.verifyDetached(
                signedBytes: signedBytes,
                armoredSignature: signature
            ) { status, fp, kid, uid, e in
                if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(returning: (status, fp, kid, uid))
                }
            }
        }
    }

    func encrypt(
        plaintext: Data,
        recipientFingerprints: [String],
        signerFingerprint: String?,
        armor: Bool
    ) async throws -> Data {
        try await call { proxy, cont in
            proxy.encrypt(
                plaintext: plaintext,
                recipientFingerprints: recipientFingerprints,
                signerFingerprint: signerFingerprint,
                armor: armor
            ) { ct, invalid, needsFp, needsUid, needsIsPin, e in
                if let ct = ct {
                    cont.resume(returning: ct)
                } else if !invalid.isEmpty {
                    cont.resume(throwing: XPCClientError.remote(
                        "no usable key for: \(invalid.joined(separator: ", "))"
                    ))
                } else if let needsFp = needsFp, let needsUid = needsUid {
                    cont.resume(throwing: XPCClientError.needsUnlock(
                        fingerprint: needsFp,
                        uid: needsUid,
                        isPin: needsIsPin
                    ))
                } else if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(throwing: XPCClientError.noResult)
                }
            }
        }
    }

    /// Write `secret` (the user-typed passphrase or PIN) into the
    /// tumpa agent cache. Subsequent `decryptVerify` / `encrypt` /
    /// `signDetached` calls hit the cache and complete without
    /// re-prompting. Used by the in-Mail unlock popover after the
    /// user submits.
    func cachePassphrase(
        fingerprint: String,
        isPin: Bool,
        secret: Data
    ) async throws {
        try await call { proxy, cont in
            proxy.cachePassphrase(
                fingerprint: fingerprint,
                isPin: isPin,
                secret: secret
            ) { ok, e in
                if ok {
                    cont.resume(returning: ())
                } else if let e = e {
                    cont.resume(throwing: XPCClientError.remote(e.localizedDescription))
                } else {
                    cont.resume(throwing: XPCClientError.noResult)
                }
            }
        }
    }

    // MARK: - Helpers

    /// Common shape: take the proxy + a continuation, dispatch to the
    /// XPC remote, surface the result on the continuation. Centralises
    /// the connection-lookup error path so each typed wrapper above
    /// stays small.
    private func call<T>(
        _ body: @escaping (TumpaCryptoXPC, CheckedContinuation<T, Error>) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            do {
                try body(proxy(), cont)
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

}
