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
enum XPCClientError: Error, LocalizedError {
    case connectionInvalidated
    case remote(String)

    var errorDescription: String? {
        switch self {
        case .connectionInvalidated:
            return "Connection to the Tumpa Crypto XPC service was lost."
        case .remote(let msg):
            return msg
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

    func tcligVersion() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().tcligVersion { version, error in
                    if let v = version { cont.resume(returning: v) }
                    else if let e = error { cont.resume(throwing: XPCClientError.remote(e.localizedDescription)) }
                    else { cont.resume(throwing: XPCClientError.connectionInvalidated) }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

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
}
