// SPDX-License-Identifier: GPL-3.0-or-later
//
// Swift implementation of the UniFFI-defined `SecretProvider`
// callback interface from `tumpa-uniffi`. Bridges libtumpa's secret
// requests to the user's secret stores.
//
// THREE TIER LOOKUP:
//
//   1. **Transient slot** — the in-memory `TumpaTransientStore`,
//      populated by the popover-driven unlock flow when the user
//      types their passphrase / PIN. The secret stays here until a
//      crypto op uses it: success → promoted to the agent; failure →
//      cleared. **NEVER hits disk.** This is what protects smartcards
//      from PIN-attempt depletion: if the popover-typed PIN is wrong,
//      the SINGLE next decrypt call consumes 1 card attempt and the
//      transient slot is wiped, so the indexer's subsequent decode
//      calls don't replay the wrong PIN.
//
//   2. **Agent socket cache** — `~/.tumpa/agent.sock`, the persistent
//      cache shared with tcli / tclig / tpass. Populated by tumpa-cli
//      (and by the promote-on-success path here). Read-only on misses.
//
//   3. **Env-var fallback** — `TUMPA_PASSPHRASE` for software keys.
//      Used only when set (testing / scripted runs).
//
// **No pinentry-mac fallback.** pinentry-mac requires Aqua-session
// access; the .appex's hard-sandboxed launchd context can't provide
// it. The popover (rendered inside Mail's window, which IS in the
// user's Aqua session) replaces it.
//
// PROMOTE / CLEAR FLOW:
//
//   - LibtumpaRunner.signDetached / encrypt / decryptVerify each
//     wrap their FFI call with provider.promoteLastServedIfTransient
//     on Ok and provider.clearLastServedIfTransient on Err. This
//     means a wrong-passphrase or wrong-PIN attempt costs at most
//     one card attempt counter slot, not the whole flood of
//     indexer-driven decode calls.

import Foundation
import os.log

private let log = Logger(
    subsystem: "in.kushaldas.tumpamail.crypto",
    category: "secret-provider"
)

/// In-memory map of unverified secrets, keyed by the slot-namespaced
/// agent cache key (`pin:<fp>` / `passphrase:<fp>`). Populated by the
/// popover via `cachePassphrase` XPC. Drained by SecretProvider on
/// crypto-op success/failure. NEVER written to disk.
final class TumpaTransientStore {

    static let shared = TumpaTransientStore()

    private var entries: [String: [UInt8]] = [:]
    private let lock = NSLock()

    private init() {}

    /// Insert or replace an entry. Used by the popover's
    /// `cachePassphrase` XPC handler.
    func put(cacheKey: String, secret: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        entries[cacheKey] = secret
    }

    /// Read without consuming. Used by SecretProvider when libtumpa
    /// asks for a secret. The entry stays in the store so a single
    /// libtumpa op (which may invoke the callback more than once on
    /// internal retries / card-first-then-software fallback) can
    /// re-read it.
    func peek(cacheKey: String) -> [UInt8]? {
        lock.lock(); defer { lock.unlock() }
        return entries[cacheKey]
    }

    /// Remove and return. Used by promote-on-success (we move it to
    /// the agent) and clear-on-failure (we discard it).
    @discardableResult
    func take(cacheKey: String) -> [UInt8]? {
        lock.lock(); defer { lock.unlock() }
        return entries.removeValue(forKey: cacheKey)
    }
}

/// The Tumpa-Mail-side implementation of the Rust `SecretProvider`
/// trait. Created once per `TumpaCryptoService` instance and passed
/// into every libtumpa call that may need to unlock a key.
final class TumpaSecretProvider: SecretProvider {

    /// Side-channel state recording which cache key + source the
    /// most recent `passphraseForKey` / `pinForCard` call served.
    /// `LibtumpaRunner` calls `promoteLastServedIfTransient` /
    /// `clearLastServedIfTransient` after each crypto op to either
    /// move the transient secret to the agent or wipe it.
    private var lastServed: LastServed?
    private let lastServedLock = NSLock()

    private struct LastServed {
        let cacheKey: String
        let source: Source
        enum Source { case transient, agent, env }
    }

    // MARK: - SecretProvider conformance

    func passphraseForKey(fingerprint: String, uid: String) throws -> Data {
        log.info("passphraseForKey fp=\(fingerprint, privacy: .public)")
        let bytes = try acquire(
            cacheKey: TumpaAgentClient.passphraseKey(forFingerprint: fingerprint),
            envVar: "TUMPA_PASSPHRASE"
        )
        return Data(bytes)
    }

    func pinForCard(cardSerial: String, keyFingerprint: String, uid: String) throws -> Data {
        log.info("pinForCard card=\(cardSerial, privacy: .public) key=\(keyFingerprint, privacy: .public)")
        let bytes = try acquire(
            cacheKey: TumpaAgentClient.pinKey(forFingerprint: keyFingerprint),
            envVar: nil // TUMPA_PASSPHRASE doesn't apply to card PINs.
        )
        return Data(bytes)
    }

    // MARK: - Promote / clear (called by LibtumpaRunner)

    /// Called after a libtumpa crypto op SUCCEEDED. If the secret we
    /// served came from the transient store, write it to the agent
    /// (so tcli / tpass / future Mail decode calls reuse it without
    /// re-prompting) and wipe the transient slot.
    ///
    /// Idempotent. Safe to call when no secret was needed.
    func promoteLastServedIfTransient() {
        let captured: LastServed? = {
            lastServedLock.lock(); defer { lastServedLock.unlock() }
            let v = lastServed
            lastServed = nil
            return v
        }()
        guard let last = captured, last.source == .transient else { return }
        if let secret = TumpaTransientStore.shared.take(cacheKey: last.cacheKey) {
            let ok = TumpaAgentClient.put(cacheKey: last.cacheKey, secret: secret)
            log.info("promoted transient → agent for \(last.cacheKey, privacy: .public) ok=\(ok)")
        }
    }

    /// Called after a libtumpa crypto op FAILED. If we served a
    /// transient secret, wipe it — so the popover-typed value
    /// doesn't re-fire on the next decode attempt and burn another
    /// card attempt counter slot.
    ///
    /// Idempotent.
    func clearLastServedIfTransient() {
        let captured: LastServed? = {
            lastServedLock.lock(); defer { lastServedLock.unlock() }
            let v = lastServed
            lastServed = nil
            return v
        }()
        guard let last = captured, last.source == .transient else { return }
        TumpaTransientStore.shared.take(cacheKey: last.cacheKey)
        log.info("cleared transient for \(last.cacheKey, privacy: .public) (op failed)")
    }

    // MARK: - Internal

    private func acquire(cacheKey: String, envVar: String?) throws -> [UInt8] {
        // 1. Transient — popover-typed, unverified.
        if let transient = TumpaTransientStore.shared.peek(cacheKey: cacheKey) {
            log.info("transient HIT for \(cacheKey, privacy: .public)")
            recordLastServed(cacheKey: cacheKey, source: .transient)
            return transient
        }

        // 2. Agent — verified by past use, persistent.
        if let cached = TumpaAgentClient.lookup(cacheKey: cacheKey) {
            log.info("agent cache HIT for \(cacheKey, privacy: .public)")
            recordLastServed(cacheKey: cacheKey, source: .agent)
            return cached
        }

        // 3. Env var — testing / scripted only.
        if let env = envVar,
           let value = ProcessInfo.processInfo.environment[env],
           !value.isEmpty {
            log.info("env-var HIT (\(env, privacy: .public))")
            recordLastServed(cacheKey: cacheKey, source: .env)
            // Don't cache env-var values either — they may be wrong.
            // The agent will get populated naturally on first
            // successful op via the transient promotion path (the
            // env hit is treated like a transient hit in that
            // dimension).
            return Array(value.utf8)
        }

        log.info("no secret available — popover will prompt")
        // No `lastServed` recorded — there's nothing to promote or
        // clear when libtumpa errors out from this call.
        recordNoServed()
        throw SecretProviderError.Cancelled
    }

    private func recordLastServed(cacheKey: String, source: LastServed.Source) {
        lastServedLock.lock(); defer { lastServedLock.unlock() }
        lastServed = LastServed(cacheKey: cacheKey, source: source)
    }

    private func recordNoServed() {
        lastServedLock.lock(); defer { lastServedLock.unlock() }
        lastServed = nil
    }
}

// MARK: - Agent socket client

/// Client for `~/.tumpa/agent.sock` — the cache shared with tcli /
/// tclig / tpass.
///
/// Read-and-write: the popover-driven unlock writes here ONLY AFTER
/// the secret has been verified by a successful libtumpa op (the
/// promote-on-success path in `TumpaSecretProvider`). Connection
/// failures (agent not running, socket missing, protocol mismatch)
/// are silent — agent absence is a normal state, not an error.
enum TumpaAgentClient {

    /// Cache-key namespace for software-key passphrases. Matches
    /// `tumpa-cli/src/pinentry.rs:cache_key_for_slot(... CacheSlot::Passphrase)`.
    static func passphraseKey(forFingerprint fp: String) -> String {
        "passphrase:\(fp.uppercased())"
    }

    /// Cache-key namespace for smartcard PINs. Matches
    /// `tumpa-cli/src/pinentry.rs:cache_key_for_slot(... CacheSlot::Pin)`.
    static func pinKey(forFingerprint fp: String) -> String {
        "pin:\(fp.uppercased())"
    }

    /// Look up a cached secret. Returns `nil` if the agent isn't
    /// running, the socket is unreachable, the key is not cached,
    /// or the protocol response is unparseable.
    static func lookup(cacheKey: String) -> [UInt8]? {
        guard let response = exchange(request: "GET_PASSPHRASE \(cacheKey)\n") else {
            return nil
        }
        if response == "NOT_FOUND" { return nil }
        guard let b64 = response.dropPrefix("PASSPHRASE ") else { return nil }
        guard let decoded = Data(base64Encoded: String(b64)) else { return nil }
        return Array(decoded)
    }

    /// Write `secret` into the agent cache under `cacheKey`. Caller
    /// MUST have verified the secret with a real libtumpa op first
    /// (typically via the transient → agent promotion path in
    /// `TumpaSecretProvider`). Caching unverified secrets can
    /// permanently lock smartcards via PIN-attempt depletion.
    @discardableResult
    static func put(cacheKey: String, secret: [UInt8]) -> Bool {
        let b64 = Data(secret).base64EncodedString()
        let response = exchange(request: "PUT_PASSPHRASE \(cacheKey) \(b64)\n")
        return response == "OK"
    }

    /// Connect → write → read one Assuan-shaped line → close.
    private static func exchange(request: String) -> String? {
        guard let socketPath = defaultSocketPath() else { return nil }
        guard FileManager.default.fileExists(atPath: socketPath) else { return nil }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            pathBytes.withUnsafeBytes { src in
                _ = memcpy(dst.baseAddress, src.baseAddress, src.count)
            }
        }

        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sap in
                Darwin.connect(fd, sap, len)
            }
        }
        guard rc == 0 else { return nil }

        var tv = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let written = request.withCString { cstr in
            Darwin.write(fd, cstr, strlen(cstr))
        }
        guard written > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let n = buffer.withUnsafeMutableBufferPointer { ptr in
            Darwin.read(fd, ptr.baseAddress, ptr.count)
        }
        guard n > 0 else { return nil }
        return String(decoding: buffer.prefix(Int(n)), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func defaultSocketPath() -> String? {
        let home = NSHomeDirectory()
        guard !home.isEmpty else { return nil }
        return "\(home)/.tumpa/agent.sock"
    }
}

private extension String {
    func dropPrefix(_ prefix: String) -> Substring? {
        guard self.hasPrefix(prefix) else { return nil }
        return self.dropFirst(prefix.count)
    }
}
