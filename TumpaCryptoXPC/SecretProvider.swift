// SPDX-License-Identifier: GPL-3.0-or-later
//
// Swift implementation of the UniFFI-defined `SecretProvider`
// callback interface from `tumpa-uniffi`. Bridges libtumpa's secret
// requests to the user's secret stores.
//
// LOOKUP ORDER:
//
//   1. **Transient slot** — the in-memory `TumpaTransientStore`,
//      populated by the popover-driven unlock flow when the agent
//      can't pinentry (headless / `PINENTRY_UNAVAILABLE`) and the
//      .appex falls back to its in-Mail SwiftUI popover. Drained by
//      `cacheVerifiedSecret` on successful verify; drained by
//      `clearLastServedIfTransient` on libtumpa op failure (covers
//      the rare post-verify crypto error + the verify-Err path).
//
//   2. **Agent `GET_OR_PROMPT`** — primary path. Cache lookup,
//      falling back to agent-side `pinentry-mac` on a desktop
//      session. On `PINENTRY_UNAVAILABLE` we drop to step 3 / 4 / 5;
//      on `CANCELLED` we abort hard (user explicitly declined).
//
//   3. **Env-var fallback** — `TUMPA_PASSPHRASE` for software keys.
//      Used only when set (testing / scripted runs).
//
//   4. Throw `SecretProviderError.Cancelled` → libtumpa raises
//      `SecretUnavailable` → .appex shows in-Mail popover.
//
// CACHE-AFTER-VERIFY:
//
//   The Rust UniFFI wrapper runs a pre-op verify
//   (`wecanencrypt::card::verify_user_pin` for cards,
//   `wecanencrypt::verify_software_passphrase` for software keys)
//   immediately after the SecretProvider returns a value. On verify
//   Ok, the wrapper calls `cacheVerifiedSecret(fingerprint, isPin,
//   secret)` HERE, which `PUT_PASSPHRASE`s the now-known-correct
//   secret into the agent and drains the transient slot. On verify
//   Err, the wrapper raises `SecretUnavailable` so the user
//   re-prompts; transient is drained by the runner's catch block
//   (`clearLastServedIfTransient`) to keep Mail's library-indexer
//   fan-out from replaying the wrong secret across N decode calls.

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
        /// Once `cacheVerifiedSecret` has handled this entry, mark it
        /// `verified` so the runner-level promote/clear callbacks
        /// stop touching the now-canonical agent cache + drained
        /// transient.
        var verified: Bool
        enum Source { case transient, agent, env }
    }

    // MARK: - SecretProvider conformance

    func passphraseForKey(fingerprint: String, uid: String) throws -> Data {
        log.info("passphraseForKey fp=\(fingerprint, privacy: .public)")
        let bytes = try acquire(
            cacheKey: TumpaAgentClient.passphraseKey(forFingerprint: fingerprint),
            envVar: "TUMPA_PASSPHRASE",
            uid: uid,
            isPin: false
        )
        return Data(bytes)
    }

    func pinForCard(cardSerial: String, keyFingerprint: String, uid: String) throws -> Data {
        log.info("pinForCard card=\(cardSerial, privacy: .public) key=\(keyFingerprint, privacy: .public)")
        let bytes = try acquire(
            cacheKey: TumpaAgentClient.pinKey(forFingerprint: keyFingerprint),
            envVar: nil, // TUMPA_PASSPHRASE doesn't apply to card PINs.
            uid: uid,
            isPin: true
        )
        return Data(bytes)
    }

    /// `SecretProvider` trait method: invoked by the Rust UniFFI
    /// wrapper after a successful pre-op verify. Writes the
    /// now-known-correct secret into the agent cache and drains the
    /// transient slot if it was the source — so the agent becomes
    /// the canonical store for subsequent calls (Mail's library
    /// indexer fan-out will hit the cache, no re-prompt).
    func cacheVerifiedSecret(fingerprint: String, isPin: Bool, secret: Data) {
        let cacheKey = isPin
            ? TumpaAgentClient.pinKey(forFingerprint: fingerprint)
            : TumpaAgentClient.passphraseKey(forFingerprint: fingerprint)
        let bytes = Array(secret)
        let ok = TumpaAgentClient.put(cacheKey: cacheKey, secret: bytes)
        log.info(
            "cacheVerifiedSecret PUT \(cacheKey, privacy: .public) ok=\(ok)"
        )
        // Drain transient — ok if it wasn't the source (no-op).
        TumpaTransientStore.shared.take(cacheKey: cacheKey)
        // Mark as verified so the runner's promote-on-success hook
        // doesn't double-PUT.
        lastServedLock.lock(); defer { lastServedLock.unlock() }
        if let last = lastServed, last.cacheKey == cacheKey {
            lastServed = LastServed(
                cacheKey: last.cacheKey,
                source: last.source,
                verified: true
            )
        }
    }

    // MARK: - Promote / clear (called by LibtumpaRunner)

    /// Runner-level hook called after a libtumpa op SUCCEEDED.
    /// `cacheVerifiedSecret` already PUT to the agent and drained
    /// the transient as part of the pre-op verify, so this is a
    /// no-op when the lastServed has already been marked verified.
    /// Kept for back-compat with `LibtumpaRunner` and as a defensive
    /// late-promote in case a libtumpa code path returns Ok without
    /// having gone through the verify-then-cache hand-off (e.g. a
    /// future op that doesn't use SecretProvider).
    func promoteLastServedIfTransient() {
        let captured: LastServed? = {
            lastServedLock.lock(); defer { lastServedLock.unlock() }
            let v = lastServed
            lastServed = nil
            return v
        }()
        guard let last = captured, !last.verified, last.source == .transient else { return }
        if let secret = TumpaTransientStore.shared.take(cacheKey: last.cacheKey) {
            let ok = TumpaAgentClient.put(cacheKey: last.cacheKey, secret: secret)
            log.info(
                "late-promote transient → agent for \(last.cacheKey, privacy: .public) ok=\(ok)"
            )
        }
    }

    /// Runner-level hook called after a libtumpa op FAILED. Wipes
    /// the transient slot to keep Mail's library-indexer fan-out
    /// from replaying a wrong-secret entry across every encrypted
    /// message in the inbox (which would burn one card attempt
    /// counter slot per message).
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

    private func acquire(
        cacheKey: String,
        envVar: String?,
        uid: String,
        isPin: Bool
    ) throws -> [UInt8] {
        // 1. Transient — populated by the in-Mail popover fallback
        // when the agent reports PINENTRY_UNAVAILABLE. Checked
        // first so a popover-typed value drives the next libtumpa
        // op without round-tripping back to the (still headless)
        // agent.
        if let transient = TumpaTransientStore.shared.peek(cacheKey: cacheKey) {
            log.info("transient HIT for \(cacheKey, privacy: .public)")
            recordLastServed(cacheKey: cacheKey, source: .transient)
            return transient
        }

        // 2. Agent GET_OR_PROMPT — primary path. Cache lookup,
        // falling back to agent-side `pinentry-mac` on a desktop
        // session.
        let description = describeUnlock(cacheKey: cacheKey, uid: uid, isPin: isPin)
        let promptText = isPin ? "PIN" : "Passphrase"
        switch TumpaAgentClient.getOrPrompt(
            cacheKey: cacheKey,
            description: description,
            prompt: promptText
        ) {
        case .passphrase(let bytes):
            log.info("agent GET_OR_PROMPT HIT for \(cacheKey, privacy: .public)")
            recordLastServed(cacheKey: cacheKey, source: .agent)
            return bytes
        case .cancelled:
            // User explicitly clicked Cancel. Do NOT fall back to
            // env / popover — Cancelled means "I don't want to
            // unlock right now."
            log.info("agent GET_OR_PROMPT cancelled for \(cacheKey, privacy: .public)")
            recordNoServed()
            throw SecretProviderError.Cancelled
        case .unavailable(let raw):
            log.info(
                "agent GET_OR_PROMPT unavailable for \(cacheKey, privacy: .public) raw=\(raw, privacy: .public) — falling back"
            )
        case .error(let msg):
            log.error(
                "agent GET_OR_PROMPT err for \(cacheKey, privacy: .public): \(msg, privacy: .public)"
            )
        case .noAgent:
            log.info("no agent socket — falling back")
        }

        // 3. Env var — testing / scripted only. After we serve it,
        // the wrapper's pre-op verify + cacheVerifiedSecret will
        // promote it to the agent if correct.
        if let env = envVar,
           let value = ProcessInfo.processInfo.environment[env],
           !value.isEmpty {
            log.info("env-var HIT (\(env, privacy: .public))")
            recordLastServed(cacheKey: cacheKey, source: .env)
            return Array(value.utf8)
        }

        // 4. No secret available. Throwing Cancelled lifts to
        // libtumpa.SecretUnavailable → .appex's needsUnlock →
        // in-Mail SwiftUI popover fallback (which writes to
        // TumpaTransientStore via the cachePassphrase XPC and then
        // test-signs to drive the verify flow).
        log.info("no secret available — popover will prompt")
        recordNoServed()
        throw SecretProviderError.Cancelled
    }

    /// Build a multi-line description string for the agent's
    /// pinentry. Mirrors the descriptions tumpa-cli builds in
    /// `gpg::sign::prompt_card_pin` so the dialog feels consistent
    /// across CLI and Mail.
    private func describeUnlock(cacheKey: String, uid: String, isPin: Bool) -> String {
        if isPin {
            return "Apple Mail wants to unlock your OpenPGP smartcard.\n\nKey: \(uid)"
        } else {
            return "Apple Mail wants to unlock your OpenPGP key.\n\nKey: \(uid)"
        }
    }

    private func recordLastServed(cacheKey: String, source: LastServed.Source) {
        lastServedLock.lock(); defer { lastServedLock.unlock() }
        lastServed = LastServed(cacheKey: cacheKey, source: source, verified: false)
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

    /// Outcome of an agent `GET_OR_PROMPT` round-trip.
    enum GetOrPromptOutcome {
        /// Agent returned a value (cache hit OR fresh pinentry result).
        case passphrase([UInt8])
        /// User clicked Cancel in the agent's pinentry dialog.
        /// Caller MUST NOT fall back to another prompt source.
        case cancelled
        /// Agent has no usable pinentry (headless server, no
        /// `pinentry-mac` installed, or cache miss with no GUI).
        /// Caller should fall through to its own fallback path.
        /// Carries the raw response wire string ("NOT_FOUND" or
        /// "PINENTRY_UNAVAILABLE") so log inspection can tell apart
        /// "request didn't parse" from "no pinentry".
        case unavailable(raw: String)
        /// Agent reported a structured error running pinentry.
        /// Caller MAY fall back; the message is for diagnostics.
        case error(String)
        /// No agent socket / agent not running.
        case noAgent
    }

    /// Issue `GET_OR_PROMPT`. The exchange uses a long read timeout
    /// (10 minutes) because pinentry is interactive — the user
    /// typing into the dialog is part of the round-trip.
    static func getOrPrompt(
        cacheKey: String,
        description: String,
        prompt: String
    ) -> GetOrPromptOutcome {
        let descB64 = Data(description.utf8).base64EncodedString()
        let promptB64 = Data(prompt.utf8).base64EncodedString()
        let req = "GET_OR_PROMPT \(cacheKey) \(descB64) \(promptB64)\n"
        guard let response = exchange(request: req, readTimeoutSeconds: 600) else {
            return .noAgent
        }
        if response == "NOT_FOUND" || response == "PINENTRY_UNAVAILABLE" {
            return .unavailable(raw: response)
        }
        if response == "CANCELLED" {
            return .cancelled
        }
        if let b64 = response.dropPrefix("PASSPHRASE "),
           let decoded = Data(base64Encoded: String(b64))
        {
            return .passphrase(Array(decoded))
        }
        if let b64 = response.dropPrefix("ERR "),
           let decoded = Data(base64Encoded: String(b64)),
           let msg = String(data: decoded, encoding: .utf8)
        {
            return .error(msg)
        }
        return .noAgent
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
    /// `readTimeoutSeconds` defaults to 2 (matches today's
    /// fast-path shape for `GET_PASSPHRASE` / `PUT_PASSPHRASE`); the
    /// `GET_OR_PROMPT` path bumps it to ~600 because the user
    /// typing into pinentry is part of the round-trip.
    private static func exchange(request: String, readTimeoutSeconds: Int = 2) -> String? {
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

        var tv = timeval(tv_sec: readTimeoutSeconds, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        // Send timeout stays short — we're never blocked writing the
        // request line.
        var sendTv = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sendTv, socklen_t(MemoryLayout<timeval>.size))

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
