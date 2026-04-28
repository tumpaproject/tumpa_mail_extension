// SPDX-License-Identifier: GPL-3.0-or-later
//
// Process-level glue around the `tclig` binary. One method per
// `TumpaCryptoXPC` operation, returning either the output bytes plus
// parsed status lines or a typed error. Every method:
//   1. Locates `tclig` via `tcligURL()` (PATH lookup + Homebrew
//      fallbacks).
//   2. Spawns it with stdin/stdout/stderr pipes.
//   3. Reads stdout as the operation's payload (signature, ciphertext,
//      plaintext) and stderr as the GnuPG-shape `[GNUPG:]` status
//      stream which `StatusLineParser` interprets.
//   4. Waits for exit; non-zero exit → `TclibError`.
//
// The runner runs inside the XPC service bundle, which is *not*
// sandboxed, so spawning + PATH lookups + `~/.tumpa/agent.sock` are
// all reachable. Both the .appex and the host UI hit the same XPC
// service rather than reimplementing this logic twice.

import Foundation

public enum TclibError: Error, LocalizedError {
    case binaryNotFound
    case versionTooOld(found: String, required: String)
    case spawnFailed(String)
    case nonZeroExit(code: Int32, stderr: String)
    case parseFailed(String)
    case invalidRecipients([String])

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            return "`tclig` not found on PATH. Install tumpa-cli (≥ 0.5.0) via Homebrew."
        case .versionTooOld(let found, let required):
            return "tumpa-cli is too old (\(found)); Tumpa Mail requires \(required) or newer."
        case .spawnFailed(let msg):
            return "Could not run tclig: \(msg)"
        case .nonZeroExit(let code, let stderr):
            return "tclig exited \(code). \(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .parseFailed(let msg):
            return "tclig output unreadable: \(msg)"
        case .invalidRecipients(let recips):
            return "no usable key for recipient(s): \(recips.joined(separator: ", "))"
        }
    }
}

/// Required `tumpa-cli` minimum version for the new flags
/// (`--digest-algo`, `--clearsign`, `--verify-decrypt`, `INV_RECP`).
public let TumpaMailRequiredTcligVersion = "0.5.0"

public final class TclibRunner {

    public init() {}

    // MARK: - Binary discovery

    /// Find `tclig` on the user's PATH, with Homebrew fallbacks for
    /// the common install locations. The XPC service inherits the
    /// user's environment but a launchd-activated process may have a
    /// minimal PATH; the fallbacks cover that.
    public func tcligURL() throws -> URL {
        // 1. Honor TUMPA_TCLIG_PATH if set (test override).
        if let override = ProcessInfo.processInfo.environment["TUMPA_TCLIG_PATH"],
           FileManager.default.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }

        // 2. PATH lookup via /usr/bin/which. Reliable cross-shell.
        if let viaWhich = which("tclig") {
            return viaWhich
        }

        // 3. Homebrew fallbacks. Apple Silicon and Intel paths.
        for candidate in [
            "/opt/homebrew/bin/tclig",
            "/usr/local/bin/tclig",
            "\(NSHomeDirectory())/.cargo/bin/tclig",
        ] {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate)
            }
        }

        throw TclibError.binaryNotFound
    }

    private func which(_ name: String) -> URL? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        proc.arguments = [name]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do { try proc.run() } catch { return nil }
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let path = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return path.isEmpty ? nil : URL(fileURLWithPath: path)
    }

    // MARK: - Version probe

    public func version() throws -> String {
        let result = try run(args: ["--version"], stdin: nil)
        let text = String(data: result.stdout, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !text.isEmpty else {
            throw TclibError.parseFailed("`tclig --version` produced no output")
        }
        return text
    }

    /// Throw `versionTooOld` if the running `tclig` is older than
    /// `TumpaMailRequiredTcligVersion`. Done once at host-app launch
    /// and once at the start of each XPC connection so the user gets
    /// a clear message instead of cryptic "unknown flag" errors.
    public func ensureVersionAtLeast(_ required: String) throws {
        let raw = try version()                       // e.g. "tclig 0.5.0"
        let actual = raw.split(separator: " ").last.map(String.init) ?? raw
        if !semverAtLeast(actual: actual, required: required) {
            throw TclibError.versionTooOld(found: actual, required: required)
        }
    }

    /// Naive `MAJOR.MINOR.PATCH` comparison; sufficient for our 0.x
    /// version line. Anything we can't parse compares as "older" so
    /// we err on the side of refusing to start.
    func semverAtLeast(actual: String, required: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.split(separator: ".").compactMap { Int($0) }
        }
        let a = parts(actual)
        let r = parts(required)
        for i in 0..<max(a.count, r.count) {
            let av = i < a.count ? a[i] : 0
            let rv = i < r.count ? r[i] : 0
            if av != rv { return av > rv }
        }
        return true
    }

    // MARK: - Sign (detached, hash-aware)

    public struct DetachedSignOutput {
        public let armoredSignature: Data
        /// What hash the signature actually used. May differ from the
        /// requested digest if a card produced the signature.
        public let hashAlgorithm: String
    }

    public func signDetached(
        body: Data,
        signerFingerprint: String,
        digest: String
    ) throws -> DetachedSignOutput {
        let result = try run(
            args: [
                "--detach-sign", "--armor",
                "-u", signerFingerprint,
                "--digest-algo", digest,
            ],
            stdin: body
        )
        let parsed = StatusLineParser.parse(result.stderr)
        let actualDigest = parsed.sigCreatedHash ?? digest
        return DetachedSignOutput(
            armoredSignature: result.stdout,
            hashAlgorithm: actualDigest
        )
    }

    // MARK: - Encrypt (multi-recipient, optional sign-then-encrypt)

    public func encrypt(
        plaintext: Data,
        recipients: [String],
        signerFingerprint: String?,
        armor: Bool
    ) throws -> Data {
        // tclig requires -o for encrypt today; tee through a tempfile.
        let outURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tumpa-mail-enc-\(UUID().uuidString).pgp")
        defer { try? FileManager.default.removeItem(at: outURL) }

        var args: [String] = ["--encrypt", "-o", outURL.path]
        if armor { args.append("--armor") }
        for r in recipients { args.append(contentsOf: ["-r", r]) }
        if let s = signerFingerprint {
            // Sign-then-encrypt single-pass: produces an OpenPGP
            // message with a one-pass signature + literal + signature
            // packets, equivalent to `gpg --sign --encrypt`. tclig
            // does card-first dispatch on the signing leg: when the
            // signer's key has a matching connected card, the inner
            // signature is produced on the card via
            // `wecanencrypt::card::sign_and_encrypt_to_multiple_on_card`;
            // otherwise tclig falls back to the software secret key
            // (with passphrase via pinentry). The XPC reply shape is
            // unchanged either way — the .appex doesn't observe which
            // backend produced the signature.
            args.append(contentsOf: ["--sign", "-u", s])
        }

        do {
            _ = try run(args: args, stdin: plaintext)
        } catch let TclibError.nonZeroExit(_, stderr) {
            // Surface the per-recipient INV_RECP names so the .appex
            // can highlight the failing chips in compose.
            let parsed = StatusLineParser.parse(stderr.data(using: .utf8) ?? Data())
            if !parsed.invalidRecipients.isEmpty {
                throw TclibError.invalidRecipients(parsed.invalidRecipients)
            }
            throw TclibError.nonZeroExit(code: -1, stderr: stderr)
        }

        return try Data(contentsOf: outURL)
    }

    // MARK: - Decrypt + verify

    public struct DecryptVerifyOutput {
        public let plaintext: Data
        /// One of "unsigned" / "good" / "bad" / "unknown" — matches
        /// `TumpaSignatureStatus`.
        public let signatureStatus: String
        public let signerFingerprint: String?
        public let signerKeyId: String?
        public let signerUid: String?
    }

    public func decryptVerify(ciphertext: Data) throws -> DecryptVerifyOutput {
        // Same tempfile dance as encrypt — `tclig --decrypt` accepts a
        // file argument; we pass stdin via "-" (the existing CLI
        // already supports it).
        let inURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tumpa-mail-dec-\(UUID().uuidString).pgp")
        try ciphertext.write(to: inURL)
        defer { try? FileManager.default.removeItem(at: inURL) }

        let result = try run(
            args: ["--decrypt", "--verify-decrypt", inURL.path],
            stdin: nil
        )
        let parsed = StatusLineParser.parse(result.stderr)

        let status: String
        if parsed.goodsigFingerprint != nil {
            status = TumpaSignatureStatus.good
        } else if parsed.badsigFingerprint != nil {
            status = TumpaSignatureStatus.bad
        } else if parsed.noPubKeyId != nil {
            status = TumpaSignatureStatus.unknown
        } else {
            status = TumpaSignatureStatus.unsigned
        }

        return DecryptVerifyOutput(
            plaintext: result.stdout,
            signatureStatus: status,
            signerFingerprint: parsed.goodsigFingerprint ?? parsed.badsigFingerprint,
            signerKeyId: parsed.noPubKeyId,
            signerUid: parsed.signerUid
        )
    }

    // MARK: - Verify detached

    public struct VerifyDetachedOutput {
        public let status: String
        public let signerFingerprint: String?
        public let signerUid: String?
    }

    public func verifyDetached(
        signedBytes: Data,
        signature: Data
    ) throws -> VerifyDetachedOutput {
        let sigURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tumpa-mail-sig-\(UUID().uuidString).asc")
        try signature.write(to: sigURL)
        defer { try? FileManager.default.removeItem(at: sigURL) }

        // `tclig --verify <sig> -` reads signed data from stdin per the
        // existing tclig contract.
        let result = try run(
            args: ["--verify", sigURL.path, "-"],
            stdin: signedBytes,
            allowNonZeroExit: true
        )
        // tclig is inconsistent about which pipe it writes the
        // `[GNUPG:]` status lines to: signing writes SIG_CREATED to
        // stderr, but `--verify` writes GOODSIG / BADSIG / NO_PUBKEY
        // to stdout (with the human-friendly "tcli: Good signature…"
        // text on stderr). Parse both so we don't lose the signer
        // fingerprint and UID on a successful verify.
        let parsed = StatusLineParser.parse(result.stdout + result.stderr)
        let status: String
        if parsed.goodsigFingerprint != nil {
            status = TumpaSignatureStatus.good
        } else if parsed.badsigFingerprint != nil {
            status = TumpaSignatureStatus.bad
        } else if parsed.noPubKeyId != nil {
            status = TumpaSignatureStatus.unknown
        } else if result.exitStatus == 0 {
            // Older tclig may not emit the status line; treat exit-0
            // as good and leave the signer fields nil.
            status = TumpaSignatureStatus.good
        } else {
            status = TumpaSignatureStatus.bad
        }
        return VerifyDetachedOutput(
            status: status,
            signerFingerprint: parsed.goodsigFingerprint ?? parsed.badsigFingerprint,
            signerUid: parsed.signerUid
        )
    }

    // MARK: - List keys

    /// List every key in the keystore.
    ///
    /// `isSecret` here means "software secret material is present in
    /// `~/.tumpa/keys.db`". A `false` value does **not** mean the key
    /// is unsignable — for card-backed keys the keystore holds only
    /// the public half and tcli routes signing through PCSC. The
    /// host UI's default-signer picker therefore lets the user tick
    /// any non-revoked / non-expired key; the actual sign attempt
    /// (card-first, software-fallback) decides at runtime whether
    /// signing is possible.
    public func listKeys() throws -> [TumpaKeyInfo] {
        let result = try run(
            args: ["--list-keys", "--with-colons"],
            stdin: nil
        )
        let text = String(data: result.stdout, encoding: .utf8) ?? ""
        return ColonListingParser.parse(text)
    }

    // MARK: - Subprocess plumbing

    struct ProcessOutput {
        let stdout: Data
        let stderr: Data
        let exitStatus: Int32
    }

    /// Spawn `tclig` with `args`, optionally feeding `stdin`. Captures
    /// stdout + stderr concurrently to avoid pipe-buffer deadlocks for
    /// large messages.
    func run(
        args: [String],
        stdin: Data?,
        allowNonZeroExit: Bool = false
    ) throws -> ProcessOutput {
        let url = try tcligURL()
        let proc = Process()
        proc.executableURL = url
        proc.arguments = args

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        proc.standardInput = stdinPipe
        proc.standardOutput = stdoutPipe
        proc.standardError = stderrPipe

        // Inherit env so TUMPA_KEYSTORE / TUMPA_PASSPHRASE / SSH_AUTH_SOCK
        // / DISPLAY / DBUS_SESSION_BUS_ADDRESS pass through to pinentry.

        do {
            try proc.run()
        } catch {
            throw TclibError.spawnFailed(error.localizedDescription)
        }

        // Drain stdout / stderr in background threads. Without this, a
        // multi-MB attachment's plaintext can fill the stdout pipe
        // buffer (~64 KB) and deadlock tclig.
        var stdoutData = Data()
        var stderrData = Data()
        let outQueue = DispatchQueue(label: "tumpa.tclig.stdout")
        let errQueue = DispatchQueue(label: "tumpa.tclig.stderr")
        let group = DispatchGroup()

        group.enter()
        outQueue.async {
            stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        errQueue.async {
            stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        if let stdin = stdin {
            try? stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
        }
        try? stdinPipe.fileHandleForWriting.close()

        proc.waitUntilExit()
        group.wait()

        if !allowNonZeroExit, proc.terminationStatus != 0 {
            let stderrText = String(data: stderrData, encoding: .utf8) ?? ""
            throw TclibError.nonZeroExit(
                code: proc.terminationStatus,
                stderr: stderrText
            )
        }

        return ProcessOutput(
            stdout: stdoutData,
            stderr: stderrData,
            exitStatus: proc.terminationStatus
        )
    }
}
