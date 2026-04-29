// SPDX-License-Identifier: GPL-3.0-or-later
//
// Smoke tests for the Swift side of the UniFFI bindings. The deep
// crypto round-trips (sign/verify, encrypt/decrypt, card dispatch)
// are covered by `openpgp/tumpa-uniffi/tests/smoke.rs` against
// fixture key material — that's the right layer because it exercises
// the same Rust entry points the Swift wrapper calls.
//
// What these tests cover instead:
//   - The static lib links and the bindings load (a missing symbol
//     manifests as a runtime crash on the first call into Rust).
//   - `listKeys()` against an empty keystore returns [].
//   - `resolveRecipients([])` against an empty keystore returns [:].
//   - `TumpaSignatureStatus` constants stay in sync (the .appex's
//     popover status switch keys on these).

import XCTest

final class LibtumpaRunnerTests: XCTestCase {

    /// Each test gets its own tempdir + TUMPA_KEYSTORE so they don't
    /// clobber the developer's real `~/.tumpa/keys.db`.
    private func withFreshKeystore<T>(_ body: () throws -> T) throws -> T {
        let dir = try FileManager.default.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: URL(fileURLWithPath: NSTemporaryDirectory()),
            create: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }

        let dbURL = dir.appendingPathComponent("keys.db")
        let prior = ProcessInfo.processInfo.environment["TUMPA_KEYSTORE"]
        setenv("TUMPA_KEYSTORE", dbURL.path, 1)
        defer {
            if let p = prior { setenv("TUMPA_KEYSTORE", p, 1) }
            else { unsetenv("TUMPA_KEYSTORE") }
        }

        return try body()
    }

    /// listKeys() against an empty keystore returns [] without
    /// throwing. Catches link-time / FFI marshalling errors at the
    /// boundary — if the static lib isn't linked correctly this
    /// crashes on first call.
    func testListKeysOnEmptyKeystoreReturnsEmpty() throws {
        let runner = LibtumpaRunner()
        let keys = try withFreshKeystore { try runner.listKeys() }
        XCTAssertEqual(keys.count, 0)
    }

    /// resolveRecipients on an empty input returns an empty
    /// dictionary — confirms the [String] / [String: String] FFI
    /// marshalling round-trips correctly.
    func testResolveRecipientsEmptyInput() throws {
        let runner = LibtumpaRunner()
        let resolved = try withFreshKeystore {
            try runner.resolveRecipients(emails: [])
        }
        XCTAssertTrue(resolved.isEmpty)
    }

    /// resolveRecipients against an empty keystore with real-looking
    /// emails returns no matches — exercises the "key not found"
    /// branch without needing a populated keystore.
    func testResolveRecipientsAgainstEmptyKeystoreFindsNothing() throws {
        let runner = LibtumpaRunner()
        let resolved = try withFreshKeystore {
            try runner.resolveRecipients(emails: [
                "alice@example.com",
                "bob@example.com",
            ])
        }
        XCTAssertTrue(resolved.isEmpty)
    }

    /// Status string constants the .appex's `decryptVerify` /
    /// `verifyDetached` reply paths populate. Pinned because
    /// `OutgoingSecurityHandler` matches on raw strings (no enum
    /// crosses XPC) — a typo would silently fall through to
    /// "decryptFailed" with no compile-time warning.
    func testSignatureStatusConstantsArePinned() {
        XCTAssertEqual(TumpaSignatureStatus.unsigned, "unsigned")
        XCTAssertEqual(TumpaSignatureStatus.good, "good")
        XCTAssertEqual(TumpaSignatureStatus.bad, "bad")
        XCTAssertEqual(TumpaSignatureStatus.unknown, "unknown")
    }

    /// describeKey on an unknown fingerprint surfaces a typed
    /// LibtumpaError. Pins the FFI surface used by the host UI's
    /// "Key details" sheet.
    func testDescribeKeyUnknownFingerprintThrowsTypedError() throws {
        let runner = LibtumpaRunner()
        try withFreshKeystore {
            XCTAssertThrowsError(
                try runner.describeKey(
                    fingerprint: "0000000000000000000000000000000000000000"
                )
            ) { error in
                guard let lib = error as? LibtumpaError else {
                    XCTFail("expected LibtumpaError, got \(type(of: error))")
                    return
                }
                // libtumpa's KeyNotFound flows through the FFI as
                // InvalidRecipients — the same shape the compose-side
                // recipient lookup uses, so callers can pattern-match
                // on a single variant for "we don't have that key".
                if case .invalidRecipients = lib { /* ok */ } else {
                    XCTFail("expected .invalidRecipients, got \(lib)")
                }
            }
        }
    }

    /// Verify-detached against bytes that aren't a valid OpenPGP
    /// signature surfaces a typed `LibtumpaError.crypto` — confirms
    /// the FFI -> Swift error translation. Exercising the error path
    /// is what our wrapper's `translate(_:)` is for.
    func testVerifyDetachedOnGarbageInputThrowsTypedError() throws {
        let runner = LibtumpaRunner()
        try withFreshKeystore {
            XCTAssertThrowsError(
                try runner.verifyDetached(
                    signedBytes: Data("hello".utf8),
                    signature: Data("not a signature".utf8)
                )
            ) { error in
                // The error must be a LibtumpaError, not an opaque
                // generated-binding error — that's the entire point
                // of the wrapper's translate(_:) shim.
                guard error is LibtumpaError else {
                    XCTFail("expected LibtumpaError, got \(type(of: error))")
                    return
                }
            }
        }
    }
}
