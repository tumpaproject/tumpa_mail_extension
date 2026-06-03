// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for the per-address signing / encryption key override
// store. This is the shared source of truth for the host's Key
// Selection pane (writes) and the .appex's OutgoingSecurityHandler
// (reads), so the normalization rules must match exactly: emails are
// case-insensitive, a nil/empty fingerprint clears the entry, and the
// two override maps (signing vs encryption) are independent.

import XCTest

final class TumpaKeyOverridesTests: XCTestCase {

    /// A throwaway in-memory-ish UserDefaults suite per test so we
    /// never touch the real App Group plist.
    private func freshDefaults() -> UserDefaults {
        let suite = "test.tumpa.overrides.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: suite)!
        d.removePersistentDomain(forName: suite)
        return d
    }

    func testRoundTripSigningAndEncryptionAreIndependent() {
        let d = freshDefaults()
        let fpSign = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
        let fpEnc = "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"

        TumpaKeyOverrides.setSigning(fpSign, forEmail: "alice@example.com", in: d)
        TumpaKeyOverrides.setEncryption(fpEnc, forEmail: "alice@example.com", in: d)

        XCTAssertEqual(
            TumpaKeyOverrides.signingFingerprint(forEmail: "alice@example.com", in: d),
            fpSign
        )
        XCTAssertEqual(
            TumpaKeyOverrides.encryptionFingerprint(forEmail: "alice@example.com", in: d),
            fpEnc
        )
    }

    func testEmailMatchingIsCaseAndWhitespaceInsensitive() {
        let d = freshDefaults()
        let fp = "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333"
        TumpaKeyOverrides.setSigning(fp, forEmail: "Alice@Example.COM", in: d)

        // Lookups normalize the same way the writer did.
        XCTAssertEqual(
            TumpaKeyOverrides.signingFingerprint(forEmail: "alice@example.com", in: d),
            fp
        )
        XCTAssertEqual(
            TumpaKeyOverrides.signingFingerprint(forEmail: "  ALICE@EXAMPLE.COM  ", in: d),
            fp
        )
    }

    func testNilOrEmptyFingerprintClearsTheEntry() {
        let d = freshDefaults()
        let fp = "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
        TumpaKeyOverrides.setEncryption(fp, forEmail: "bob@example.com", in: d)
        XCTAssertNotNil(TumpaKeyOverrides.encryptionFingerprint(forEmail: "bob@example.com", in: d))

        TumpaKeyOverrides.setEncryption(nil, forEmail: "bob@example.com", in: d)
        XCTAssertNil(TumpaKeyOverrides.encryptionFingerprint(forEmail: "bob@example.com", in: d))

        TumpaKeyOverrides.setEncryption(fp, forEmail: "bob@example.com", in: d)
        TumpaKeyOverrides.setEncryption("", forEmail: "bob@example.com", in: d)
        XCTAssertNil(TumpaKeyOverrides.encryptionFingerprint(forEmail: "bob@example.com", in: d))
    }

    func testUnsetAddressReturnsNil() {
        let d = freshDefaults()
        XCTAssertNil(TumpaKeyOverrides.signingFingerprint(forEmail: "nobody@example.com", in: d))
        XCTAssertNil(TumpaKeyOverrides.encryptionFingerprint(forEmail: "nobody@example.com", in: d))
    }

    func testNilDefaultsIsSafe() {
        // The .appex constructs `UserDefaults(suiteName:)` which is
        // nullable; the accessors must no-op rather than crash.
        XCTAssertNil(TumpaKeyOverrides.signingFingerprint(forEmail: "x@y.z", in: nil))
        TumpaKeyOverrides.setSigning("AAAA", forEmail: "x@y.z", in: nil) // must not crash
    }
}
