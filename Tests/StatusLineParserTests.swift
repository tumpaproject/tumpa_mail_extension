// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for `StatusLineParser` and `ColonListingParser`. Pinned
// against the actual byte output of `tclig` 0.5.0 (PR #23) so the
// Mail extension's signer / recipient resolution doesn't drift if
// tclig's status-line emission rules change again.

import XCTest

final class StatusLineParserTests: XCTestCase {

    // MARK: - Detached `--verify`: GOODSIG + VALIDSIG

    /// `tclig --verify <sig> -` writes (verbatim, captured from a real
    /// run on 2026-04-28):
    ///
    ///     [GNUPG:] GOODSIG E3917C1325E60537 Kushal Das <kushal@civilized.systems>
    ///     [GNUPG:] VALIDSIG 37417ABF83C07691C565C434E3917C1325E60537
    ///     [GNUPG:] TRUST_FULLY 0 pgp
    ///
    /// We must capture both the 16-char key ID (GOODSIG) and the
    /// 40-char fingerprint (VALIDSIG) — the popover prefers the
    /// fingerprint, the fallback path uses the key ID.
    func testParsesGoodsigAndValidsigFromVerifyOutput() {
        let raw = """
            [GNUPG:] GOODSIG E3917C1325E60537 Kushal Das <kushal@civilized.systems>
            [GNUPG:] VALIDSIG 37417ABF83C07691C565C434E3917C1325E60537
            [GNUPG:] TRUST_FULLY 0 pgp
            """
        let s = StatusLineParser.parse(raw)
        XCTAssertEqual(s.goodsigFingerprint, "E3917C1325E60537",
                       "GOODSIG must yield the 16-char trailing key ID")
        XCTAssertEqual(s.validsigFingerprint,
                       "37417ABF83C07691C565C434E3917C1325E60537",
                       "VALIDSIG must yield the full 40-char fingerprint")
        XCTAssertEqual(s.signerUid, "Kushal Das <kushal@civilized.systems>")
        XCTAssertNil(s.badsigFingerprint)
        XCTAssertNil(s.noPubKeyId)
    }

    /// VALIDSIG values shorter or longer than 40 hex chars are
    /// rejected — defends against a malformed line poisoning the
    /// popover with a bogus fingerprint.
    func testValidsigRejectsMalformedFingerprint() {
        let cases = [
            "[GNUPG:] VALIDSIG 1234",                        // too short
            "[GNUPG:] VALIDSIG zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
            "[GNUPG:] VALIDSIG 37417ABF83C07691C565C434E3917C1325E60537AB", // too long
        ]
        for line in cases {
            let s = StatusLineParser.parse(line)
            XCTAssertNil(s.validsigFingerprint, "should reject: \(line)")
        }
    }

    /// VALIDSIG output is always uppercased so case-sensitive
    /// comparisons against the keystore (which stores fingerprints
    /// uppercase) don't drift.
    func testValidsigUppercasesFingerprint() {
        let raw = "[GNUPG:] VALIDSIG 37417abf83c07691c565c434e3917c1325e60537"
        let s = StatusLineParser.parse(raw)
        XCTAssertEqual(s.validsigFingerprint,
                       "37417ABF83C07691C565C434E3917C1325E60537")
    }

    // MARK: - `--decrypt --verify-decrypt`: GOODSIG only

    /// `tclig --decrypt --verify-decrypt <ct>` emits to STDERR:
    ///
    ///     [GNUPG:] DECRYPTION_OKAY
    ///     [GNUPG:] GOODSIG E3917C1325E60537 Kushal Das <kushal@civilized.systems>
    ///
    /// **No VALIDSIG** — the inner-signature path uses 16-char key IDs
    /// only. Captured from a real round-trip on 2026-04-28.
    func testParsesDecryptVerifyOutput() {
        let raw = """
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] GOODSIG E3917C1325E60537 Kushal Das <kushal@civilized.systems>
            """
        let s = StatusLineParser.parse(raw)
        XCTAssertTrue(s.decryptionOkay)
        XCTAssertEqual(s.goodsigFingerprint, "E3917C1325E60537")
        XCTAssertNil(s.validsigFingerprint,
                     "decrypt+verify-decrypt does not emit VALIDSIG")
        XCTAssertEqual(s.signerUid, "Kushal Das <kushal@civilized.systems>")
    }

    /// Encrypt-only ciphertext: `DECRYPTION_OKAY` arrives but no
    /// signature line at all.
    func testParsesDecryptOnly() {
        let s = StatusLineParser.parse("[GNUPG:] DECRYPTION_OKAY")
        XCTAssertTrue(s.decryptionOkay)
        XCTAssertNil(s.goodsigFingerprint)
        XCTAssertNil(s.badsigFingerprint)
        XCTAssertNil(s.noPubKeyId)
    }

    // MARK: - SIG_CREATED hash mapping

    /// SIG_CREATED's `<hash_algo>` field must round-trip back to a
    /// canonical hash name; the Mail extension uses this for the
    /// `multipart/signed` `micalg` parameter.
    func testSigCreatedHashIdMapping() {
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 8), "SHA256")
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 9), "SHA384")
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 10), "SHA512")
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 11), "SHA224")
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 12), "SHA3-256")
        XCTAssertEqual(StatusLineParser.hashAlgoName(forGnupgId: 14), "SHA3-512")
        XCTAssertNil(StatusLineParser.hashAlgoName(forGnupgId: 0))
    }

    /// Pulled directly from `tclig --detach-sign --armor --digest-algo
    /// SHA256` stderr (real run, 2026-04-28):
    ///
    ///     [GNUPG:] SIG_CREATED D 0 8 00 0 37417ABF83C07691C565C434E3917C1325E60537
    func testParsesSigCreated() {
        let raw = "[GNUPG:] SIG_CREATED D 0 8 00 0 37417ABF83C07691C565C434E3917C1325E60537"
        let s = StatusLineParser.parse(raw)
        XCTAssertEqual(s.sigCreatedHash, "SHA256")
        XCTAssertEqual(s.sigCreatedFingerprint,
                       "37417ABF83C07691C565C434E3917C1325E60537")
    }

    // MARK: - INV_RECP

    /// Encrypt-time per-recipient failure surfaces as INV_RECP. The
    /// Mail compose UI marks the failing chip in red.
    func testParsesInvRecp() {
        let raw = """
            [GNUPG:] INV_RECP 0 nobody@example.com
            [GNUPG:] INV_RECP 1 ambiguous@example.com
            """
        let s = StatusLineParser.parse(raw)
        XCTAssertEqual(s.invalidRecipients,
                       ["nobody@example.com", "ambiguous@example.com"])
    }

    /// A signature UID that contains a forged `[GNUPG:] VALIDSIG` line
    /// must NOT inject a fake fingerprint — tclig sanitizes UIDs and
    /// pins them to the same physical line as GOODSIG, so any `\n` in
    /// the UID is a parser-side input we trust to land on its own
    /// line. We just verify our parser doesn't synthesize VALIDSIG
    /// from a malformed line whose fingerprint field is non-hex.
    func testValidsigInjectionRejected() {
        // What tclig actually emits is single-line; we test the
        // forgery-attempted shape that an attacker WOULD have to
        // produce to forge a 40-char fingerprint slot.
        let raw = "[GNUPG:] VALIDSIG forged\n[GNUPG:] GOODSIG E3917C1325E60537 X"
        let s = StatusLineParser.parse(raw)
        XCTAssertNil(s.validsigFingerprint, "non-hex VALIDSIG must be rejected")
        XCTAssertEqual(s.goodsigFingerprint, "E3917C1325E60537")
    }
}

final class ColonListingParserTests: XCTestCase {

    /// `tclig --list-keys --with-colons` (>= 0.5.0, PR #23) computes
    /// the validity column: "r" for revoked, "e" for expiry_time <=
    /// now, "-" otherwise. Pre-0.5.0 every row was hard-coded "-",
    /// which let expired keys leak into the recipient picker and
    /// produced a confusing INV_RECP at send time.
    ///
    /// Captured shape from a real run on 2026-04-28:
    ///
    ///     pub:e:0:0:014B273D614BE877:1605035916:1668107916:::::sc:
    ///     uid:-::::::::Mikael Nordin <hej@mic.ke>:
    ///     sub:e:0:0:7021EE9AB01BAC8A:1605035916:1668107916:::::e:
    func testExpiredKeyMarkedExpired() {
        let raw = """
            pub:e:0:0:014B273D614BE877:1605035916:1668107916:::::sc:
            uid:-::::::::Mikael Nordin <hej@mic.ke>:
            sub:e:0:0:7021EE9AB01BAC8A:1605035916:1668107916:::::e:
            """
        let keys = ColonListingParser.parse(raw)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].fingerprint, "014B273D614BE877")
        XCTAssertEqual(keys[0].primaryUid, "Mikael Nordin <hej@mic.ke>")
        XCTAssertTrue(keys[0].isExpired)
        XCTAssertFalse(keys[0].isRevoked)
    }

    /// "r" in the validity column means the key was revoked. The
    /// recipient resolver in `TumpaCryptoService.resolveRecipients`
    /// filters these out, so a sender accidentally typing a
    /// recipient whose key is revoked sees a red dot in compose
    /// rather than a misleading INV_RECP at send time.
    func testRevokedKeyMarkedRevoked() {
        let raw = """
            pub:r:0:0:DEADBEEFCAFEBABE:1700000000:1900000000:::::sc:
            uid:-::::::::Revoked User <r@example.com>:
            """
        let keys = ColonListingParser.parse(raw)
        XCTAssertEqual(keys.count, 1)
        XCTAssertTrue(keys[0].isRevoked)
        XCTAssertFalse(keys[0].isExpired)
    }

    /// Live key (validity "-") is neither revoked nor expired, so
    /// `resolveRecipients` returns it.
    func testLiveKeyHealthy() {
        let raw = """
            pub:-:0:0:E3917C1325E60537:1777294917:1814400000:::::sc:
            uid:-::::::::Kushal Das <kushal@civilized.systems>:
            sub:-:0:0:7533F0A54A204200:1777294917:1814400000:::::e:
            """
        let keys = ColonListingParser.parse(raw)
        XCTAssertEqual(keys.count, 1)
        XCTAssertFalse(keys[0].isExpired)
        XCTAssertFalse(keys[0].isRevoked)
        XCTAssertEqual(keys[0].primaryUid,
                       "Kushal Das <kushal@civilized.systems>")
    }

    /// Multiple keys back-to-back: each `pub` flushes the previous
    /// pending row. Expired and live keys both surface with their
    /// validity flag intact.
    func testParsesMultipleKeysWithMixedValidity() {
        let raw = """
            pub:-:0:0:E3917C1325E60537:1777294917:1814400000:::::sc:
            uid:-::::::::Kushal Das <kushal@civilized.systems>:
            sub:-:0:0:7533F0A54A204200:1777294917:1814400000:::::e:
            pub:e:0:0:014B273D614BE877:1605035916:1668107916:::::sc:
            uid:-::::::::Mikael Nordin <hej@mic.ke>:
            pub:r:0:0:DEADBEEFCAFEBABE:1700000000:1900000000:::::sc:
            uid:-::::::::Revoked User <r@example.com>:
            """
        let keys = ColonListingParser.parse(raw)
        XCTAssertEqual(keys.count, 3)

        let kushal = keys.first { $0.fingerprint == "E3917C1325E60537" }
        XCTAssertNotNil(kushal)
        XCTAssertFalse(kushal?.isExpired ?? true)
        XCTAssertFalse(kushal?.isRevoked ?? true)

        let mikael = keys.first { $0.fingerprint == "014B273D614BE877" }
        XCTAssertNotNil(mikael)
        XCTAssertTrue(mikael?.isExpired ?? false)
        XCTAssertFalse(mikael?.isRevoked ?? true)

        let revoked = keys.first { $0.fingerprint == "DEADBEEFCAFEBABE" }
        XCTAssertNotNil(revoked)
        XCTAssertTrue(revoked?.isRevoked ?? false)
        XCTAssertFalse(revoked?.isExpired ?? true)
    }
}
