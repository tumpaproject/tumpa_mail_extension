// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for `PGPMimeBuilder`'s line-ending detection and
// outer-envelope emission. The line-ending fix is what makes Apple
// Mail's MailKit encoder leave our `multipart/signed` bytes alone.

import XCTest

final class PGPMimeBuilderLineEndingTests: XCTestCase {

    /// Apple Mail's `MEMessage.rawData` is LF-only — detectLineEnding
    /// must return `\n` when the headers contain no CRLF.
    func testDetectLineEnding_LFInput() {
        let lfMessage = Data("""
            From: a@example.com
            To: b@example.com
            Subject: hi

            hello
            """.utf8)
        let eol = PGPMimeBuilder.detectLineEnding(in: lfMessage)
        XCTAssertEqual(eol, "\n".data(using: .ascii)!,
                       "LF-only input must detect as \\n")
    }

    /// CRLF-style RFC-strict messages (e.g. wire-format from sendmail
    /// bypass tests) must keep emitting CRLF — back-compat for non-Mail
    /// callers.
    func testDetectLineEnding_CRLFInput() {
        let crlfMessage = Data("From: a@example.com\r\nTo: b@example.com\r\n\r\nhello\r\n".utf8)
        let eol = PGPMimeBuilder.detectLineEnding(in: crlfMessage)
        XCTAssertEqual(eol, "\r\n".data(using: .ascii)!,
                       "Any CRLF in headers means detect CRLF")
    }

    /// Construct a representative Apple Mail original (LF outer, single
    /// text/plain inner) and check that `buildSignedMessage` emits LF
    /// for outer headers and `--boundary` delimiters. This is the
    /// mangling fix: pre-fix we emitted `\r\n` and Mail's MIME parser
    /// "consolidated" the structure on the way out, dropping inner
    /// boundaries and the BEGIN-PGP-SIGNATURE line.
    func testBuildSignedMessage_LFOriginal_OuterEnvelopeIsLF() throws {
        let original = Data("""
            From: kushal@civilized.systems
            Subject: Hi
            Message-Id: <abc@civilized.systems>
            To: kushal@civilized.systems
            Content-Type: text/plain; charset=us-ascii

            Hello world.
            """.utf8)
        let canonInner = Data("Content-Type: text/plain; charset=us-ascii\r\n\r\nHello world.\r\n".utf8)
        let signature = Data("-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=AA\n-----END PGP SIGNATURE-----\n".utf8)

        let encoded = try PGPMimeBuilder.buildSignedMessage(
            original: original,
            canonicalizedInnerPart: canonInner,
            armoredSignature: signature,
            micalg: "pgp-sha256"
        )

        XCTAssertTrue(encoded.isSigned)
        XCTAssertFalse(encoded.isEncrypted)

        let bytes = encoded.bytes
        // Outer header lines end with LF, NOT CRLF.
        XCTAssertNotNil(bytes.range(of: "Content-Type: multipart/signed".data(using: .utf8)!),
                        "outer Content-Type missing")
        XCTAssertNil(
            bytes.range(of: "multipart/signed; protocol=\"application/pgp-signature\"; micalg=\"pgp-sha256\"; boundary=\"".data(using: .utf8)!.appending(byte: 0x0D)),
            "outer Content-Type line ended with CR — should be LF only")

        // The opening `--boundary` after outer headers must be preceded
        // by LF + LF (blank-line then boundary), not CRLF + CRLF.
        // Look for the literal `\n\n--tumpa-signed-` sequence.
        let boundaryOpen = "\n\n--tumpa-signed-".data(using: .utf8)!
        XCTAssertNotNil(bytes.range(of: boundaryOpen),
                        "outer envelope must use LF separator + LF before opening boundary")

        // Closing boundary likewise terminates with LF.
        XCTAssertTrue(bytes.suffix(2).last == 0x0A &&
                      bytes.suffix(2).first != 0x0D,
                      "closing --boundary-- must end with bare LF when original is LF-only")
    }

    /// CRLF original (e.g. from sendmail-bypass test fixture) must
    /// still produce CRLF outer envelope, so that path keeps working.
    func testBuildSignedMessage_CRLFOriginal_OuterEnvelopeIsCRLF() throws {
        let original = Data("From: a@example.com\r\nSubject: Hi\r\nTo: b@example.com\r\nContent-Type: text/plain\r\n\r\nbody\r\n".utf8)
        let canonInner = Data("Content-Type: text/plain\r\n\r\nbody\r\n".utf8)
        let signature = Data("-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=AA\n-----END PGP SIGNATURE-----\n".utf8)

        let encoded = try PGPMimeBuilder.buildSignedMessage(
            original: original,
            canonicalizedInnerPart: canonInner,
            armoredSignature: signature,
            micalg: "pgp-sha256"
        )

        let bytes = encoded.bytes
        // CRLF separator before opening boundary.
        let boundaryOpenCRLF = "\r\n\r\n--tumpa-signed-".data(using: .utf8)!
        XCTAssertNotNil(bytes.range(of: boundaryOpenCRLF),
                        "CRLF input must produce CRLF separator + CRLF before opening boundary")
    }

    /// Regression: the bytes a recipient extracts between the two
    /// inner-part boundaries MUST be byte-equal to the
    /// `canonicalizedInnerPart` we passed to the signing call.
    /// Earlier code relied on the inner part's own trailing CRLF as
    /// the boundary's preceding CRLF — which made recipients strip
    /// two bytes off the hashed entity, causing `tclig --verify` to
    /// report BADSIG even though every other byte was correct
    /// (observed on the 4.eml dump, 2026-04-27).
    func testSignedInnerPart_RoundTripBytesEqualSignedBytes() throws {
        let original = Data("From: a@example.com\nSubject: Hi\nTo: b@example.com\nContent-Type: text/plain\n\nbody\n".utf8)
        // Mimic what OutgoingSecurityHandler.applyOpenPGP passes to
        // tclig --detach-sign: a CRLF-canonical inner part terminated
        // with CRLF.
        let canonInner = Data("Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello,\r\n\r\nKushal\r\n".utf8)
        let signature = Data("-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n".utf8)

        let encoded = try PGPMimeBuilder.buildSignedMessage(
            original: original,
            canonicalizedInnerPart: canonInner,
            armoredSignature: signature,
            micalg: "pgp-sha256"
        )

        // Re-parse the encoded multipart and pull the signed part out
        // exactly the way a receiving MUA (or our own PGPMimeParser)
        // would. The bytes MUST match what we asked tclig to sign.
        switch PGPMimeParser.classify(encoded.bytes) {
        case .pgpSigned(let signedPart, _, _):
            XCTAssertEqual(signedPart, canonInner,
                           "extracted signed bytes must equal canonicalizedInnerPart")
        default:
            XCTFail("buildSignedMessage output should classify as pgpSigned")
        }
    }

    /// `multipart/encrypted` follows the same line-ending rule.
    func testBuildEncryptedMessage_LFOriginal_OuterEnvelopeIsLF() throws {
        let original = Data("From: a@example.com\nSubject: Hi\nTo: b@example.com\nContent-Type: text/plain\n\nbody\n".utf8)
        let ciphertext = Data("-----BEGIN PGP MESSAGE-----\n\nXXXX\n-----END PGP MESSAGE-----\n".utf8)

        let encoded = try PGPMimeBuilder.buildEncryptedMessage(
            original: original,
            armoredCiphertext: ciphertext,
            innerWasSigned: false
        )

        let bytes = encoded.bytes
        XCTAssertNil(bytes.range(of: "\r\n--tumpa-encrypted-".data(using: .utf8)!),
                     "LF-original encrypted output must not contain CRLF before boundary")
        XCTAssertNotNil(bytes.range(of: "\n\n--tumpa-encrypted-".data(using: .utf8)!),
                        "LF-original encrypted output must use bare-LF before opening boundary")
    }
}

private extension Data {
    /// Local test helper: append a single byte to a Data and return it.
    func appending(byte: UInt8) -> Data {
        var copy = self
        copy.append(byte)
        return copy
    }
}

/// Tests for `PGPMimeBuilder.headerValue(_:in:)`. Used by the
/// outbound-decoded-message cache to extract `X-Universally-Unique-
/// Identifier` and `Message-Id` from raw RFC 822 bytes for cache
/// keying. The helper has to handle the same line-ending mixes Apple
/// Mail and our own emit path produce.
final class PGPMimeBuilderHeaderValueTests: XCTestCase {

    func testHeaderValue_LFOnly_CaseInsensitive() {
        let raw = Data("""
            From: a@example.com
            Message-Id: <abc-123@example.com>
            Subject: hello

            body
            """.utf8)
        XCTAssertEqual(
            PGPMimeBuilder.headerValue("Message-Id", in: raw),
            "<abc-123@example.com>"
        )
        // Case-insensitive per RFC 5322.
        XCTAssertEqual(
            PGPMimeBuilder.headerValue("message-id", in: raw),
            "<abc-123@example.com>"
        )
    }

    func testHeaderValue_CRLF_PreservesValueExactly() {
        let raw = Data("Message-Id: <wire@example.com>\r\nSubject: x\r\n\r\nbody".utf8)
        XCTAssertEqual(
            PGPMimeBuilder.headerValue("message-id", in: raw),
            "<wire@example.com>"
        )
    }

    func testHeaderValue_MissingHeader_ReturnsNil() {
        let raw = Data("From: a@example.com\n\nbody".utf8)
        XCTAssertNil(PGPMimeBuilder.headerValue("Message-Id", in: raw))
    }

    /// Cache-relevant: an Apple-Mail compose draft carries
    /// `X-Universally-Unique-Identifier`. Our pre-cache path reads it
    /// out of the in-memory `MEMessage` headers, but the decode-side
    /// fallback parses it out of bytes — same helper handles both.
    func testHeaderValue_FindsXUUID() {
        let raw = Data("""
            From: kushal@civilized.systems
            X-Universally-Unique-Identifier: 78C6BAF5-3012-40DA-8A61-E679BFC12C04
            Subject: Test

            body
            """.utf8)
        XCTAssertEqual(
            PGPMimeBuilder.headerValue("X-Universally-Unique-Identifier", in: raw),
            "78C6BAF5-3012-40DA-8A61-E679BFC12C04"
        )
    }

    /// Returns nil rather than throwing when the bytes have no
    /// blank-line separator (Mail occasionally hands us partial
    /// header-only callbacks during the indexer's pre-fetch). The
    /// caller treats nil as "no cache key here, fall through to the
    /// real decode" — throwing here would make `decodedMessage` look
    /// like a fatal error path.
    func testHeaderValue_HeaderOnlyBytes_NoCrash() {
        let raw = Data("Message-Id: <only-headers@example.com>".utf8)
        // Fallback parse path — still returns the value.
        XCTAssertEqual(
            PGPMimeBuilder.headerValue("message-id", in: raw),
            "<only-headers@example.com>"
        )
    }
}

/// Tests for `PGPMimeBuilder.assembleInboundDecodedMessage`. This
/// helper synthesizes a full RFC 822 message for Mail's reader from
/// an inbound encrypted wrapper's outer envelope + the decrypted
/// inner part. Without it, the inbound real-decrypt path returns
/// inner-part-only `data` and the message body renders empty.
final class PGPMimeBuilderInboundAssemblyTests: XCTestCase {

    /// Outer envelope's routing headers are preserved; outer
    /// Content-* and MIME-Version are dropped (the inner part
    /// supplies its own); the decrypted inner part is appended after
    /// a blank line.
    func testAssembleInbound_KeepsEnvelopeDropsContentHeaders() throws {
        let envelopeSource = Data("""
            From: sender@example.com
            To: kushal@civilized.systems
            Subject: encrypted hello
            Date: Mon, 27 Apr 2026 22:00:00 +0200
            Message-Id: <abc@example.com>
            MIME-Version: 1.0
            Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="x"

            --x
            Content-Type: application/pgp-encrypted

            Version: 1
            --x
            Content-Type: application/octet-stream

            -----BEGIN PGP MESSAGE-----
            (ciphertext)
            -----END PGP MESSAGE-----
            --x--
            """.utf8)
        let decryptedInner = Data("""
            Content-Type: text/plain; charset=utf-8

            Hello, decrypted!
            """.utf8)

        let assembled = try PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: envelopeSource,
            decryptedInnerPart: decryptedInner
        )
        let s = String(data: assembled, encoding: .utf8)!
        XCTAssertTrue(s.contains("From: sender@example.com"),
                      "envelope From: must be preserved")
        XCTAssertTrue(s.contains("Subject: encrypted hello"),
                      "envelope Subject: must be preserved")
        XCTAssertTrue(s.contains("Message-Id: <abc@example.com>"),
                      "envelope Message-Id: must be preserved")
        XCTAssertFalse(s.contains("multipart/encrypted"),
                       "outer Content-Type must NOT appear in assembled output")
        XCTAssertTrue(s.contains("Content-Type: text/plain; charset=utf-8"),
                      "inner part Content-Type must be lifted up onto the outer envelope")
        XCTAssertTrue(s.contains("Hello, decrypted!"),
                      "inner part body must appear")
        // Single header block: there should be exactly one blank
        // line in the assembled output, between headers and body.
        // Two blank lines means two header blocks, which is what
        // caused the inner Content-* to render as literal body text.
        let blanks = s.components(separatedBy: "\n\n").count - 1
            + s.components(separatedBy: "\r\n\r\n").count - 1
        XCTAssertEqual(blanks, 1,
                       "exactly one header/body separator (got \(blanks)) — multiple means inner headers will leak into the body")
    }

    /// Envelope detection honors the outer message's line-ending
    /// style. CRLF in equates to CRLF out for the assembled headers
    /// — important because the assembled bytes get written into
    /// Mail's library and a line-ending mix-up there could break
    /// downstream consumers.
    func testAssembleInbound_CRLFEnvelope_EmitsCRLFHeaders() throws {
        let envelope = Data("From: a@example.com\r\nSubject: x\r\nMessage-Id: <m@x>\r\nContent-Type: multipart/encrypted\r\n\r\nbody".utf8)
        let inner = Data("Content-Type: text/plain\r\n\r\nhi".utf8)
        let assembled = try PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: envelope, decryptedInnerPart: inner
        )
        // Envelope headers section uses CRLF.
        let s = String(data: assembled, encoding: .utf8)!
        XCTAssertTrue(s.contains("From: a@example.com\r\n"),
                      "CRLF envelope must produce CRLF assembled headers")
    }

    /// Real-world inbound case: outer envelope is LF (Mail strips CR
    /// before invoking `decodedMessage`), decrypted inner part is a
    /// CRLF `multipart/alternative` (Thunderbird-Android, Gmail, etc.
    /// canonicalise to CRLF before encrypting). The assembled body
    /// must use a CONSISTENT line ending so Mail's reader can walk
    /// the `--boundary` lines and render the alternatives instead of
    /// dumping the whole MIME tree as raw text. Reproduces the
    /// `kano1.eml` symptom from 2026-04-28.
    func testAssembleInbound_LFEnvelope_CRLFMultipartInner_BodyIsLineEndingConsistent() throws {
        let envelope = Data(
            "From: a@example.com\nSubject: x\nMessage-Id: <m@x>\nContent-Type: multipart/encrypted\n\nbody"
                .utf8
        )
        // Inner part: CRLF throughout, multipart/alternative with
        // text/plain + text/html. Mirrors what tclig --decrypt
        // returns for a Thunderbird-Android-sent encrypted mail.
        let boundary = "----ABCXYZ"
        let inner = Data((
            "Content-Type: multipart/alternative; boundary=\"\(boundary)\"\r\n"
            + "\r\n"
            + "--\(boundary)\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + "\r\n"
            + "Hello plain\r\n"
            + "--\(boundary)\r\n"
            + "Content-Type: text/html; charset=utf-8\r\n"
            + "\r\n"
            + "<p>Hello html</p>\r\n"
            + "--\(boundary)--\r\n"
        ).utf8)
        let assembled = try PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: envelope, decryptedInnerPart: inner
        )
        // The whole assembled message must NOT contain a CR — the
        // envelope is LF, so the inner body must have been rewritten
        // to LF too. Any leftover \r between the body's boundary
        // lines is what triggers the kano1 symptom.
        XCTAssertFalse(assembled.contains(0x0D),
                       "inner body's CRLF must be rewritten to match the LF envelope so Mail can walk the multipart boundaries")
        // Sanity: the boundary lines are still present and parsable.
        let s = String(data: assembled, encoding: .utf8)!
        XCTAssertTrue(s.contains("\n--\(boundary)\n"),
                      "boundary delimiters must survive line-ending normalization")
        XCTAssertTrue(s.contains("\n--\(boundary)--\n")
                      || s.hasSuffix("\n--\(boundary)--"),
                      "closing boundary must survive line-ending normalization")
        XCTAssertTrue(s.contains("Content-Type: multipart/alternative"),
                      "inner part Content-Type lifted to envelope")
    }

    /// Symmetric case: CRLF envelope + LF inner body — rare in
    /// practice (Mail almost always hands LF) but the helper must be
    /// robust to it.
    func testAssembleInbound_CRLFEnvelope_LFInner_BodyIsLineEndingConsistent() throws {
        let envelope = Data(
            "From: a@example.com\r\nSubject: x\r\nMessage-Id: <m@x>\r\nContent-Type: multipart/encrypted\r\n\r\nbody"
                .utf8
        )
        let inner = Data("Content-Type: text/plain\n\nLine 1\nLine 2\n".utf8)
        let assembled = try PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: envelope, decryptedInnerPart: inner
        )
        let s = String(data: assembled, encoding: .utf8)!
        // No bare LF anywhere in the assembled output.
        var prev: UInt8 = 0
        for byte in assembled {
            if byte == 0x0A {
                XCTAssertEqual(prev, 0x0D, "bare LF found in CRLF-targeted assembled output")
            }
            prev = byte
        }
        XCTAssertTrue(s.contains("Line 1\r\nLine 2"),
                      "LF inner body rewritten to CRLF")
    }

    /// Apple-internal `X-Apple-*` headers from the outer envelope
    /// don't leak into the assembled output (they're compose-state
    /// from the sender's machine and irrelevant on inbound).
    func testAssembleInbound_StripsAppleInternal() throws {
        let envelope = Data("""
            From: a@example.com
            X-Apple-Auto-Saved: 1
            Subject: y
            Content-Type: multipart/encrypted

            body
            """.utf8)
        let inner = Data("Content-Type: text/plain\n\nz".utf8)
        let assembled = try PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: envelope, decryptedInnerPart: inner
        )
        let s = String(data: assembled, encoding: .utf8)!
        XCTAssertFalse(s.contains("X-Apple-Auto-Saved"),
                       "X-Apple-* headers from sender's compose state must not leak to inbound assembled view")
    }
}

/// Tests for `PGPMimeParser.hasPGPMarkers` — the cheap precheck that
/// gates the expensive `classify` + XPC verify path. Bug fix for
/// 2026-04-28 `jocar1.eml` regression: an earlier version capped the
/// scan at 8 KiB, which silently dropped legitimately-signed mail
/// routed through Microsoft 365 / Exchange (where the ARC + DKIM +
/// `x-ms-*` header pile alone exceeds 8 KiB). Mail showed no
/// security indicator on the message.
final class PGPMimeParserMarkerPrecheckTests: XCTestCase {

    /// Baseline: a small `multipart/signed` message — markers visible
    /// well inside any prefix window.
    func testHasPGPMarkers_SmallSigned_Detected() {
        let msg = """
            From: a@example.com\r
            Subject: x\r
            Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="b"; micalg=pgp-sha256\r
            \r
            --b\r
            Content-Type: text/plain\r
            \r
            hi\r
            --b\r
            Content-Type: application/pgp-signature\r
            \r
            -----BEGIN PGP SIGNATURE-----\r
            -----END PGP SIGNATURE-----\r
            --b--\r
            """
        XCTAssertTrue(PGPMimeParser.hasPGPMarkers(in: Data(msg.utf8)))
    }

    /// Baseline: a small `multipart/encrypted` message — markers also
    /// detected.
    func testHasPGPMarkers_SmallEncrypted_Detected() {
        let msg = """
            From: a@example.com\r
            Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b"\r
            \r
            --b\r
            Content-Type: application/pgp-encrypted\r
            \r
            Version: 1\r
            --b\r
            Content-Type: application/octet-stream\r
            \r
            -----BEGIN PGP MESSAGE-----\r
            -----END PGP MESSAGE-----\r
            --b--\r
            """
        XCTAssertTrue(PGPMimeParser.hasPGPMarkers(in: Data(msg.utf8)))
    }

    /// Regression for the `jocar1.eml` symptom: 16 KiB of leading
    /// header padding (mimicking Microsoft 365 ARC + DKIM +
    /// `x-microsoft-antispam-messagedata-*` chunks) pushes the
    /// `Content-Type: multipart/signed` line WELL past the old 8 KiB
    /// cutoff. The whole-message scan must still see the markers.
    func testHasPGPMarkers_HeavyHeaderPile_StillDetected() {
        var headers = "From: jocar@sunet.se\r\nSubject: Re: My public key\r\n"
        // 16 KiB of x-microsoft-antispam-messagedata-style padding
        // before the real Content-Type header. ~80 bytes per line ×
        // 200 lines ≈ 16 KiB.
        for i in 0..<200 {
            headers += "X-Microsoft-Antispam-Messagedata-\(i): "
                + String(repeating: "A", count: 70) + "\r\n"
        }
        headers += "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"b\"; micalg=pgp-sha512\r\n"
        let body = """
            \r
            --b\r
            Content-Type: text/plain\r
            \r
            hi\r
            --b\r
            Content-Type: application/pgp-signature\r
            \r
            -----BEGIN PGP SIGNATURE-----\r
            -----END PGP SIGNATURE-----\r
            --b--\r
            """
        let data = Data((headers + body).utf8)
        XCTAssertGreaterThan(data.count, 8192,
            "test fixture must exceed the OLD 8 KiB cutoff to be a real regression guard")
        XCTAssertTrue(PGPMimeParser.hasPGPMarkers(in: data),
            "marker scan must cover the WHOLE message; bytes past 8 KiB carry the multipart/signed Content-Type when routed through MS Exchange")
    }

    /// Negative: an inbox-typical 12 KiB plain-text mail with no PGP
    /// must NOT trigger the precheck (otherwise we churn tclig per
    /// inbox message).
    func testHasPGPMarkers_PlainBigMessage_NotDetected() {
        let big = "From: a@example.com\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\n"
            + String(repeating: "lorem ipsum dolor sit amet ", count: 500)
        XCTAssertFalse(PGPMimeParser.hasPGPMarkers(in: Data(big.utf8)))
    }

    /// Case-insensitive: RFC 2045 §5.1 says MIME type/subtype tokens
    /// match case-insensitively. Some senders emit `Multipart/Signed`
    /// with capital letters.
    func testHasPGPMarkers_MixedCase_Detected() {
        let msg = "Content-Type: Multipart/Signed; protocol=\"Application/PGP-Signature\"; boundary=\"b\"\r\n\r\nbody"
        XCTAssertTrue(PGPMimeParser.hasPGPMarkers(in: Data(msg.utf8)))
    }

    /// Negative: a message that mentions "multipart/signed" only in
    /// natural-language body text (no `application/pgp-signature`)
    /// should NOT trip the precheck. Both markers required.
    func testHasPGPMarkers_BodyTextMentionsSigned_NotDetected() {
        let msg = "From: a@example.com\r\nContent-Type: text/plain\r\n\r\nThe spec calls this multipart/signed, by the way.\r\n"
        XCTAssertFalse(PGPMimeParser.hasPGPMarkers(in: Data(msg.utf8)))
    }
}
