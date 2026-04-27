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
