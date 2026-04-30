// SPDX-License-Identifier: GPL-3.0-or-later
//
// RFC 3156 PGP/MIME envelope builder.
//
// Apple Mail hands us a fully-formed RFC 822 outgoing message via
// `MEMessage.rawData`. Our job is to wrap that message in either:
//
//  • multipart/signed; protocol="application/pgp-signature"; micalg="…"
//  • multipart/encrypted; protocol="application/pgp-encrypted"
//
// without rewriting any of the inner MIME — attachments, HTML
// alternative parts, and inline images all flow through opaquely as
// the inner body. The only transform on the inner side is CRLF
// canonicalization of the signed-body bytes (RFC 3156 §5.1).
//
// Header strategy: the OUTER message keeps the original
// From / To / Cc / Bcc / Subject / Date / Message-ID / In-Reply-To /
// References / User-Agent / MIME-Version headers. Content-* headers
// move down to the INNER (encapsulated) MIME part so the recipient's
// MUA discovers the original Content-Type after unwrapping. The
// outer Content-Type is replaced with the multipart wrapper.

import Foundation

/// Result of one of the PGP/MIME build operations.
struct EncodedRFC822 {
    let bytes: Data
    /// Whether the encoded bytes carry a signature.
    let isSigned: Bool
    /// Whether the encoded bytes are encrypted.
    let isEncrypted: Bool
}

/// Errors specific to the framing step. XPC / tclig errors stay in
/// their own type and are surfaced separately to the security
/// handler.
enum PGPMimeBuilderError: Error, LocalizedError {
    case noBlankLineSeparator
    case malformedHeaders

    var errorDescription: String? {
        switch self {
        case .noBlankLineSeparator:
            return "outgoing message is missing the header/body separator"
        case .malformedHeaders:
            return "outgoing message has malformed headers"
        }
    }
}

enum PGPMimeBuilder {

    // Per RFC 822 the header / body separator is a literal CRLF, but
    // Apple Mail's `MEMessage.rawData` is LF-only — and crucially,
    // Mail's outgoing encoder *destroys* multipart structures whose
    // outer envelope is in CRLF when it was expecting LF (we observed
    // headers from the inner parts getting lifted into the outer
    // header section, opening boundary delimiters and the part-1 body
    // dropped, and the `-----BEGIN PGP SIGNATURE-----` armor line
    // stripped). So: we detect the original message's line-ending
    // style and emit the OUTER multipart envelope in that style. The
    // CRLF canonicalization required by RFC 3156 §5 still applies to
    // the signed-content bytes (those go to `tclig --detach-sign`
    // verbatim — see `wecanencrypt/src/sign.rs:540` regression test).
    // Mail's SMTP transport converts the wire LF→CRLF on outgoing,
    // so the recipient receives all-CRLF and the signature verifies.
    //
    // This mirrors `mailgpg/MailGPG/GPGServiceImpl+MIME.swift:88-91`
    // and `:194-196` ("Mail.app uses LF (\n), not CRLF (\r\n).
    // Returning mismatched line endings crashes Mail's MIME parser").
    private static let crlf: Data = "\r\n".data(using: .ascii)!
    private static let lf: Data = "\n".data(using: .ascii)!
    private static let crlfcrlf: Data = "\r\n\r\n".data(using: .ascii)!

    /// Detect the line-ending style used by an RFC 822 message. Looks
    /// at the first 4 KiB of headers — long enough to span the routing
    /// headers plus a fold or two without scanning a whole multi-MB
    /// body. Returns `\r\n` only when explicit CRLF is present;
    /// otherwise `\n` (Apple Mail's native form).
    static func detectLineEnding(in data: Data) -> Data {
        let probe = data.prefix(4096)
        return probe.range(of: crlf) != nil ? crlf : lf
    }

    // MARK: - Public API

    /// Wrap `original` (a complete RFC 822 message) in
    /// `multipart/signed`, given a detached signature over the
    /// canonicalized inner part.
    ///
    /// `micalg` is the OpenPGP hash algorithm name lowercased and
    /// prefixed with `pgp-`, e.g. `pgp-sha256` for SHA-256. The
    /// caller gets it from `LibtumpaRunner.signDetached` (via the
    /// XPC `signDetached(canonicalizedBody:...)` reply slot).
    ///
    /// The signed part the caller already detached-signed is the
    /// CRLF-canonicalized headers+body of the inner MIME. Pass that
    /// SAME byte sequence as `canonicalizedInnerPart` so the
    /// resulting multipart structure carries exactly the bytes the
    /// signature was made over.
    static func buildSignedMessage(
        original: Data,
        canonicalizedInnerPart: Data,
        armoredSignature: Data,
        micalg: String
    ) throws -> EncodedRFC822 {
        let eol = detectLineEnding(in: original)
        let split = try splitHeadersAndBody(original)
        let outerHeaders = retainOuterHeaders(split.headers)

        let boundary = randomBoundary(prefix: "tumpa-signed")
        var out = Data()

        // Outer headers: keep envelope, replace Content-Type / MIME-Version,
        // strip Content-Transfer-Encoding (irrelevant for multipart).
        out.append(serializeHeaders(outerHeaders, eol: eol))
        appendHeader(into: &out, name: "MIME-Version", value: "1.0", eol: eol)
        appendHeader(
            into: &out,
            name: "Content-Type",
            value: "multipart/signed; "
                + "protocol=\"application/pgp-signature\"; "
                + "micalg=\"\(micalg)\"; "
                + "boundary=\"\(boundary)\"",
            eol: eol
        )
        out.append(eol)

        // Inner part: the CRLF-canonical bytes the signature was made
        // over, verbatim. RFC 3156 §5.1: "the signed message and
        // transmitted message MUST be byte-for-byte identical to the
        // form which was given to the signing process." The inner
        // bytes stay CRLF even when the outer envelope is LF — Mail's
        // MIME parser treats inter-boundary content as opaque, and
        // CRLF on the wire is what the recipient verifies against.
        //
        // We ALWAYS append CRLF after the inner part, even when it
        // already ends with one. RFC 2046 §5.1.1: the CRLF
        // immediately preceding `--boundary` is part of the boundary
        // delimiter, not the part body. If we relied on the inner
        // part's own trailing CRLF to serve as the boundary delimiter,
        // recipients would strip 2 bytes off the part body before
        // hashing — and tclig signed the longer (un-stripped) form,
        // so verify fails. Always emitting an extra CRLF guarantees
        // the bytes between the boundaries (= what recipients hash)
        // match the bytes we passed to `tclig --detach-sign`.
        out.append("--\(boundary)".data(using: .ascii)!)
        out.append(eol)
        out.append(canonicalizedInnerPart)
        out.append(crlf)

        // Signature part.
        out.append("--\(boundary)".data(using: .ascii)!)
        out.append(eol)
        appendHeader(into: &out, name: "Content-Type",
                     value: "application/pgp-signature; name=\"signature.asc\"",
                     eol: eol)
        appendHeader(into: &out, name: "Content-Description",
                     value: "OpenPGP digital signature", eol: eol)
        appendHeader(into: &out, name: "Content-Disposition",
                     value: "attachment; filename=\"signature.asc\"", eol: eol)
        out.append(eol)
        out.append(armoredSignature)
        if !armoredSignature.hasSuffix(eol) && !armoredSignature.hasSuffix(crlf) {
            out.append(eol)
        }

        out.append("--\(boundary)--".data(using: .ascii)!)
        out.append(eol)

        return EncodedRFC822(bytes: out, isSigned: true, isEncrypted: false)
    }

    /// Wrap `original` in `multipart/encrypted`, given an armored
    /// OpenPGP message produced by `tclig --encrypt`. Optionally
    /// flagged as also-signed if the underlying ciphertext is sign-
    /// then-encrypted.
    static func buildEncryptedMessage(
        original: Data,
        armoredCiphertext: Data,
        innerWasSigned: Bool
    ) throws -> EncodedRFC822 {
        let eol = detectLineEnding(in: original)
        let split = try splitHeadersAndBody(original)
        let outerHeaders = retainOuterHeaders(split.headers)

        let boundary = randomBoundary(prefix: "tumpa-encrypted")
        var out = Data()

        out.append(serializeHeaders(outerHeaders, eol: eol))
        appendHeader(into: &out, name: "MIME-Version", value: "1.0", eol: eol)
        appendHeader(
            into: &out,
            name: "Content-Type",
            value: "multipart/encrypted; "
                + "protocol=\"application/pgp-encrypted\"; "
                + "boundary=\"\(boundary)\"",
            eol: eol
        )
        out.append(eol)

        // First part: PGP/MIME version control packet (RFC 3156 §4.2).
        out.append("--\(boundary)".data(using: .ascii)!)
        out.append(eol)
        appendHeader(into: &out, name: "Content-Type",
                     value: "application/pgp-encrypted", eol: eol)
        appendHeader(into: &out, name: "Content-Description",
                     value: "PGP/MIME version identification", eol: eol)
        out.append(eol)
        out.append("Version: 1".data(using: .ascii)!)
        out.append(eol)

        // Second part: the actual ciphertext.
        out.append("--\(boundary)".data(using: .ascii)!)
        out.append(eol)
        appendHeader(into: &out, name: "Content-Type",
                     value: "application/octet-stream; name=\"encrypted.asc\"",
                     eol: eol)
        appendHeader(into: &out, name: "Content-Description",
                     value: "OpenPGP encrypted message", eol: eol)
        appendHeader(into: &out, name: "Content-Disposition",
                     value: "inline; filename=\"encrypted.asc\"", eol: eol)
        out.append(eol)
        out.append(armoredCiphertext)
        if !armoredCiphertext.hasSuffix(eol) && !armoredCiphertext.hasSuffix(crlf) {
            out.append(eol)
        }

        out.append("--\(boundary)--".data(using: .ascii)!)
        out.append(eol)

        return EncodedRFC822(bytes: out, isSigned: innerWasSigned, isEncrypted: true)
    }

    // MARK: - Inner-part canonicalization (the signed bytes)

    /// CRLF-canonicalize the inner MIME part the signature will be
    /// made over.
    ///
    /// RFC 3156 §5.1 + §5.4: the signed body must use CRLF line
    /// endings. RFC 2049 §1.1 also requires that bare CRs and bare
    /// LFs not appear in the canonical form of text data. We do the
    /// minimum-correct transformation: every LF that isn't already
    /// preceded by a CR gets one, and every CR not followed by an LF
    /// gets an LF. This is bidirectionally safe — already-CRLF input
    /// passes through unchanged.
    static func canonicalizeForSigning(_ innerPart: Data) -> Data {
        var out = Data()
        out.reserveCapacity(innerPart.count + innerPart.count / 32)

        var i = innerPart.startIndex
        while i < innerPart.endIndex {
            let byte = innerPart[i]
            switch byte {
            case 0x0D:                // CR
                out.append(0x0D)
                let next = innerPart.index(after: i)
                if next < innerPart.endIndex && innerPart[next] == 0x0A {
                    out.append(0x0A)
                    i = innerPart.index(after: next)
                } else {
                    out.append(0x0A)        // bare CR → CRLF
                    i = next
                }
            case 0x0A:                // bare LF → CRLF
                out.append(0x0D)
                out.append(0x0A)
                i = innerPart.index(after: i)
            default:
                out.append(byte)
                i = innerPart.index(after: i)
            }
        }
        return out
    }

    /// Recovery variants for inbound detached verify when the
    /// straight-canonical bytes don't match the signature.
    ///
    /// In the wild we see two compounding mangling sources for
    /// `multipart/signed` text parts that round-trip through
    /// Microsoft Exchange / Outlook:
    ///
    /// 1. `\r\r\n` doubling — Exchange runs an LF→CRLF normalization
    ///    pass on text parts; on already-CRLF bytes the naive
    ///    `s.replace("\n","\r\n")` doubles the CR. Only the
    ///    `text/plain` part is affected; the `application/pgp-signature`
    ///    part skips text normalization (different Content-Type).
    ///
    /// 2. Extra trailing CRLFs — observed on a 2026-04-30 inbound
    ///    `jocar_failed.eml`. Wire bytes between boundaries had two
    ///    extra `\r\n` beyond what the sender signed. Likely Mail's
    ///    `MCMessageGenerator` adding blank lines on outbound, or a
    ///    relay padding the part. RFC 2046 §5.1.1 only reserves ONE
    ///    preceding-boundary CRLF; the rest belong to the body and
    ///    break the hash.
    ///
    /// We try the straight-canonical form first (correct senders
    /// always succeed there). Only if it fails do we fall back to the
    /// recovery variants in this list — they're not part of the spec,
    /// they're a tolerance shim for known sender-side / MTA bugs.
    /// Each variant is a self-contained alternative; callers verify
    /// against each in order and accept the first `good` outcome.
    static func tolerantSignedVariants(of canonicalSigned: Data) -> [Data] {
        var variants: [Data] = []

        // Outlook/Exchange `\r\r\n` doubling collapse.
        let collapsed = collapseDoubledCR(canonicalSigned)
        if collapsed != canonicalSigned {
            variants.append(collapsed)
        }

        // Extra trailing CRLFs. Try peeling off 1, 2, 3 trailing CRLFs
        // from BOTH the original-canonical and the collapsed form —
        // both sources of mangling can stack with extra-blank-line
        // padding.
        for base in [canonicalSigned, collapsed] {
            var current = base
            for _ in 0..<3 {
                if current.hasSuffix(crlf) {
                    current = current.subdata(in: current.startIndex..<(current.endIndex - 2))
                    if !variants.contains(current) && current != canonicalSigned {
                        variants.append(current)
                    }
                } else {
                    break
                }
            }
        }
        return variants
    }

    /// Collapse runs of `\r\r\n` to `\r\n`. Idempotent. Used by
    /// `tolerantSignedVariants` and worth keeping as a separate
    /// helper so the regression test can target it directly.
    static func collapseDoubledCR(_ data: Data) -> Data {
        var out = Data()
        out.reserveCapacity(data.count)
        var i = data.startIndex
        while i < data.endIndex {
            // Look for the literal `\r\r\n` (two CRs followed by LF)
            // and emit just `\r\n`.
            if data[i] == 0x0D,
               data.index(after: i) < data.endIndex,
               data[data.index(after: i)] == 0x0D,
               data.index(i, offsetBy: 2) < data.endIndex,
               data[data.index(i, offsetBy: 2)] == 0x0A {
                out.append(0x0D)
                out.append(0x0A)
                i = data.index(i, offsetBy: 3)
            } else {
                out.append(data[i])
                i = data.index(after: i)
            }
        }
        return out
    }

    /// Rewrite `data`'s line endings to `eol` (which must be `crlf` or
    /// `lf`). Treats CR / LF / CRLF interchangeably as a single line
    /// terminator and re-emits each one as `eol`. Used on the inbound
    /// decode path to align the decrypted inner body with the outer
    /// envelope's eol style — Mail's reader fails to walk a
    /// `multipart/*` body whose `--boundary` lines use a different
    /// line-ending than the surrounding headers, and falls back to
    /// rendering the whole body as `text/plain` (visible 2026-04-28
    /// on a Thunderbird-Android-encrypted mail: `kano1.eml`).
    static func rewriteLineEndings(_ data: Data, to eol: Data) -> Data {
        var out = Data()
        out.reserveCapacity(data.count + data.count / 32)
        var i = data.startIndex
        while i < data.endIndex {
            let byte = data[i]
            switch byte {
            case 0x0D:                              // CR (or CRLF)
                out.append(eol)
                let next = data.index(after: i)
                if next < data.endIndex && data[next] == 0x0A {
                    i = data.index(after: next)
                } else {
                    i = next
                }
            case 0x0A:                              // bare LF
                out.append(eol)
                i = data.index(after: i)
            default:
                out.append(byte)
                i = data.index(after: i)
            }
        }
        return out
    }

    /// Build the inner MIME part from an RFC 822 message: lift the
    /// Content-* headers down with the body, drop the outer-only
    /// envelope headers (From / To / Subject / Date / Message-ID
    /// etc.). The returned bytes are LF-form; canonicalize separately
    /// before signing.
    static func extractInnerPart(from rfc822: Data) throws -> Data {
        let split = try splitHeadersAndBody(rfc822)
        var out = Data()
        for header in split.headers where isInnerHeader(name: header.name) {
            appendHeader(into: &out, name: header.name, value: header.value)
        }
        // If the original carried no Content-Type, default to text/plain
        // so unwrapping clients don't choke. RFC 822 + RFC 2045 say
        // text/plain charset=us-ascii is the implicit default; emit it
        // explicitly as utf-8 since that's overwhelmingly what Mail.app
        // composes.
        if !split.headers.contains(where: { $0.name.lowercased() == "content-type" }) {
            appendHeader(
                into: &out,
                name: "Content-Type",
                value: "text/plain; charset=utf-8"
            )
        }
        out.append(crlf)
        out.append(split.body)
        return out
    }

    /// Assemble a render-friendly RFC 822 message from an inbound
    /// `multipart/encrypted` envelope + the decrypted inner MIME
    /// part. The result has the outer envelope's routing headers
    /// (From, To, Subject, Date, Message-Id, References, In-Reply-To,
    /// etc.) followed by the decrypted inner part's Content-* headers
    /// and body — i.e., what an unencrypted version of the same
    /// message would look like on the wire.
    ///
    /// Why this exists: `MEDecodedMessage.data` is what Mail's reader
    /// uses to lay out the message view AND what MFLibrary indexes
    /// for full-text search. Handing it just the inner part (no
    /// envelope) makes the body render empty in the reader and gives
    /// the indexer no recipients/subject to record. The outbound
    /// pre-cache solved this for messages we sent (cache `data` is
    /// the original draft); inbound decrypt has to synthesize the
    /// envelope from the encrypted message's outer headers.
    ///
    /// Drops outer Content-* and MIME-Version headers — the inner
    /// part carries its own. Drops Apple-internal `X-Apple-*`. Keeps
    /// everything else verbatim.
    static func assembleInboundDecodedMessage(
        envelopeSource: Data,
        decryptedInnerPart: Data
    ) throws -> Data {
        let envelopeSplit = try splitHeadersAndBody(envelopeSource)
        let innerSplit = try splitHeadersAndBody(decryptedInnerPart)
        let eol = detectLineEnding(in: envelopeSource)

        var out = Data()
        // 1. Outer envelope routing headers — drop Content-* (those
        //    describe the encrypted multipart wrapper, not the
        //    decrypted entity) and MIME-Version (we re-emit one);
        //    drop X-Apple-* compose-state.
        for header in envelopeSplit.headers
        where !isInnerHeader(name: header.name)
            && header.name.lowercased() != "mime-version"
            && !isAppleInternalHeader(name: header.name) {
            appendHeader(into: &out, name: header.name, value: header.value, eol: eol)
        }
        // 2. Inner part's Content-* headers, lifted UP onto the
        //    outer envelope. Without this lift, the assembled
        //    message has two header blocks separated by a blank
        //    line, and Mail's parser stops at the first blank line —
        //    so the inner Content-Type / Content-Transfer-Encoding
        //    lines render as literal body text in the message
        //    viewer (observed 2026-04-27 with the naive "concat
        //    envelope + inner-part-bytes" form).
        for header in innerSplit.headers where isInnerHeader(name: header.name) {
            appendHeader(into: &out, name: header.name, value: header.value, eol: eol)
        }
        appendHeader(into: &out, name: "MIME-Version", value: "1.0", eol: eol)

        // 3. Single blank line, then the inner part's body — with
        //    line endings rewritten to match `eol`. PGP/MIME bodies
        //    come back from `tclig --decrypt` in canonical CRLF form
        //    (RFC 3156); the outer envelope (built from
        //    `MEMessage.rawData`) is LF-only because Mail strips CR
        //    before invoking `decodedMessage(forMessageData:)`. A
        //    mixed-eol assembled message confuses Mail's reader: it
        //    can't match `\n--<boundary>\n` against the body's
        //    `\r\n--<boundary>\r\n` and falls back to rendering the
        //    whole body as `text/plain` — boundaries, inner headers,
        //    and quoted-printable escapes show up as literal text.
        out.append(eol)
        out.append(rewriteLineEndings(innerSplit.body, to: eol))
        return out
    }

    // MARK: - Header parsing / serialization

    struct ParsedHeader {
        let name: String
        let value: String
    }

    struct SplitMessage {
        let headers: [ParsedHeader]
        let body: Data
    }

    /// Split an RFC 822 message at the first blank line. Accepts
    /// either LF-only or CRLF blank-line separators — Apple Mail's
    /// `MEMessage.rawData` is LF-only, sendmail-bypass test fixtures
    /// are CRLF, and our own outgoing envelope mixes the two (LF outer
    /// + CRLF inner-part bytes between boundaries).
    ///
    /// Critical: pick whichever separator comes FIRST in the byte
    /// stream. A naive "look for CRLFCRLF, fall back to LFLF" scheme
    /// finds the inner `\r\n\r\n` between the part headers and part
    /// body inside the multipart, then incorrectly treats that as the
    /// outer header/body boundary — corrupting the header parse.
    /// MailGPG hit and documented exactly this in
    /// `mailgpg/MailGPG/GPGServiceImpl+MIME.swift:62-79`.
    static func splitHeadersAndBody(_ data: Data) throws -> SplitMessage {
        let crlfRange = data.range(of: crlfcrlf)
        let lflfRange = data.range(of: "\n\n".data(using: .ascii)!)

        let separatorRange: Range<Data.Index>
        switch (crlfRange, lflfRange) {
        case (let r?, let l?):
            separatorRange = r.lowerBound <= l.lowerBound ? r : l
        case (let r?, nil):
            separatorRange = r
        case (nil, let l?):
            separatorRange = l
        case (nil, nil):
            throw PGPMimeBuilderError.noBlankLineSeparator
        }

        let headerData = data.subdata(in: data.startIndex..<separatorRange.lowerBound)
        let body = data.subdata(in: separatorRange.upperBound..<data.endIndex)

        return SplitMessage(
            headers: try parseHeaders(headerData),
            body: body
        )
    }

    /// Parse RFC 822 headers, joining continuation lines (lines that
    /// start with whitespace) into the preceding header.
    static func parseHeaders(_ data: Data) throws -> [ParsedHeader] {
        guard let text = String(data: data, encoding: .utf8) else {
            throw PGPMimeBuilderError.malformedHeaders
        }

        // Normalize line endings so we can split uniformly.
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)

        var out: [ParsedHeader] = []
        var current: (name: String, value: String)?

        for line in lines {
            if line.isEmpty { continue }

            if line.first == " " || line.first == "\t" {
                guard var c = current else {
                    throw PGPMimeBuilderError.malformedHeaders
                }
                c.value += " " + line.trimmingCharacters(in: .whitespaces)
                current = c
                continue
            }

            // Flush previous.
            if let c = current {
                out.append(ParsedHeader(name: c.name, value: c.value))
            }
            // Parse `Name: Value`.
            guard let colon = line.firstIndex(of: ":") else {
                throw PGPMimeBuilderError.malformedHeaders
            }
            let name = String(line[..<colon])
            let valueStart = line.index(after: colon)
            let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
            current = (name, value)
        }
        if let c = current {
            out.append(ParsedHeader(name: c.name, value: c.value))
        }
        return out
    }

    /// Look up a single header value from raw RFC 822 bytes. Used by
    /// the decode-side cache so we can index an encoded message we
    /// just produced under its tracking IDs without re-parsing the
    /// whole envelope. Header names are case-insensitive (RFC 5322
    /// §2.2). Continuation lines are folded into the value with a
    /// single space, matching `parseHeaders`.
    ///
    /// Returns the FIRST occurrence. Some headers (Received, DKIM-
    /// Signature) repeat — callers that care about all values should
    /// use `splitHeadersAndBody` directly.
    static func headerValue(_ name: String, in data: Data) -> String? {
        let split: SplitMessage
        do {
            split = try splitHeadersAndBody(data)
        } catch {
            // Bytes don't have a blank-line separator (e.g. Mail's
            // header-only "still arriving" callbacks). Fall through
            // to header-only parse.
            guard let parsed = try? parseHeaders(data) else { return nil }
            return parsed.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame })?.value
        }
        return split.headers
            .first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame })?
            .value
    }

    /// Headers we keep on the OUTER multipart wrapper: the routing
    /// envelope. Anything that describes the BODY's Content-* moves
    /// down with the body into the inner MIME part.
    ///
    /// Also strips a small set of Apple-Mail-internal headers that
    /// the user's MEMessage.rawData carries from the compose draft.
    /// `X-Universally-Unique-Identifier` is the draft tracking UUID;
    /// keeping it on the encoded outgoing message makes Mail's
    /// `MFLibrary queueMessagesAddedNotification` pipeline crash
    /// with `*** -[__NSSetM addObject:]: object cannot be nil` when
    /// it tries to dereference the (now-stale) draft (verified by
    /// dumping the encoded bytes during a Mail.app crash). Sent
    /// messages don't need any of these — Mail synthesizes new
    /// tracking metadata for the Sent-folder copy itself.
    private static func retainOuterHeaders(_ all: [ParsedHeader]) -> [ParsedHeader] {
        all.filter { !isInnerHeader(name: $0.name) }
            .filter { $0.name.lowercased() != "mime-version" }    // we re-emit
            .filter { !isAppleInternalHeader(name: $0.name) }
    }

    /// Apple-Mail-internal compose-time headers we strip from the
    /// outgoing wrapper. `X-Apple-*` (Auto-Saved, Remote-Attachments,
    /// etc.) carry compose-state that Mail re-derives for the Sent
    /// copy on its own.
    ///
    /// Note: `X-Universally-Unique-Identifier` is deliberately
    /// preserved, despite an earlier analysis suggesting it should
    /// be stripped. The MFLibrary `-[__NSSetM addObject:]: object
    /// cannot be nil` crash that drove the strip-it diagnosis
    /// reproduces with the header stripped (verified four times on
    /// 2026-04-27). The Sent-folder library write appears to need
    /// the X-UUID to link the Sent copy back to the compose draft;
    /// without it, the reverse-lookup returns nil and trips the
    /// same crash by a different path.
    static func isAppleInternalHeader(name: String) -> Bool {
        let lc = name.lowercased()
        return lc.hasPrefix("x-apple-")
    }

    /// Headers that belong to the INNER MIME part (Content-*).
    /// MIME-Version is special-cased — emitted on the outer wrapper.
    static func isInnerHeader(name: String) -> Bool {
        let lc = name.lowercased()
        return lc.hasPrefix("content-")
    }

    private static func serializeHeaders(_ headers: [ParsedHeader], eol: Data = crlf) -> Data {
        var out = Data()
        for h in headers {
            appendHeader(into: &out, name: h.name, value: h.value, eol: eol)
        }
        return out
    }

    private static func appendHeader(into data: inout Data, name: String, value: String, eol: Data = crlf) {
        data.append("\(name): \(value)".data(using: .utf8)!)
        data.append(eol)
    }

    // MARK: - Boundary generation

    /// 16 hex chars + a stable prefix. Long enough that an RFC 2046
    /// boundary collision with quoted body content is astronomically
    /// unlikely.
    static func randomBoundary(prefix: String) -> String {
        let bytes = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return "\(prefix)-\(hex)"
    }
}

// MARK: - Helpers

private extension Data {
    /// Disambiguate from Foundation's `suffix(_:)` (returns Slice) by
    /// name — avoids a Swift name-clash with the parameter name.
    func hasSuffix(_ tail: Data) -> Bool {
        guard count >= tail.count else { return false }
        return subdata(in: (count - tail.count)..<count) == tail
    }
}
