// SPDX-License-Identifier: GPL-3.0-or-later
//
// Inbound side of the PGP/MIME plumbing. Given the raw RFC 822 bytes
// of an incoming message, classify it and pull out the parts the
// decoder needs:
//
//   • multipart/encrypted — extract the application/octet-stream part
//     that holds the OpenPGP ciphertext.
//   • multipart/signed   — extract the signed-part bytes verbatim
//     (boundary-to-boundary, with the bytes the sender's signature
//     was made over) PLUS the detached application/pgp-signature
//     part.
//
// The signed-part extraction is the subtle one: RFC 3156 §5.1 says
// the verifier MUST hash the bytes of the signed entity exactly as
// they appear in the multipart body, including its own headers, with
// CRLF canonicalization. We slice the original message bytes between
// the boundary delimiters rather than re-serializing parsed headers,
// so any header ordering, whitespace, or charset quirks the sender
// cared about survive.

import Foundation

/// Top-level classification of an inbound RFC 822 message.
enum InboundClassification {
    /// `multipart/encrypted; protocol=application/pgp-encrypted`. The
    /// associated value is the armored OpenPGP ciphertext extracted
    /// from the message's second body part.
    case pgpEncrypted(ciphertext: Data)

    /// `multipart/signed; protocol=application/pgp-signature`. Carries
    /// the byte-exact signed entity (for verification) plus the
    /// detached signature.
    case pgpSigned(signedPart: Data, signature: Data, micalg: String?)

    /// Anything else — Mail's native MIME pipeline handles it.
    case notPGP
}

enum PGPMimeParserError: Error, LocalizedError {
    case malformed(String)

    var errorDescription: String? {
        switch self {
        case .malformed(let s): return "PGP/MIME message malformed: \(s)"
        }
    }
}

enum PGPMimeParser {

    /// Cheap precheck: does this RFC 822 message contain the textual
    /// markers of a PGP/MIME signed or encrypted body? Lets the common
    /// case (a non-PGP message in the inbox) skip the full classify +
    /// XPC round-trip — Mail's indexer calls `decodedMessage` on
    /// EVERY received message during scan, so we MUST short-circuit
    /// the boring 99% or we churn `tclig` for nothing.
    ///
    /// MUST scan the WHOLE message: an earlier prefix-only version
    /// (8 KiB) silently rejected legitimately-signed mail routed
    /// through Microsoft 365 / Exchange, where the ARC + DKIM +
    /// `x-ms-*` + `x-microsoft-antispam-messagedata-*` header pile
    /// alone exceeds 8 KiB and pushes the outer
    /// `Content-Type: multipart/signed` line past the cutoff
    /// (observed 2026-04-28 with `jocar1.eml`). The `O(n)` byte scan
    /// is cheap; the savings vs. spawning `tclig` come from skipping
    /// the XPC round-trip, not from how little we look at.
    ///
    /// Lossy UTF-8 decode (replaces invalid bytes; never fails) so
    /// we can use the standard case-insensitive `range(of:options:)`
    /// search — RFC 2045 §5.1 mandates case-insensitive matching for
    /// MIME type/subtype tokens.
    static func hasPGPMarkers(in data: Data) -> Bool {
        let s = String(decoding: data, as: UTF8.self)
        let opts: String.CompareOptions = [.caseInsensitive, .literal]
        let signed = s.range(of: "multipart/signed", options: opts) != nil
            && s.range(of: "application/pgp-signature", options: opts) != nil
        let encrypted = s.range(of: "multipart/encrypted", options: opts) != nil
            && s.range(of: "application/pgp-encrypted", options: opts) != nil
        return signed || encrypted
    }

    /// Classify a top-level RFC 822 message.
    static func classify(_ raw: Data) -> InboundClassification {
        do {
            let split = try PGPMimeBuilder.splitHeadersAndBody(raw)
            let contentType = split.headers
                .first(where: { $0.name.lowercased() == "content-type" })?
                .value ?? ""
            let lc = contentType.lowercased()

            if lc.hasPrefix("multipart/encrypted") &&
                contentTypeMatchesProtocol(contentType, "application/pgp-encrypted") {
                return classifyEncrypted(split: split, headerValue: contentType)
            }

            if lc.hasPrefix("multipart/signed") &&
                contentTypeMatchesProtocol(contentType, "application/pgp-signature") {
                return classifySigned(rawMessage: raw, split: split, headerValue: contentType)
            }
        } catch {
            // Anything malformed is "not PGP" from our point of view —
            // Mail's pipeline will deal with it and we won't claim it.
        }
        return .notPGP
    }

    // MARK: - multipart/encrypted

    private static func classifyEncrypted(
        split: PGPMimeBuilder.SplitMessage,
        headerValue: String
    ) -> InboundClassification {
        guard let boundary = parseBoundary(from: headerValue) else {
            return .notPGP
        }
        let parts = sliceParts(body: split.body, boundary: boundary)
        // RFC 3156 §4: the encrypted message has two parts. The first
        // is the version control packet (application/pgp-encrypted,
        // body "Version: 1"). The second is the actual ciphertext as
        // application/octet-stream.
        guard parts.count >= 2 else { return .notPGP }

        // We accept the first part with Content-Type
        // application/pgp-encrypted as the version part, and the next
        // application/octet-stream as the ciphertext. Some senders
        // produce only the ciphertext part with the right
        // Content-Type, so we pick the first octet-stream regardless
        // of position.
        for partBytes in parts {
            guard
                let inner = try? PGPMimeBuilder.splitHeadersAndBody(partBytes),
                let ct = inner.headers.first(where: { $0.name.lowercased() == "content-type" })
            else {
                continue
            }
            if ct.value.lowercased().hasPrefix("application/octet-stream") {
                return .pgpEncrypted(ciphertext: stripTrailingCRLF(inner.body))
            }
        }
        return .notPGP
    }

    // MARK: - multipart/signed

    private static func classifySigned(
        rawMessage: Data,
        split: PGPMimeBuilder.SplitMessage,
        headerValue: String
    ) -> InboundClassification {
        guard let boundary = parseBoundary(from: headerValue) else {
            return .notPGP
        }
        let micalg = parseMicalg(from: headerValue)

        // Find the boundary positions in the ORIGINAL body bytes. We
        // must NOT round-trip through the parsed-headers form — the
        // signed entity is the byte-exact subsection of the input.
        let positions = findBoundaryPositions(body: split.body, boundary: boundary)
        guard positions.count >= 3 else {
            // Need at least: opener, separator-after-signed-part,
            // closing `--boundary--`. (3 boundaries → 2 parts.)
            return .notPGP
        }

        // The signed entity is between boundary[0] and boundary[1].
        // The detached signature is between boundary[1] and boundary[2].
        let signedEntityRange = byteRangeBetweenBoundaries(
            body: split.body,
            firstStart: positions[0],
            secondStart: positions[1]
        )
        let signatureRange = byteRangeBetweenBoundaries(
            body: split.body,
            firstStart: positions[1],
            secondStart: positions[2]
        )

        let signedEntity = split.body.subdata(in: signedEntityRange)
        let signaturePart = split.body.subdata(in: signatureRange)

        // The signature part has a small header block + the armored
        // signature bytes. The signed entity, however, must be passed
        // verbatim — it includes its own MIME headers.
        guard let parsedSig = try? PGPMimeBuilder.splitHeadersAndBody(signaturePart) else {
            return .notPGP
        }
        let armoredSignature = stripTrailingCRLF(parsedSig.body)

        return .pgpSigned(
            signedPart: signedEntity,
            signature: armoredSignature,
            micalg: micalg
        )
    }

    // MARK: - Multipart slicing

    /// Slice the body at every `--boundary` line and return each part
    /// (without the boundary lines themselves, but with the part's
    /// own MIME headers and content). Used for the encrypted-message
    /// path, which doesn't need byte-exact reproduction.
    static func sliceParts(body: Data, boundary: String) -> [Data] {
        let positions = findBoundaryPositions(body: body, boundary: boundary)
        guard positions.count >= 2 else { return [] }
        var parts: [Data] = []
        for i in 0..<(positions.count - 1) {
            let range = byteRangeBetweenBoundaries(
                body: body,
                firstStart: positions[i],
                secondStart: positions[i + 1]
            )
            if !range.isEmpty {
                parts.append(body.subdata(in: range))
            }
        }
        return parts
    }

    /// Find the byte offsets of every boundary delimiter line in
    /// `body`. A boundary line is `--boundary` at the start of a line
    /// (after CRLF or LF, or at offset 0). The returned offsets point
    /// at the leading `-` of `--boundary`.
    static func findBoundaryPositions(body: Data, boundary: String) -> [Int] {
        let needle = "--\(boundary)"
        guard let needleData = needle.data(using: .ascii) else { return [] }
        var offsets: [Int] = []
        var search = body.startIndex
        while search < body.endIndex {
            guard
                let r = body.range(of: needleData, in: search..<body.endIndex)
            else {
                break
            }
            // Boundary must start a line: either at offset 0, or
            // preceded by LF / CRLF.
            if r.lowerBound == 0 ||
                body[r.lowerBound - 1] == 0x0A {
                offsets.append(r.lowerBound)
            }
            search = body.index(after: r.lowerBound)
        }
        return offsets
    }

    /// Compute the byte range for the part body lying between two
    /// boundary delimiters. The range starts AFTER the CRLF (or LF)
    /// that terminates the first boundary line, and ENDS BEFORE the
    /// CRLF (or LF) preceding the second boundary line. Per RFC 2046,
    /// that CRLF before the second boundary is part of the boundary
    /// delimiter, not the part content.
    static func byteRangeBetweenBoundaries(
        body: Data,
        firstStart: Int,
        secondStart: Int
    ) -> Range<Int> {
        // Skip the first boundary line: walk forward to the next LF.
        var partStart = firstStart
        while partStart < secondStart && body[partStart] != 0x0A {
            partStart += 1
        }
        if partStart < secondStart { partStart += 1 }   // skip the LF

        // The CRLF immediately preceding `secondStart` is part of the
        // boundary delimiter. Trim it off.
        var partEnd = secondStart
        if partEnd > partStart && body[partEnd - 1] == 0x0A {
            partEnd -= 1
            if partEnd > partStart && body[partEnd - 1] == 0x0D {
                partEnd -= 1
            }
        }

        if partEnd < partStart { return partStart..<partStart }
        return partStart..<partEnd
    }

    // MARK: - Content-Type header dissection

    /// Parse the `boundary=…` parameter from a Content-Type value.
    /// Handles both quoted (`boundary="abc"`) and unquoted forms and
    /// is tolerant of leading whitespace / case. Returns nil when no
    /// boundary parameter is present (in which case the message is
    /// invalid multipart).
    static func parseBoundary(from contentType: String) -> String? {
        parseParameter(from: contentType, key: "boundary")
    }

    /// Parse the `micalg=…` parameter (the OpenPGP hash algorithm
    /// label, e.g. `pgp-sha256`).
    static func parseMicalg(from contentType: String) -> String? {
        parseParameter(from: contentType, key: "micalg")?.lowercased()
    }

    /// Parse the `protocol=…` parameter and confirm it equals
    /// `expected` (case-insensitive). Returns true when it matches OR
    /// when the parameter is absent — RFC 3156 §4 requires it but a
    /// few legacy senders omit it; we accept those rather than
    /// rejecting otherwise-valid PGP/MIME mail.
    static func contentTypeMatchesProtocol(_ contentType: String, _ expected: String) -> Bool {
        guard let p = parseParameter(from: contentType, key: "protocol") else { return true }
        return p.lowercased() == expected.lowercased()
    }

    /// Common parameter parser for Content-Type values. Tolerant of
    /// whitespace, parameter ordering, and folded headers. Quotes are
    /// stripped from the value.
    static func parseParameter(from header: String, key: String) -> String? {
        // Split on `;`, ignoring `;` inside quoted strings. RFC 822
        // header values can contain quoted-string parameters; a naive
        // split would break boundary= values that contain semicolons.
        var parts: [String] = []
        var current = ""
        var inQuotes = false
        for c in header {
            if c == "\"" {
                inQuotes.toggle()
                current.append(c)
            } else if c == ";" && !inQuotes {
                parts.append(current)
                current = ""
            } else {
                current.append(c)
            }
        }
        if !current.isEmpty { parts.append(current) }

        let needle = key.lowercased() + "="
        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix(needle) {
                var v = String(trimmed.dropFirst(needle.count))
                if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
                    v = String(v.dropFirst().dropLast())
                }
                return v
            }
        }
        return nil
    }

    // MARK: - Helpers

    /// Strip a trailing CRLF / LF from `data`. Multipart parts we
    /// extract above already exclude the boundary-preceding CRLF, but
    /// sub-headers' parsers can leave a stray newline at the end of
    /// the body region.
    private static func stripTrailingCRLF(_ data: Data) -> Data {
        var end = data.count
        if end > 0 && data[end - 1] == 0x0A {
            end -= 1
            if end > 0 && data[end - 1] == 0x0D {
                end -= 1
            }
        }
        if end == data.count { return data }
        return data.subdata(in: 0..<end)
    }
}
