// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tests for the inbound-decode performance fixes:
//
//   1. `BoundedContentCache` — the content-keyed decode cache that
//      stops `decodedMessage(forMessageData:)` from re-decrypting the
//      same (potentially multi-MB) message on every viewer / indexer
//      call. Verifies hit/miss, count-bounded eviction of the
//      oldest entry, and in-place update of an existing key.
//
//   2. The empty-ciphertext precondition — `PGPMimeParser.classify`
//      returns `.pgpEncrypted` with ZERO ciphertext bytes for a
//      degenerate `multipart/encrypted` message. The decode path
//      short-circuits to nil on that, avoiding a pointless XPC trip
//      and the libtumpa software-key fan-out (each missing key
//      otherwise triggers an agent prompt that can block for seconds).

import XCTest

final class BoundedContentCacheTests: XCTestCase {

    func testInsertThenLookupHits() {
        let cache = BoundedContentCache<Int>(capacity: 4)
        cache.insert(42, forKey: "a")
        XCTAssertEqual(cache.value(forKey: "a"), 42)
    }

    func testLookupMissReturnsNil() {
        let cache = BoundedContentCache<Int>(capacity: 4)
        cache.insert(1, forKey: "a")
        XCTAssertNil(cache.value(forKey: "absent"))
    }

    func testEvictsOldestPastCapacity() {
        let cache = BoundedContentCache<Int>(capacity: 2)
        cache.insert(1, forKey: "a")
        cache.insert(2, forKey: "b")
        cache.insert(3, forKey: "c") // evicts "a", the oldest

        XCTAssertNil(cache.value(forKey: "a"), "oldest entry must be evicted")
        XCTAssertEqual(cache.value(forKey: "b"), 2)
        XCTAssertEqual(cache.value(forKey: "c"), 3)
        XCTAssertEqual(cache.count, 2, "count stays bounded at capacity")
    }

    func testReinsertExistingKeyUpdatesInPlaceWithoutEviction() {
        let cache = BoundedContentCache<Int>(capacity: 2)
        cache.insert(1, forKey: "a")
        cache.insert(2, forKey: "b")
        // Re-inserting "a" must NOT grow the cache or evict "b" — it's
        // an update of the existing slot, not a new entry.
        cache.insert(99, forKey: "a")

        XCTAssertEqual(cache.value(forKey: "a"), 99)
        XCTAssertEqual(cache.value(forKey: "b"), 2, "re-insert must not evict an existing key")
        XCTAssertEqual(cache.count, 2)
    }

    func testContentCacheKeyIsStableAndDistinct() {
        let a1 = contentCacheKey(for: Data("hello world".utf8))
        let a2 = contentCacheKey(for: Data("hello world".utf8))
        let b = contentCacheKey(for: Data("hello worle".utf8))

        XCTAssertEqual(a1, a2, "same bytes must hash to the same key")
        XCTAssertNotEqual(a1, b, "different bytes must hash to different keys")
        XCTAssertEqual(a1.count, 64, "SHA-256 hex is 64 chars")
    }
}

final class EmptyCiphertextClassificationTests: XCTestCase {

    /// A `multipart/encrypted` envelope whose `application/octet-stream`
    /// part has an empty body classifies as `.pgpEncrypted` with zero
    /// ciphertext bytes. `decodedMessage` keys its short-circuit off
    /// exactly this (`ciphertext.isEmpty`) to bail before any decrypt.
    func testEmptyOctetStreamYieldsEmptyCiphertext() {
        let bnd = "tumpa-enc-boundary"
        let raw = Data([
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\(bnd)\"",
            "MIME-Version: 1.0",
            "",
            "--\(bnd)",
            "Content-Type: application/pgp-encrypted",
            "",
            "Version: 1",
            "--\(bnd)",
            "Content-Type: application/octet-stream",
            "",
            // header/body separator above, then an empty (CRLF-only)
            // body that strips to zero ciphertext bytes
            "",
            "--\(bnd)--",
            ""
        ].joined(separator: "\r\n").utf8)

        switch PGPMimeParser.classify(raw) {
        case .pgpEncrypted(let ciphertext):
            XCTAssertTrue(ciphertext.isEmpty,
                          "empty octet-stream part must yield empty ciphertext (drives the nil short-circuit)")
        default:
            XCTFail("a multipart/encrypted envelope should classify as pgpEncrypted")
        }
    }

    /// Sanity counterpart: a non-empty octet-stream part yields
    /// non-empty ciphertext, so the short-circuit does NOT fire for a
    /// real message.
    func testNonEmptyOctetStreamYieldsCiphertext() {
        let bnd = "tumpa-enc-boundary"
        let raw = Data([
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\(bnd)\"",
            "MIME-Version: 1.0",
            "",
            "--\(bnd)",
            "Content-Type: application/pgp-encrypted",
            "",
            "Version: 1",
            "--\(bnd)",
            "Content-Type: application/octet-stream",
            "",
            "-----BEGIN PGP MESSAGE-----",
            "",
            "hQEMA0xyz...not-real-but-non-empty",
            "-----END PGP MESSAGE-----",
            "--\(bnd)--",
            ""
        ].joined(separator: "\r\n").utf8)

        switch PGPMimeParser.classify(raw) {
        case .pgpEncrypted(let ciphertext):
            XCTAssertFalse(ciphertext.isEmpty)
        default:
            XCTFail("a multipart/encrypted envelope should classify as pgpEncrypted")
        }
    }
}
