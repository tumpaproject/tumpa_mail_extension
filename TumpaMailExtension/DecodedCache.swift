// SPDX-License-Identifier: GPL-3.0-or-later
//
// A small, thread-safe, bounded content-keyed cache used by the
// inbound decode path to avoid re-decrypting the same message on every
// `decodedMessage(forMessageData:)` call. Extracted into its own type
// so the eviction semantics can be unit-tested without MailKit.

import CryptoKit
import Foundation

/// Stable lowercase-hex SHA-256 of `data`, used as the cache key for a
/// decoded message. Keying on the exact bytes Mail handed us means the
/// viewer, the standalone-window open, and the library indexer all
/// share one decode for a given message.
func contentCacheKey(for data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

/// Insertion-ordered, count-bounded cache. On insert past `capacity`
/// the oldest-inserted entry is evicted. Re-inserting an existing key
/// updates the value in place without changing its eviction position or
/// growing the cache. Bounded by entry count (not bytes) because each
/// cached value can hold a multi-MB decrypted body; a small cap keeps
/// worst-case memory predictable.
final class BoundedContentCache<Value> {
    private var store: [String: Value] = [:]
    private var order: [String] = []
    private let capacity: Int
    private let lock = NSLock()

    init(capacity: Int) {
        precondition(capacity > 0, "capacity must be positive")
        self.capacity = capacity
    }

    func value(forKey key: String) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return store[key]
    }

    func insert(_ value: Value, forKey key: String) {
        lock.lock()
        defer { lock.unlock() }
        if store[key] == nil {
            order.append(key)
            while order.count > capacity {
                let evicted = order.removeFirst()
                store.removeValue(forKey: evicted)
            }
        }
        store[key] = value
    }

    /// Test/diagnostic hook: current number of cached entries.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return store.count
    }
}
