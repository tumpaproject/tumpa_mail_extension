// SPDX-License-Identifier: GPL-3.0-or-later
//
// XPC contract between Tumpa Mail's MailKit extension (.appex) and the
// crypto-bearing XPC service bundle that lives inside the host app.
//
// Why an XPC service: the .appex is hard-sandboxed by Apple's MailKit
// runtime — it cannot open `~/.tumpa/agent.sock`, touch PCSC, or
// spawn `pinentry-mac`. The XPC service runs unsandboxed and is the
// only place libtumpa (linked in via UniFFI) is called. The host
// app UI uses the same XPC service for `listKeys` so there's one
// path to the crypto.
//
// All `Data` payloads are raw bytes — armored OpenPGP for signatures /
// ciphertext, UTF-8 text or binary for plaintext. The protocol does
// not interpret payloads; that work lives in `PGPMimeBuilder` and
// `PGPMimeParser` in the .appex.

import Foundation

@objc(TumpaCryptoXPC)
public protocol TumpaCryptoXPC {

    // MARK: - Signing (PGP/MIME multipart/signed)

    /// Detached signature over `canonicalizedBody` using the keystore key
    /// identified by `signerFingerprint`. The body must already be
    /// CRLF-canonicalized per RFC 3156 §5; the XPC service signs the
    /// bytes verbatim.
    ///
    /// `digest` is one of `"SHA256"`, `"SHA384"`, `"SHA512"`. If
    /// software signing is used, that hash is honored. If a card backs
    /// the key, the card chooses; in either case the reply's
    /// `actualDigest` reflects what the signature packet really uses,
    /// which the caller writes into the `multipart/signed` `micalg`
    /// parameter.
    ///
    /// `needsUnlockFingerprint` / `needsUnlockUid` / `needsUnlockIsPin`
    /// are populated when libtumpa needed a passphrase or smartcard
    /// PIN that wasn't in the agent / transient cache. The host app's
    /// Unlock pane (and the in-Mail unlock popover) drive a probe-then-
    /// prompt UX off these slots: an empty-secret `signDetached` call
    /// returns the trio so the UI knows whether to ask for a PIN or a
    /// passphrase, and against which key.
    func signDetached(
        canonicalizedBody: Data,
        signerFingerprint: String,
        digest: String,
        reply: @escaping (_ armoredSignature: Data?,
                          _ actualDigest: String?,
                          _ needsUnlockFingerprint: String?,
                          _ needsUnlockUid: String?,
                          _ needsUnlockIsPin: Bool,
                          _ error: NSError?) -> Void
    )

    // MARK: - Encryption (PGP/MIME multipart/encrypted)

    /// Encrypt `plaintext` to `recipientFingerprints`, optionally signing
    /// with `signerFingerprint` (the sign-then-encrypt path).
    ///
    /// When `signerFingerprint` is non-nil and the signer's key has a
    /// matching connected OpenPGP card, the inner signature is produced
    /// on the card; otherwise the software secret key is used (with
    /// passphrase via pinentry). Same reply shape for both backends.
    ///
    /// On per-recipient resolution failure the reply carries the
    /// invalid recipient identifiers in `invalidRecipients` (the
    /// typed `TumpaError.invalidRecipients` variant from libtumpa,
    /// preserving what was previously parsed from `[GNUPG:] INV_RECP`
    /// status lines) so the compose UI can show "no key for X"
    /// inline. When at least one recipient is invalid,
    /// `armoredCiphertext` is `nil` and `error` is set.
    func encrypt(
        plaintext: Data,
        recipientFingerprints: [String],
        signerFingerprint: String?,
        armor: Bool,
        reply: @escaping (_ armoredCiphertext: Data?,
                          _ invalidRecipients: [String],
                          _ needsUnlockFingerprint: String?,
                          _ needsUnlockUid: String?,
                          _ needsUnlockIsPin: Bool,
                          _ error: NSError?) -> Void
    )

    // MARK: - Decryption + verification (PGP/MIME inbound)

    /// Decrypt and verify the inner signature in one pass. The reply's
    /// `signatureStatus` is one of:
    /// - `"unsigned"` — encrypt-only payload, no inner sig.
    /// - `"good"` — inner signature verified by `signerFingerprint`.
    /// - `"bad"` — signer was found in keystore but signature did not
    ///   verify.
    /// - `"unknown"` — inner signature present, signer not in keystore;
    ///   `signerKeyId` is the issuer key ID for display.
    ///
    /// Card-first dispatch: when the user's decryption subkey lives on a
    /// connected OpenPGP card, the card decrypts the session key and the
    /// inner-signature classification runs in software; otherwise the
    /// software secret key (with passphrase via pinentry) is used. The
    /// reply shape is identical for both backends.
    ///
    /// Plaintext is returned regardless of signature outcome (matching
    /// Thunderbird / GPG Suite behavior — the user sees the body with
    /// a banner). Caller is responsible for memory hygiene of the
    /// returned `Data`.
    func decryptVerify(
        armoredCiphertext: Data,
        reply: @escaping (_ plaintext: Data?,
                          _ signatureStatus: String,
                          _ signerFingerprint: String?,
                          _ signerKeyId: String?,
                          _ signerUid: String?,
                          _ needsUnlockFingerprint: String?,
                          _ needsUnlockUid: String?,
                          _ needsUnlockIsPin: Bool,
                          _ error: NSError?) -> Void
    )

    // MARK: - Verification (PGP/MIME multipart/signed inbound)

    /// Verify a detached signature over `signedBytes` (already
    /// CRLF-canonicalized by the caller per RFC 3156).
    ///
    /// `signerFingerprint` is the 40-char OpenPGP fingerprint parsed
    /// from `[GNUPG:] VALIDSIG`; `signerKeyId` is the 16-char trailing
    /// key ID parsed from `[GNUPG:] GOODSIG / BADSIG / NO_PUBKEY`. Both
    /// can be present together on a successful verify; the caller's
    /// popover prefers the fingerprint and falls back to the key ID.
    func verifyDetached(
        signedBytes: Data,
        armoredSignature: Data,
        reply: @escaping (_ status: String,
                          _ signerFingerprint: String?,
                          _ signerKeyId: String?,
                          _ signerUid: String?,
                          _ error: NSError?) -> Void
    )

    // MARK: - Keystore lookup (compose UI helpers)

    /// List keys in the user's tumpa keystore (`~/.tumpa/keys.db`),
    /// in the same shape `tclig --list-keys --with-colons` returns.
    /// Used by the host app's key picker and the .appex's compose-time
    /// "do I have a signing key for this From address" check.
    func listKeys(
        reply: @escaping (_ keys: [TumpaKeyInfo],
                          _ error: NSError?) -> Void
    )

    /// Render a multi-line `tcli describe`-shaped key summary for one
    /// keystore key. Used by the host app's "Key details" sheet so the
    /// UI text stays byte-for-byte identical to `tcli describe <fp>`.
    /// Includes the trailing `Cards:` block when the keystore has
    /// linked card rows for the fingerprint.
    func describeKey(
        fingerprint: String,
        reply: @escaping (_ details: String?,
                          _ error: NSError?) -> Void
    )

    /// Resolve a list of email addresses to keystore fingerprints.
    /// The reply's `resolved` dictionary contains only the emails that
    /// matched a usable key (uppercase hex, 40-char primary fingerprint);
    /// inputs absent from the dictionary are unresolved. `[String: String?]`
    /// is not Obj-C-bridgeable across XPC, so the caller diffs against
    /// the input list rather than getting explicit `nil` slots.
    /// `resolveRecipients(["alice@x", "bob@y"])` is the call the
    /// .appex makes during compose to drive the lock indicator.
    func resolveRecipients(
        emails: [String],
        reply: @escaping (_ resolved: [String: String],
                          _ error: NSError?) -> Void
    )

    // MARK: - Agent cache (in-Mail unlock flow)

    /// Write `secret` into the tumpa agent cache at
    /// `~/.tumpa/agent.sock` under the slot determined by `isPin`
    /// (`pin:<fp>` for smartcard PINs, `passphrase:<fp>` for
    /// software-key passphrases). Same namespacing tcli /
    /// tpass / tclig use, so once the popover writes here every
    /// subsequent crypto op (Mail extension, host UI, or any other
    /// tumpa client) reuses the cached secret.
    ///
    /// Reply `success: false` means the agent isn't running or
    /// rejected the request — the .appex's popover surfaces that as
    /// an error so the user can re-launch the agent and retry.
    ///
    /// The .appex is sandboxed and CANNOT reach the agent socket
    /// directly; this XPC method is the only path for the .appex's
    /// in-Mail unlock UI to populate the cache.
    func cachePassphrase(
        fingerprint: String,
        isPin: Bool,
        secret: Data,
        reply: @escaping (_ success: Bool, _ error: NSError?) -> Void
    )

    // MARK: - Health

    /// Whether `~/.tumpa/agent.sock` exists right now. Drives the
    /// host's StatusView "Agent" indicator. The host UI is sandboxed
    /// and can't reach the user's home directory itself, so the
    /// (unsandboxed) XPC service does the `fileExists` probe.
    ///
    /// Note: `tcligVersion` was removed when the XPC service stopped
    /// spawning `tclig` and started linking libtumpa directly via
    /// UniFFI. There is no separate `tclig` binary to version-check
    /// anymore — the crypto code is part of the XPC binary itself.
    func agentSocketExists(
        reply: @escaping (_ exists: Bool) -> Void
    )
}

// MARK: - Shared models

/// A keystore key as the picker / compose-status code wants it. Mirrors
/// the columns of `tclig --list-keys --with-colons` we care about.
@objc(TumpaKeyInfo)
public final class TumpaKeyInfo: NSObject, NSSecureCoding, Codable {
    public static var supportsSecureCoding: Bool { true }

    @objc public let fingerprint: String
    @objc public let primaryUid: String
    @objc public let isSecret: Bool
    @objc public let hasCard: Bool
    @objc public let isRevoked: Bool
    @objc public let isExpired: Bool

    public init(fingerprint: String,
                primaryUid: String,
                isSecret: Bool,
                hasCard: Bool,
                isRevoked: Bool,
                isExpired: Bool) {
        self.fingerprint = fingerprint
        self.primaryUid = primaryUid
        self.isSecret = isSecret
        self.hasCard = hasCard
        self.isRevoked = isRevoked
        self.isExpired = isExpired
    }

    public required convenience init?(coder: NSCoder) {
        guard
            let fp = coder.decodeObject(of: NSString.self, forKey: "fingerprint") as String?,
            let uid = coder.decodeObject(of: NSString.self, forKey: "primaryUid") as String?
        else { return nil }
        self.init(
            fingerprint: fp,
            primaryUid: uid,
            isSecret: coder.decodeBool(forKey: "isSecret"),
            hasCard: coder.decodeBool(forKey: "hasCard"),
            isRevoked: coder.decodeBool(forKey: "isRevoked"),
            isExpired: coder.decodeBool(forKey: "isExpired")
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(fingerprint as NSString, forKey: "fingerprint")
        coder.encode(primaryUid as NSString, forKey: "primaryUid")
        coder.encode(isSecret, forKey: "isSecret")
        coder.encode(hasCard, forKey: "hasCard")
        coder.encode(isRevoked, forKey: "isRevoked")
        coder.encode(isExpired, forKey: "isExpired")
    }
}

/// String constants used in `signatureStatus` reply slot above. Kept
/// as raw strings so the @objc protocol stays Foundation-only (no
/// custom enums cross XPC).
public enum TumpaSignatureStatus {
    public static let unsigned = "unsigned"
    public static let good = "good"
    public static let bad = "bad"
    public static let unknown = "unknown"
}

/// XPC service bundle identifier. `NSXPCConnection(serviceName:)`
/// looks up an XPC service bundle by its CFBundleIdentifier — so this
/// MUST match the `PRODUCT_BUNDLE_IDENTIFIER` of the
/// `TumpaCryptoXPC` target in `project.yml`. Both the host UI and the
/// .appex import this constant.
public let TumpaCryptoXPCServiceName = "in.kushaldas.tumpamail.crypto"

/// App Group used to share preferences (default signer fingerprint,
/// preferred digest, …) between the host UI and the sandboxed .appex.
/// `UserDefaults.standard` is per-process and inaccessible from a
/// sandboxed extension; an App Group lets both ends see the same
/// defaults plist.
///
/// MUST match the entry in both targets' `.entitlements` under
/// `com.apple.security.application-groups`.
public let TumpaMailSharedSuite = "group.in.kushaldas.tumpamail"

/// Shared `UserDefaults` keys.
public enum TumpaMailDefaults {
    public static let defaultDigest = "defaultDigest"
    public static let alwaysSign = "alwaysSign"
    public static let preferEncryptedReplies = "preferEncryptedReplies"
}
