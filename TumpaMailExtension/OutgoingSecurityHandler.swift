// SPDX-License-Identifier: GPL-3.0-or-later
//
// MailKit's `MEMessageSecurityHandler` lives at the intersection of
// the encoder (outgoing) and decoder (incoming) protocols. Phase 2
// fills in the encoder side; Phase 3 will fill in
// `decodedMessageForMessageData:` for inbound mail.
//
// Two callback methods Mail invokes on this handler:
//
//   • getEncodingStatus(for:composeContext:completionHandler:)
//     Called whenever the From / To / Cc / Bcc set changes during
//     compose. We return `MEOutgoingMessageEncodingStatus` describing
//     whether sign / encrypt are possible right now and which
//     recipients are missing keys.
//
//   • encodeMessage(_:composeContext:completionHandler:)
//     Called when the user clicks Send. We get the assembled RFC-822
//     bytes, do the OpenPGP work via XPC + the PGP/MIME framer, and
//     hand back the wrapped bytes for Mail to transmit.
//
// All crypto goes through `TumpaCryptoXPC` — this file only contains
// MailKit glue + decisions about which path (sign / encrypt /
// sign-then-encrypt / nothing) to take based on `composeContext`.

import Foundation
import MailKit
import os.log

/// Dedicated logger for the .appex so we can grep `log stream` for
/// `subsystem == "in.kushaldas.tumpamail.extension"` and see exactly
/// which capability check / encoding step is firing.
private let log = Logger(
    subsystem: "in.kushaldas.tumpamail.extension",
    category: "outgoing"
)

@objc(TumpaOutgoingSecurityHandler)
final class TumpaOutgoingSecurityHandler: NSObject, MEMessageSecurityHandler {

    private let xpc = XPCClient()

    // MARK: - UUID-keyed encode cache
    //
    // Mail invokes `encode()` multiple times for the same logical
    // message (auto-save → real send → Sent-folder copy) and calls
    // `decodedMessage(forMessageData:)` 10+ times for inbound mail
    // during indexing. We cache by `X-Universally-Unique-Identifier`
    // so only the first call actually hits tclig — subsequent calls
    // for the same UUID return the same bytes. Mirrors
    // mailgpg/MailGPGExtension/MessageSecurityHandler.swift:19-64.
    //
    // The `decodedMessage` slot is populated speculatively on
    // outgoing encode (so Mail's indexer can short-circuit when it
    // re-reads the encrypted Sent copy); inbound use lands when
    // Phase 3 enables `decodedMessage(forMessageData:)`.
    struct UUIDCacheEntry {
        let encodeResult: MEMessageEncodingResult?
        let decodedMessage: MEDecodedMessage?
    }
    private var uuidCache: [String: UUIDCacheEntry] = [:]
    private let uuidCacheLock = NSLock()

    private func cachedEncodeResult(for uuid: String?) -> MEMessageEncodingResult? {
        guard let uuid else { return nil }
        uuidCacheLock.lock()
        defer { uuidCacheLock.unlock() }
        return uuidCache[uuid]?.encodeResult
    }

    private func storeEncodeResult(_ result: MEMessageEncodingResult, for uuid: String) {
        uuidCacheLock.lock()
        defer { uuidCacheLock.unlock() }
        let prior = uuidCache[uuid]
        uuidCache[uuid] = UUIDCacheEntry(
            encodeResult: result,
            decodedMessage: prior?.decodedMessage
        )
    }

    /// Look up a pre-built `MEDecodedMessage` by either tracking key.
    /// `X-Universally-Unique-Identifier` is preferred for messages we
    /// just encoded (carried over from the compose draft); `Message-Id`
    /// is the fallback that survives onto the encoded RFC 822 wrapper
    /// and matches when MFLibrary indexes the Sent copy. The first
    /// non-nil hit wins.
    private func cachedDecodedMessage(uuid: String?, messageId: String?) -> MEDecodedMessage? {
        uuidCacheLock.lock()
        defer { uuidCacheLock.unlock() }
        if let u = uuid, let entry = uuidCache[u], let decoded = entry.decodedMessage {
            return decoded
        }
        if let m = messageId, let entry = uuidCache[m], let decoded = entry.decodedMessage {
            return decoded
        }
        return nil
    }

    /// Stash a pre-built `MEDecodedMessage` under each tracking key we
    /// know for the message: the compose UUID (alive only until Mail
    /// strips it on egress) AND the Message-Id (which survives onto
    /// the wire and is what MFLibrary's Sent-copy indexer reads back).
    /// Storing under both removes the gap where the indexer sees only
    /// the Message-Id form and would otherwise miss the cache.
    private func storeDecodedMessage(_ decoded: MEDecodedMessage, uuid: String?, messageId: String?) {
        uuidCacheLock.lock()
        defer { uuidCacheLock.unlock() }
        for key in [uuid, messageId].compactMap({ $0 }) where !key.isEmpty {
            let prior = uuidCache[key]
            uuidCache[key] = UUIDCacheEntry(
                encodeResult: prior?.encodeResult,
                decodedMessage: decoded
            )
        }
    }

    // The host app's Keys pane writes the user's default signing key
    // into the shared App Group `UserDefaults`. The .appex reads it
    // here. Both targets carry the
    // `com.apple.security.application-groups` entitlement with
    // `TumpaMailSharedSuite` listed.
    private var sharedDefaults: UserDefaults? {
        UserDefaults(suiteName: TumpaMailSharedSuite)
    }
    private var preferredDigest: String {
        sharedDefaults?.string(forKey: TumpaMailDefaults.defaultDigest) ?? "SHA256"
    }
    /// "Sign every outgoing message by default" — host UI toggle in
    /// Settings. When true, encode() opts the message into signing
    /// even if Mail's compose UI didn't toggle Sign, BUT only when
    /// the From address has a key in the keystore (best-effort: a
    /// missing key for that account must NOT fail the send).
    private var alwaysSignPreference: Bool {
        sharedDefaults?.bool(forKey: TumpaMailDefaults.alwaysSign) ?? false
    }

    // MARK: - MEMessageEncoder (outgoing)

    func getEncodingStatus(
        for message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void
    ) {
        let from = message.fromAddress.addressString ?? ""
        let recipients: [String] = (message.toAddresses + message.ccAddresses + message.bccAddresses)
            .compactMap { $0.addressString }

        log.info("getEncodingStatus from=\(from, privacy: .public) recipients=\(recipients, privacy: .public)")

        Task {
            // Sign capability: we can sign iff the From address
            // resolves to a secret key in the keystore. A single Mail
            // install can host multiple accounts, so the choice of
            // signing key MUST follow the message's From header — not
            // a global default.
            var canSign = false
            do {
                let resolved = try await xpc.resolveRecipients([from])
                log.info("resolveRecipients(from)=\(resolved, privacy: .public)")
                canSign = resolved[from] != nil
            } catch {
                log.error("resolveRecipients(from) failed: \(error.localizedDescription, privacy: .public)")
                canSign = false
            }

            // Encrypt capability: every recipient must resolve to a
            // key. Missing ones populate `addressesFailingEncryption`
            // so Mail's compose UI can put a red dot on the chip.
            var canEncrypt = !recipients.isEmpty
            var missing: [MEEmailAddress] = []
            do {
                let resolved = try await xpc.resolveRecipients(recipients)
                log.info("resolveRecipients(recipients)=\(resolved, privacy: .public)")
                for addr in (message.toAddresses + message.ccAddresses + message.bccAddresses) {
                    let str = addr.addressString ?? addr.rawString
                    if resolved[str] == nil {
                        missing.append(addr)
                        canEncrypt = false
                    }
                }
            } catch {
                log.error("resolveRecipients(recipients) failed: \(error.localizedDescription, privacy: .public)")
                canEncrypt = false
                missing = (message.toAddresses + message.ccAddresses + message.bccAddresses)
            }

            log.info("→ canSign=\(canSign) canEncrypt=\(canEncrypt) missing=\(missing.count)")

            let status = MEOutgoingMessageEncodingStatus(
                canSign: canSign,
                canEncrypt: canEncrypt,
                securityError: nil,
                addressesFailingEncryption: missing
            )
            completionHandler(status)
        }
    }

    func encode(
        _ message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEMessageEncodingResult) -> Void
    ) {
        let userRequestedSign = composeContext.shouldSign
        let shouldEncrypt = composeContext.shouldEncrypt
        let alwaysSign = alwaysSignPreference

        log.info("encode userRequestedSign=\(userRequestedSign) shouldEncrypt=\(shouldEncrypt) alwaysSignPref=\(alwaysSign) rawSize=\(message.rawData?.count ?? -1)")

        // Fast path: when none of {compose-UI Sign, compose-UI
        // Encrypt, alwaysSign preference} is on, there's nothing
        // for us to do. Skip the Task hop and the auto-save / cache
        // checks below.
        if !userRequestedSign && !shouldEncrypt && !alwaysSign {
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: nil,
                encryptionError: nil
            ))
            return
        }

        // Diagnostic dump: when set true, writes both the original
        // (Mail-supplied) and the encoded RFC 822 bytes to the
        // .appex's tmp directory so the bytes survive a Mail crash
        // for post-mortem. Off in shipping builds — flip to true
        // locally when iterating on encode/decode shape problems.
        let DIAG_DUMP = false

        // Skip encode() for Mail's auto-saved drafts. Mail invokes
        // encode() up to 3× per logical message (auto-save → real
        // send → Sent-folder copy). Auto-saves carry partial data:
        // attachments are still server-side references rather than
        // inlined bytes, signalled by `X-Apple-Mail-Remote-Attachments:
        // YES` (and sometimes `X-Apple-Auto-Saved`). Encrypting that
        // partial body wastes a tclig round-trip and the encrypted
        // draft is useless — only the actual send (with attachments
        // inlined) needs PGP. Mirrors mailgpg/MailGPGExtension/
        // MessageSecurityHandler.swift:144-156.
        if isAutoSaveDraft(message) {
            log.info("encode: auto-save draft — passing through unchanged")
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: nil,
                encryptionError: nil
            ))
            return
        }

        // UUID-keyed cache: short-circuit repeated encode() calls.
        let messageUUID = headerValue("x-universally-unique-identifier", in: message)
        if let cached = cachedEncodeResult(for: messageUUID) {
            log.info("encode: cache hit for UUID \(messageUUID ?? "<nil>", privacy: .public)")
            completionHandler(cached)
            return
        }

        guard let raw = message.rawData else {
            completionHandler(.failure(
                signing: nil,
                encrypt: makeError("Apple Mail did not provide rawData for the outgoing message.")
            ))
            return
        }

        Task {
            // Honor the "Sign every outgoing message by default"
            // preference: if Mail's compose UI didn't toggle Sign but
            // the preference is on AND the From address has a usable
            // key, opt the message into signing. Best-effort: a
            // missing key for this account must NOT fail the send —
            // some accounts (work webmail, throwaways) won't have a
            // PGP identity, and forcing the user to disable the
            // preference per-account would be hostile.
            var shouldSign = userRequestedSign
            if alwaysSign && !shouldSign {
                let from = message.fromAddress.addressString ?? message.fromAddress.rawString
                let resolved = (try? await self.xpc.resolveRecipients([from])) ?? [:]
                if resolved[from] != nil {
                    shouldSign = true
                    log.info("encode: alwaysSign opted into signing for from=\(from, privacy: .public)")
                } else {
                    log.info("encode: alwaysSign requested but no key for from=\(from, privacy: .public) — sending unsigned")
                }
            }

            // Nothing to do — return a no-op result. Per
            // MEMessageEncodingResult docs, an `encodedMessage` of nil
            // with no errors means "the message did not need encoding".
            if !shouldSign && !shouldEncrypt {
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: nil
                ))
                return
            }

            do {
                let encoded = try await applyOpenPGP(
                    rawMessage: raw,
                    message: message,
                    shouldSign: shouldSign,
                    shouldEncrypt: shouldEncrypt
                )

                // The .appex's sandbox blocks `/tmp` writes for
                // arbitrary paths, but
                // `FileManager.default.temporaryDirectory` always
                // returns a sandbox-writable container path
                // (`~/Library/Containers/<bundle>/Data/tmp/`).
                if DIAG_DUMP {
                    let stamp = Int(Date().timeIntervalSince1970)
                    let tmp = FileManager.default.temporaryDirectory
                    let originalURL = tmp.appendingPathComponent("tumpa-original-\(stamp).eml")
                    let encodedURL = tmp.appendingPathComponent("tumpa-encoded-\(stamp).eml")
                    try? raw.write(to: originalURL)
                    try? encoded.rawData.write(to: encodedURL)
                    log.info("DIAG dumped: original=\(originalURL.path, privacy: .public) encoded=\(encodedURL.path, privacy: .public)")
                }

                let result = MEMessageEncodingResult(
                    encodedMessage: encoded,
                    signingError: nil,
                    encryptionError: nil
                )
                if let uuid = messageUUID {
                    self.storeEncodeResult(result, for: uuid)
                }
                completionHandler(result)
            } catch let TumpaSendError.signing(msg) {
                completionHandler(.failure(signing: makeError(msg), encrypt: nil))
            } catch let TumpaSendError.encryption(msg) {
                completionHandler(.failure(signing: nil, encrypt: makeError(msg)))
            } catch {
                // Generic failure — surface as encryption error so the
                // compose UI shows it; signing-error semantics in
                // MailKit are tied to the lock indicator.
                completionHandler(.failure(
                    signing: nil,
                    encrypt: makeError(error.localizedDescription)
                ))
            }
        }
    }

    // MARK: - MEMessageDecoder (incoming PGP/MIME)

    /// Decode an inbound RFC 822 message. We classify with
    /// `PGPMimeParser.classify`, then dispatch to verify or decrypt.
    /// Mail invokes this synchronously on a non-main thread (the
    /// indexer uses it during background scan), so we bridge to async
    /// XPC via `blockingXPC` (DispatchSemaphore + Task.detached).
    ///
    /// Returns nil for non-PGP messages so Mail's native MIME
    /// pipeline handles them (we don't claim ownership of every
    /// incoming message). For PGP messages we always return a non-nil
    /// `MEDecodedMessage` — even on failure — so Mail renders a banner
    /// instead of falling back to the raw armor blob.
    ///
    /// Crash-safety. The earlier Phase 3 attempt triggered
    /// `-[__NSSetM addObject:]: object cannot be nil` in
    /// `-[MFLibrary queueMessagesAddedNotification:]`. Two fixes
    /// applied here, mirroring MailGPG's working implementation:
    /// (1) `MEMessageSigner.emailAddresses` is never empty — we
    /// synthesize a placeholder address from the fingerprint when the
    /// UID has no `<…>` parsable email, and (2) every
    /// `MEDecodedMessage` is constructed with a non-nil `context:`
    /// (empty `Data()`), since Mail's observer apparently force-
    /// unwraps that slot somewhere.
    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        log.info("decodedMessage called: rawSize=\(data.count) markers=\(PGPMimeParser.hasPGPMarkers(in: data))")

        // Fast path: messages we just encoded outbound carry a
        // tracking ID we already have a decoded result for. Hit the
        // cache before doing any PGP work — this is what keeps
        // MFLibrary's Sent-copy indexer from spinning up tclig once
        // per indexed message AND from triggering the documented
        // KVO re-entrancy crash. Compose UUID is preferred when
        // present; Message-Id is the wire-side fallback.
        let uuid = PGPMimeBuilder.headerValue("x-universally-unique-identifier", in: data)
        let messageId = PGPMimeBuilder.headerValue("message-id", in: data)
        if let cached = cachedDecodedMessage(uuid: uuid, messageId: messageId) {
            log.info("decodedMessage: cache hit (uuid=\(uuid ?? "<nil>", privacy: .public) messageId=\(messageId ?? "<nil>", privacy: .public))")
            return cached
        }

        guard PGPMimeParser.hasPGPMarkers(in: data) else {
            return nil
        }
        let kind = PGPMimeParser.classify(data)
        switch kind {
        case .pgpEncrypted(let ciphertext):
            log.info("decodedMessage classified as encrypted ciphertext=\(ciphertext.count)B")
            return decodeEncrypted(ciphertext: ciphertext, original: data)
        case .pgpSigned(let signedPart, let signature, _):
            log.info("decodedMessage classified as signed signedBytes=\(signedPart.count)B sigBytes=\(signature.count)B")
            return decodeSigned(
                signedEntity: signedPart,
                signature: signature,
                original: data
            )
        case .notPGP:
            log.info("decodedMessage classified as notPGP — returning nil")
            return nil
        }
    }

    private func decodeEncrypted(ciphertext: Data, original: Data) -> MEDecodedMessage? {
        let result = blockingXPC { try await self.xpc.decryptVerify(ciphertext: ciphertext) }
        switch result {
        case .success(let r):
            // Default: use whatever decryptVerify reported (covers the
            // sign-then-encrypt OpenPGP-native case, where the
            // signature lives inside the encrypted packet stream and
            // tclig's --verify-decrypt surfaces it as GOODSIG/BADSIG).
            var signatureStatus = r.signatureStatus
            var signerFp = r.signerFingerprint
            var signerKid = r.signerKeyId
            var signerUid = r.signerUid
            var bodyForAssembly = r.plaintext

            // Sign-then-encrypt at the MIME layer (RFC 3156 §6.2): the
            // decrypted plaintext is itself a `multipart/signed`
            // entity. tclig reports unsigned because there's no
            // OpenPGP-native sig inside the encrypted blob; we have to
            // run a detached verify on the inner multipart/signed
            // ourselves. Observed 2026-04-28 with `jocar2.eml`
            // (Apple-Mail-style boundary inside the decrypted
            // payload).
            if signatureStatus == TumpaSignatureStatus.unsigned,
               case let .pgpSigned(signedPart, signature, _) = PGPMimeParser.classify(r.plaintext) {
                log.info("decodeEncrypted: inner multipart/signed detected (signedPart=\(signedPart.count)B sig=\(signature.count)B); running detached verify")
                let canonical = PGPMimeBuilder.canonicalizeForSigning(signedPart)
                let verify = blockingXPC {
                    try await self.verifyDetachedTolerant(
                        canonicalSigned: canonical,
                        signature: signature
                    )
                }
                if case .success(let v) = verify {
                    signatureStatus = v.status
                    // `verifyDetached` populates `signerFingerprint`
                    // from VALIDSIG (40-char) and `signerKeyId` from
                    // GOODSIG (16-char). Both can be present on a
                    // good verify; the popover prefers the fingerprint
                    // and falls back to the key ID.
                    signerFp = v.signerFingerprint
                    signerUid = v.signerUid
                    signerKid = v.signerKeyId
                    // Use the SIGNED ENTITY (inner MIME part) as the
                    // assembled body — we don't want the multipart/signed
                    // wrapper to render in Mail's viewer; the signature
                    // status is conveyed via MEMessageSecurityInformation,
                    // not by leaving the wrapper visible.
                    bodyForAssembly = signedPart
                }
            }

            let isSigned = signatureStatus != TumpaSignatureStatus.unsigned
            let secCtx = securityContext(
                isEncrypted: true,
                signatureStatus: signatureStatus,
                fingerprint: signerFp,
                uid: signerUid,
                keyId: signerKid,
                errorMessage: nil
            )
            let signingError = signingError(for: signatureStatus, hadSignature: isSigned)
            // Crash-safety: only populate the signers slot on a CLEAN
            // verification (status=good). When signingError is set,
            // Mail's library treats `signers` as authoritative-but-
            // invalid and ends up adding nils to an internal set,
            // crashing in `-[__NSSetM addObject:]`. Mirror MailGPG's
            // makeDecodedMessage pattern (see
            // MessageSecurityHandler.swift:521-535): success ⇒ signers,
            // any error ⇒ empty signers + the error.
            let signers = signingError == nil ? makeSigners(
                fingerprint: signerFp,
                uid: signerUid,
                keyId: signerKid,
                contextPayload: secCtx
            ) : []
            let secInfo = MEMessageSecurityInformation(
                signers: signers,
                isEncrypted: true,
                signingError: signingError,
                encryptionError: nil
            )
            // Hand Mail's reader a complete RFC 822 message — outer
            // envelope (From/To/Subject/Date/...) from the encrypted
            // wrapper plus the decrypted inner part. Returning just
            // the inner part bytes makes the body render empty in
            // Mail's viewer, since the reader uses `data` as a full
            // message and looks up envelope metadata from its
            // headers. Falls back to the raw plaintext if envelope
            // assembly fails — better an inner-part-only render than
            // nothing.
            let assembled = (try? PGPMimeBuilder.assembleInboundDecodedMessage(
                envelopeSource: original,
                decryptedInnerPart: bodyForAssembly
            )) ?? bodyForAssembly
            return MEDecodedMessage(
                data: assembled,
                securityInformation: secInfo,
                context: secCtx,
                banner: securityBanner(
                    isEncrypted: true,
                    signatureStatus: signatureStatus,
                    errorMessage: nil
                )
            )
        case .failure(let err):
            // libtumpa needed a passphrase / PIN that wasn't in the
            // agent cache. Render a `.lockedWaiting` context so Mail's
            // puzzle-piece popover prompts the user; on submit, the
            // popover writes the secret to the agent and the user
            // re-selects the message to redecode.
            if case let XPCClientError.needsUnlock(fp, uid, isPin) = err {
                log.info("decodeEncrypted: needs unlock for \(fp, privacy: .public)")
                let lockedCtx = TumpaSecurityContext(
                    status: .lockedWaiting,
                    signerEmail: extractEmail(fromUid: uid),
                    signerLabel: uid,
                    fingerprint: fp,
                    keyId: nil,
                    errorMessage: nil,
                    isPin: isPin
                )
                let secCtx = TumpaSecurityContext.encode(lockedCtx)

                // Mail only shows the security shield (which opens
                // `extensionViewController(messageContext:)`) when
                // `signers` is non-empty. Setting `encryptionError`
                // routes Mail to its built-in "could not decrypt"
                // banner with Details/Dismiss instead, with no path
                // to our popover. Workaround: attach the locked
                // context to a synthetic signer entry so the shield
                // appears; clicking it opens our popover →
                // SecureField → cachePassphrase XPC →
                // `~/.tumpa/agent.sock` PUT_PASSPHRASE → user
                // re-selects message → cache hit → real decrypt.
                let lockedSigner = makeSigners(
                    fingerprint: fp,
                    uid: uid,
                    keyId: nil,
                    contextPayload: secCtx
                )
                let secInfo = MEMessageSecurityInformation(
                    signers: lockedSigner,
                    isEncrypted: true,
                    signingError: nil,
                    encryptionError: nil
                )

                // Synthetic placeholder body. Without this, returning
                // `data: original` (the raw RFC 822 wrapper) would
                // make Mail render the constituent OpenPGP/MIME parts
                // (`application/pgp-encrypted`, `encrypted.asc`) as
                // file attachments — confusing UX. Inline a small
                // RFC 822 message that explains what to do.
                let placeholder = lockedPlaceholderMessage(
                    envelopeSource: original,
                    isPin: isPin,
                    uid: uid
                )

                return MEDecodedMessage(
                    data: placeholder,
                    securityInformation: secInfo,
                    context: secCtx,
                    banner: MEDecodedMessageBanner(
                        title: isPin
                            ? "Encrypted — unlock the smartcard to read"
                            : "Encrypted — enter the key passphrase to read",
                        primaryActionTitle: "Unlock",
                        dismissable: false
                    )
                )
            }

            let secCtx = TumpaSecurityContext.encode(.init(
                status: .decryptFailed,
                signerEmail: nil, signerLabel: nil,
                fingerprint: nil, keyId: nil,
                errorMessage: err.localizedDescription
            ))
            let secInfo = MEMessageSecurityInformation(
                signers: [],
                isEncrypted: true,
                signingError: nil,
                encryptionError: makeError(err.localizedDescription)
            )
            return MEDecodedMessage(
                data: original,
                securityInformation: secInfo,
                context: secCtx,
                banner: securityBanner(
                    isEncrypted: true,
                    signatureStatus: TumpaSignatureStatus.unsigned,
                    errorMessage: err.localizedDescription
                )
            )
        }
    }

    /// Extract the bare email from a UID like
    /// `Alice <alice@example.com>`. Returns `nil` if there's no
    /// `<email>` form. Used for popover row rendering.
    private func extractEmail(fromUid uid: String) -> String? {
        guard let lt = uid.firstIndex(of: "<"),
              let gt = uid.lastIndex(of: ">"),
              lt < gt
        else { return nil }
        let email = String(uid[uid.index(after: lt)..<gt])
        return email.isEmpty ? nil : email
    }

    /// Build a placeholder RFC 822 message body to hand back when an
    /// inbound encrypted message is awaiting unlock. Reuses the
    /// envelope (From/To/Subject/Date) of the original encrypted
    /// message so Mail's reader still threads the message correctly,
    /// and replaces the body with a `text/plain` instructing the
    /// user to click the security shield.
    private func lockedPlaceholderMessage(
        envelopeSource original: Data,
        isPin: Bool,
        uid: String
    ) -> Data {
        let body = isPin
            ? """
              This message is encrypted to your smartcard.

              Click the security shield in the message header to
              enter your card PIN. After unlocking once, the PIN is
              cached in the tumpa agent and subsequent messages
              decrypt automatically.

              Key: \(uid)
              """
            : """
              This message is encrypted to your OpenPGP key.

              Click the security shield in the message header to
              enter your key passphrase. After unlocking once, the
              passphrase is cached in the tumpa agent and subsequent
              messages decrypt automatically.

              Key: \(uid)
              """

        let synthetic = "Content-Type: text/plain; charset=utf-8\r\n" +
                        "Content-Transfer-Encoding: 8bit\r\n" +
                        "\r\n" +
                        body

        if let assembled = try? PGPMimeBuilder.assembleInboundDecodedMessage(
            envelopeSource: original,
            decryptedInnerPart: Data(synthetic.utf8)
        ) {
            return assembled
        }
        return Data(synthetic.utf8)
    }

    private func decodeSigned(signedEntity: Data, signature: Data, original: Data) -> MEDecodedMessage? {
        // RFC 3156 §5.1: the signature was made over the CRLF-canonical
        // form. The bytes Mail hands us in `decodedMessage(forMessageData:)`
        // have been normalized to LF on the way in — we observed (5.eml
        // dump, 2026-04-27) the ON-DISK on-the-wire body was 119 CRLF
        // bytes but our decoder received only 113 LF bytes for the
        // same message. tclig's verify is byte-exact (regression guard
        // at `wecanencrypt/src/sign.rs:540`), so we re-canonicalize
        // back to CRLF here before asking it to verify. Mirrors
        // MailGPG `MessageSecurityHandler.swift:629-633`.
        let canonicalSigned = PGPMimeBuilder.canonicalizeForSigning(signedEntity)
        log.info("decodeSigned: canonicalized \(signedEntity.count)B → \(canonicalSigned.count)B for verify")
        let result = blockingXPC {
            try await self.verifyDetachedTolerant(
                canonicalSigned: canonicalSigned,
                signature: signature
            )
        }
        switch result {
        case .success(let r):
            let secCtx = securityContext(
                isEncrypted: false,
                signatureStatus: r.status,
                fingerprint: r.signerFingerprint,
                uid: r.signerUid,
                keyId: nil,
                errorMessage: nil
            )
            let signingError = signingError(for: r.status, hadSignature: true)
            // Same crash-safety as decodeEncrypted: signers only when
            // verification is fully clean.
            let signers = signingError == nil ? makeSigners(
                fingerprint: r.signerFingerprint,
                uid: r.signerUid,
                keyId: nil,
                contextPayload: secCtx
            ) : []
            let secInfo = MEMessageSecurityInformation(
                signers: signers,
                isEncrypted: false,
                signingError: signingError,
                encryptionError: nil
            )
            return MEDecodedMessage(
                // Mail's text/plain renderer leaves the reading pane
                // empty when the body bytes contain `\r\r\n` (Outlook /
                // Exchange MTA mangling). Collapse it for rendering.
                // Idempotent on clean CRLF, so well-formed senders
                // round-trip unchanged. Only the `data:` slot is
                // touched — verification already completed against
                // the canonicalized signed entity above, so the
                // signature status carried in `secInfo` is unaffected.
                data: PGPMimeBuilder.collapseDoubledCR(original),
                securityInformation: secInfo,
                context: secCtx,
                banner: securityBanner(
                    isEncrypted: false,
                    signatureStatus: r.status,
                    errorMessage: nil
                )
            )
        case .failure(let err):
            let secCtx = TumpaSecurityContext.encode(.init(
                status: .signedBad,
                signerEmail: nil, signerLabel: nil,
                fingerprint: nil, keyId: nil,
                errorMessage: err.localizedDescription
            ))
            let secInfo = MEMessageSecurityInformation(
                signers: [],
                isEncrypted: false,
                signingError: makeError(err.localizedDescription),
                encryptionError: nil
            )
            return MEDecodedMessage(
                // Same `\r\r\n` collapse as the success path — even
                // when verify ultimately failed, we want the message
                // body to render so the user can read the text and
                // see the failure banner instead of a blank pane.
                data: PGPMimeBuilder.collapseDoubledCR(original),
                securityInformation: secInfo,
                context: secCtx,
                banner: securityBanner(
                    isEncrypted: false,
                    signatureStatus: TumpaSignatureStatus.bad,
                    errorMessage: err.localizedDescription
                )
            )
        }
    }

    /// Build the JSON payload that travels in `MEDecodedMessage.context`
    /// and `MEMessageSigner.context`. We decode it back when Mail
    /// invokes `extensionViewController(...)` so the popover that
    /// pops out of the puzzle-piece icon shows accurate signer info.
    private func securityContext(
        isEncrypted: Bool,
        signatureStatus: String,
        fingerprint: String?,
        uid: String?,
        keyId: String?,
        errorMessage: String?
    ) -> Data {
        let label: String? = {
            if let uid, !uid.isEmpty { return uid }
            if let fingerprint, !fingerprint.isEmpty { return fingerprint }
            return keyId
        }()
        let email: String? = {
            if let uid, let lt = uid.firstIndex(of: "<"),
               let gt = uid.lastIndex(of: ">"), lt < gt {
                let parsed = String(uid[uid.index(after: lt)..<gt])
                return parsed.isEmpty ? nil : parsed
            }
            return nil
        }()
        let status: TumpaSecurityContext.Status = {
            switch signatureStatus {
            case TumpaSignatureStatus.good:
                return isEncrypted ? .signedAndEncrypted : .signed
            case TumpaSignatureStatus.bad:
                return .signedBad
            case TumpaSignatureStatus.unknown:
                return .signedUnknown
            case TumpaSignatureStatus.unsigned:
                return .encrypted
            default:
                return isEncrypted ? .encrypted : .signedUnknown
            }
        }()
        let ctx = TumpaSecurityContext(
            status: status,
            signerEmail: email,
            signerLabel: label,
            fingerprint: fingerprint,
            keyId: keyId,
            errorMessage: errorMessage
        )
        return TumpaSecurityContext.encode(ctx)
    }

    private func securityBanner(
        isEncrypted: Bool,
        signatureStatus: String,
        errorMessage: String?
    ) -> MEDecodedMessageBanner {
        let title: String
        if errorMessage != nil {
            title = isEncrypted ? "Tumpa Mail could not decrypt this message" : "Tumpa Mail could not verify this message"
        } else if isEncrypted && signatureStatus == TumpaSignatureStatus.good {
            title = "Tumpa Mail decrypted and verified this message"
        } else if isEncrypted {
            title = "Tumpa Mail decrypted this message"
        } else if signatureStatus == TumpaSignatureStatus.good {
            title = "Tumpa Mail verified this message"
        } else {
            title = "Tumpa Mail checked this message"
        }

        return MEDecodedMessageBanner(
            title: title,
            primaryActionTitle: "Details",
            dismissable: true
        )
    }

    /// Build an `MEMessageSigner` array from XPC-returned fingerprint /
    /// UID / key id. Returns an empty array if we have no signer info
    /// at all — Mail then shows just the signing error banner without
    /// a name. Whenever we DO return a signer, its `emailAddresses`
    /// list is guaranteed non-empty: Mail's `MFLibrary` adds the
    /// elements to an `NSMutableSet` and crashes (`__NSSetM
    /// addObject:nil`) if the array is empty when `signers` is not.
    /// The `context` slot is never nil for the same reason — Mail's
    /// notification observer force-unwraps it somewhere.
    /// Verify a detached signature with progressive recovery for
    /// known sender / MTA mangling. Always tries the strict-canonical
    /// bytes first — well-behaved senders verify there. On a `bad` /
    /// `unknown` outcome we fall back to the variants described in
    /// `PGPMimeBuilder.tolerantSignedVariants` (Outlook `\r\r\n`
    /// doubling + extra trailing CRLFs) and accept the first one
    /// that returns `good`.
    ///
    /// Diagnosed concretely on `jocar_failed.eml` (2026-04-30): wire
    /// bytes had +2 trailing CRLFs vs signed AND `\r\r\n` doubling
    /// from Exchange. Strict verify failed; collapse + 2-CRLF strip
    /// recovered. Without this shim, Tumpa Mail-to-Tumpa Mail signed
    /// messages routed through Microsoft Exchange / Outlook would
    /// always show "Bad signature" even when they're cryptographically
    /// fine end-to-end.
    private func verifyDetachedTolerant(
        canonicalSigned: Data,
        signature: Data
    ) async throws -> (
        status: String,
        signerFingerprint: String?,
        signerKeyId: String?,
        signerUid: String?
    ) {
        let strict = try await self.xpc.verifyDetached(
            signedBytes: canonicalSigned,
            signature: signature
        )
        if strict.status == TumpaSignatureStatus.good {
            return strict
        }
        let variants = PGPMimeBuilder.tolerantSignedVariants(of: canonicalSigned)
        log.info("verifyDetachedTolerant: strict=\(strict.status, privacy: .public); trying \(variants.count) recovery variant(s)")
        for (idx, variant) in variants.enumerated() {
            let attempt = try await self.xpc.verifyDetached(
                signedBytes: variant,
                signature: signature
            )
            if attempt.status == TumpaSignatureStatus.good {
                log.info("verifyDetachedTolerant: recovered on variant #\(idx) (\(canonicalSigned.count)B → \(variant.count)B)")
                return attempt
            }
        }
        // No variant recovered — return the strict result so the
        // popover renders the original error, not a guess.
        return strict
    }

    private func makeSigners(
        fingerprint: String?,
        uid: String?,
        keyId: String?,
        contextPayload: Data = Data()
    ) -> [MEMessageSigner] {
        guard let label = uid ?? fingerprint ?? keyId, !label.isEmpty else {
            return []
        }
        // Try to extract an RFC 822-style address from the UID first
        // ("Real Name <email@example.com>"). If that's not parseable,
        // fall back to a synthesized address built from the fingerprint
        // (or whatever label we have). The synthetic address is mostly
        // for crash-safety; Mail's compose UI may also use it as the
        // signer chip label.
        var emails: [MEEmailAddress] = []
        if let uid = uid,
           let lt = uid.firstIndex(of: "<"),
           let gt = uid.lastIndex(of: ">"),
           lt < gt {
            let email = String(uid[uid.index(after: lt)..<gt])
            if !email.isEmpty {
                emails.append(MEEmailAddress(rawString: email))
            }
        }
        if emails.isEmpty {
            // Synthesize a placeholder so Mail never sees an empty
            // emailAddresses array. The fingerprint (preferred) reads
            // as "openpgp:37417ABF…" so the user can tell it's a key
            // ID rather than a real address; falls back to the label.
            let synthetic = fingerprint.map { "openpgp:\($0)" } ?? "openpgp:\(label)"
            emails.append(MEEmailAddress(rawString: synthetic))
        }
        let signer = MEMessageSigner(
            emailAddresses: emails,
            signatureLabel: label,
            context: contextPayload
        )
        return [signer]
    }

    /// Translate the `unsigned` / `good` / `bad` / `unknown` status
    /// returned by tclig into a signing error suitable for Mail's
    /// `MEMessageSecurityInformation.signingError` slot. `nil` here
    /// means "no signing error to display" — used for `good` AND for
    /// genuinely-unsigned encrypted-only mail.
    private func signingError(for status: String, hadSignature: Bool) -> NSError? {
        switch status {
        case TumpaSignatureStatus.good:
            return nil
        case TumpaSignatureStatus.unsigned:
            // Encrypt-only is a fine state; no error.
            return nil
        case TumpaSignatureStatus.bad:
            return makeError("Signature did not verify against the signer's key.")
        case TumpaSignatureStatus.unknown:
            return makeError("Signed by an unknown key. Import the signer's public key with `tcli import` to verify.")
        default:
            // Defensive: unknown status string. If we expected a
            // signature, surface a generic warning.
            if hadSignature {
                return makeError("Signature status could not be determined.")
            }
            return nil
        }
    }

    /// Bridge async-throwing XPC into the synchronous decoder
    /// callback. Runs the work on a detached task and waits with a
    /// semaphore — Mail invokes the decoder off the main thread, so
    /// blocking is fine. 30-second backstop matches the longest sane
    /// interactive crypto operation (PIN entry on a smartcard).
    private func blockingXPC<T>(
        _ work: @escaping () async throws -> T
    ) -> Result<T, Error> {
        let sem = DispatchSemaphore(value: 0)
        var captured: Result<T, Error>!
        Task.detached {
            do {
                captured = .success(try await work())
            } catch {
                captured = .failure(error)
            }
            sem.signal()
        }
        let timeout = DispatchTime.now() + .seconds(30)
        if sem.wait(timeout: timeout) == .timedOut {
            return .failure(XPCTimeoutError())
        }
        return captured
    }

    private struct XPCTimeoutError: LocalizedError {
        var errorDescription: String? {
            "Tumpa Crypto XPC service did not respond in time. Is `tumpa-cli`'s agent running (`brew services start tumpa-cli`)?"
        }
    }

    // MARK: - View controllers

    /// Mail calls this when the user clicks the puzzle-piece icon on
    /// a signed message; the signers list carries the per-signer
    /// `context: Data` we set in `makeSigners`. Decode the JSON and
    /// hand back the SwiftUI-wrapped `SecurityDetailView`.
    func extensionViewController(signers: [MEMessageSigner]) -> MEExtensionViewController? {
        log.info("extensionViewController(signers:) called signerCount=\(signers.count)")
        let context = signers.lazy.compactMap { signer -> TumpaSecurityContext? in
            TumpaSecurityContext.decode(signer.context)
        }.first
        guard let context else {
            log.info("extensionViewController(signers:) — no usable context, returning nil")
            return nil
        }
        log.info("extensionViewController(signers:) status=\(String(describing: context.status), privacy: .public)")
        return TumpaSecurityDetailViewController(context: context)
    }

    /// Same path for cases where Mail has only the message-level
    /// context (encrypt-only mail, decryption failure banners).
    func extensionViewController(messageContext: Data) -> MEExtensionViewController? {
        log.info("extensionViewController(messageContext:) called bytes=\(messageContext.count)")
        guard let decoded = TumpaSecurityContext.decode(messageContext) else {
            log.info("extensionViewController(messageContext:) — context decode failed, returning nil")
            return nil
        }
        log.info("extensionViewController(messageContext:) status=\(String(describing: decoded.status), privacy: .public)")
        return TumpaSecurityDetailViewController(context: decoded)
    }

    func primaryActionClicked(
        forMessageContext context: Data,
        completionHandler: @escaping (MEExtensionViewController?) -> Void
    ) {
        log.info("primaryActionClicked fired bytes=\(context.count)")
        let vc = extensionViewController(messageContext: context)
        log.info("primaryActionClicked returning vc=\(vc != nil ? "<vc>" : "nil", privacy: .public)")
        completionHandler(vc)
    }

    // MARK: - Pipeline

    /// Produce an `MEEncodedOutgoingMessage` for the requested mode
    /// (sign-only / encrypt-only / sign+encrypt). All crypto goes
    /// through XPC; framing happens in `PGPMimeBuilder`.
    private func applyOpenPGP(
        rawMessage: Data,
        message: MEMessage,
        shouldSign: Bool,
        shouldEncrypt: Bool
    ) async throws -> MEEncodedOutgoingMessage {
        let signer = try await resolveSignerFingerprint(message: message, sign: shouldSign)
        var recipientFprs = try await resolveRecipientFingerprints(
            message: message,
            encrypt: shouldEncrypt
        )

        if shouldEncrypt {
            // Always include the sender's own encryption key in the
            // recipient set. The Sent copy that MFLibrary writes to
            // disk needs to be decryptable on this same machine, or
            // Mail's background indexer's decode attempt fails and
            // crashes Mail with `*** -[__NSSetM addObject:]: object
            // cannot be nil` via a KVO re-entrancy path inside
            // MFLibrary's library-write NSOperation. Adding the
            // sender keeps the Sent copy decryptable and makes the
            // crash unreachable. (Independent of the cache fix
            // below — both defenses are needed.)
            if let senderFpr = try? await resolveSenderEncryptionFingerprint(message: message),
               !senderFpr.isEmpty,
               !recipientFprs.contains(senderFpr) {
                recipientFprs.append(senderFpr)
                log.info("encode: appended sender's key to encrypt recipients (\(senderFpr, privacy: .public))")
            }

            // Sign-then-encrypt (or encrypt-only) into a single
            // OpenPGP message; PGP/MIME wraps the result.
            let plaintext = try PGPMimeBuilder.extractInnerPart(from: rawMessage)
            log.info(
                "encode: calling xpc.encrypt — plaintextSize=\(plaintext.count) recipients=\(recipientFprs, privacy: .public) signer=\(shouldSign ? (signer ?? "<nil>") : "<none>", privacy: .public)"
            )
            let armored: Data
            do {
                armored = try await xpcEncrypt(
                    plaintext: plaintext,
                    recipients: recipientFprs,
                    signer: shouldSign ? signer : nil
                )
            } catch {
                log.error(
                    "encode: xpc.encrypt FAILED — \(error.localizedDescription, privacy: .public) :: \(String(describing: error), privacy: .public)"
                )
                throw error
            }
            log.info("encode: xpc.encrypt OK — ciphertextSize=\(armored.count)")
            let encoded = try PGPMimeBuilder.buildEncryptedMessage(
                original: rawMessage,
                armoredCiphertext: armored,
                innerWasSigned: shouldSign
            )

            // Pre-build a decoded result for the bytes we just
            // produced and stash it under the message's tracking
            // keys. When MFLibrary later calls
            // `decodedMessage(forMessageData:)` on the Sent copy, the
            // cache short-circuits the entire decrypt path: no tclig
            // spawn, no agent passphrase prompt, and no indexer-
            // driven decode. Keyed under both the compose UUID and
            // the Message-Id so whichever one MFLibrary sees on the
            // encoded bytes still hits.
            //
            // `data` is the ORIGINAL draft RFC 822 message (envelope
            // headers + body), NOT just the inner MIME part. Mail's
            // library-write path extracts envelope metadata (To/From/
            // Subject/Date) from the decoded `data` for indexing —
            // handing it inner-part bytes (no envelope) makes that
            // extraction return nil and crashes MFLibrary in
            // `-[__NSSetM addObject:]: object cannot be nil`. The
            // working reference does the same (passes `body =
            // message.rawData`).
            // When signing too, resolve the signer's primary UID from
            // the keystore so the cached `MEMessageSigner` carries a
            // real RFC 822 address (e.g. `Kushal Das <kushal@…>`)
            // instead of the synthetic `openpgp:<fpr>` placeholder.
            // Mail's reader silently elides signer info from any
            // signer whose emailAddresses aren't real addresses, so
            // skipping this lookup costs us the on-screen "Signed by"
            // badge for the Sent-copy render — the most visible
            // user-facing signal that signing actually happened.
            let signerUid: String?
            if shouldSign, let signer {
                signerUid = await lookupSignerUid(fingerprint: signer)
            } else {
                signerUid = nil
            }
            let outboundDecoded = makeOutgoingDecodedMessage(
                data: rawMessage,
                isSigned: shouldSign,
                isEncrypted: true,
                signerFingerprint: signer,
                signerUid: signerUid
            )
            cacheOutboundDecoded(outboundDecoded, draft: message, encoded: encoded.bytes)

            // For the encrypted path we tell Mail honestly that the
            // returned bytes are encrypted. The mangling-avoidance
            // reason that drives `isSigned: false` on the
            // `multipart/signed` branch (`makeOpaqueEncodedMessage`)
            // does not apply here — the encrypted body is already
            // an opaque OpenPGP armor blob, so MCMessageGenerator
            // has no inner MIME structure to "consolidate". Honest
            // flags also mean Mail's reader correctly displays the
            // lock icon and goes through `decodedMessage(forMessageData:)`,
            // which is where our pre-cached `MEDecodedMessage`
            // (with full envelope `data: rawMessage`) renders the
            // body.
            return MEEncodedOutgoingMessage(
                rawData: encoded.bytes,
                isSigned: shouldSign,
                isEncrypted: true
            )
        }

        // shouldSign && !shouldEncrypt — multipart/signed path.
        let inner = try PGPMimeBuilder.extractInnerPart(from: rawMessage)
        let canon = PGPMimeBuilder.canonicalizeForSigning(inner)
        guard let signer = signer else {
            throw TumpaSendError.signing("no signing key available; pick a default signer in Tumpa Mail.")
        }

        let result = try await xpcSign(
            canon: canon,
            signer: signer
        )
        let micalg = "pgp-\(result.actualDigest.lowercased())"
        let encoded = try PGPMimeBuilder.buildSignedMessage(
            original: rawMessage,
            canonicalizedInnerPart: canon,
            armoredSignature: result.signature,
            micalg: micalg
        )

        // Pre-cache the decoded result for the Sent copy of this
        // signed message, same rationale as the encrypted branch:
        // MFLibrary will call `decodedMessage(forMessageData:)` on
        // the Sent copy during indexing, and a synchronous re-verify
        // there is unnecessary churn (we already verified by virtue
        // of having just signed these bytes ourselves).
        let signerUid = await lookupSignerUid(fingerprint: signer)
        let outboundDecoded = makeOutgoingDecodedMessage(
            data: rawMessage,
            isSigned: true,
            isEncrypted: false,
            signerFingerprint: signer,
            signerUid: signerUid
        )
        cacheOutboundDecoded(outboundDecoded, draft: message, encoded: encoded.bytes)

        return makeOpaqueEncodedMessage(rawData: encoded.bytes)
    }

    /// Build a self-consistent `MEDecodedMessage` for an outgoing
    /// message we just produced — used to pre-populate the decode
    /// cache so MFLibrary's Sent-copy indexer can short-circuit. The
    /// security info matches "exactly what we just did": signed
    /// and/or encrypted, no error, signer info synthesized from the
    /// known signer fingerprint when present. All nil-safety
    /// invariants documented for the inbound decode path apply here
    /// too (signers/signingError mutual-exclusion; non-nil context).
    private func makeOutgoingDecodedMessage(
        data: Data,
        isSigned: Bool,
        isEncrypted: Bool,
        signerFingerprint: String? = nil,
        signerUid: String? = nil
    ) -> MEDecodedMessage {
        let status: String = isSigned ? TumpaSignatureStatus.good : TumpaSignatureStatus.unsigned
        let secCtx = securityContext(
            isEncrypted: isEncrypted,
            signatureStatus: status,
            fingerprint: signerFingerprint,
            uid: signerUid,
            keyId: nil,
            errorMessage: nil
        )
        let signers = isSigned
            ? makeSigners(
                fingerprint: signerFingerprint,
                uid: signerUid,
                keyId: nil,
                contextPayload: secCtx
            )
            : []
        let secInfo = MEMessageSecurityInformation(
            signers: signers,
            isEncrypted: isEncrypted,
            signingError: nil,
            encryptionError: nil
        )
        return MEDecodedMessage(
            data: data,
            securityInformation: secInfo,
            context: secCtx,
            banner: securityBanner(
                isEncrypted: isEncrypted,
                signatureStatus: status,
                errorMessage: nil
            )
        )
    }

    /// Index a pre-built decoded message under every tracking key
    /// MFLibrary might query when it indexes the Sent copy. We don't
    /// know in advance which one Mail will see (X-UUID is stripped
    /// by `retainOuterHeaders` for outbound, but the in-memory draft
    /// still has it; Message-Id is preserved on the wire).
    private func cacheOutboundDecoded(
        _ decoded: MEDecodedMessage,
        draft message: MEMessage,
        encoded: Data
    ) {
        let uuid = headerValue("x-universally-unique-identifier", in: message)
        let messageId = headerValue("message-id", in: message)
            ?? PGPMimeBuilder.headerValue("message-id", in: encoded)
        storeDecodedMessage(decoded, uuid: uuid, messageId: messageId)
    }

    /// Wrap our pre-built RFC 822 bytes for return to MailKit.
    ///
    /// We deliberately pass `isSigned: false, isEncrypted: false` even
    /// when the rawData is a real `multipart/signed` /
    /// `multipart/encrypted` envelope. The dump pair recorded on
    /// 2026-04-27 (`tumpa-encoded-1777302114.eml` we returned vs.
    /// `hi.eml` that landed at the recipient) shows that when those
    /// flags are true, Mail's outgoing pipeline runs our rawData
    /// through `MCMessageGenerator` and re-emits it: every inner-part
    /// `Content-*` header gets lifted into the outer header section,
    /// the part-1 body and both opening boundary delimiters are
    /// dropped, the `-----BEGIN PGP SIGNATURE-----` armor line is
    /// stripped, and Mail's own `X-Mailer` lands among the lifted
    /// inner-part headers — proof Mail itself is the rewriter.
    /// Lying about isSigned/isEncrypted asks Mail to treat the bytes
    /// as opaque so the PGP/MIME structure survives transport.
    /// Side effect: Mail's compose UI doesn't paint the lock/signed
    /// glyph on this outgoing message, but the recipient's MUA reads
    /// a real RFC 3156 envelope.
    private func makeOpaqueEncodedMessage(rawData: Data) -> MEEncodedOutgoingMessage {
        MEEncodedOutgoingMessage(rawData: rawData, isSigned: false, isEncrypted: false)
    }

    /// Look up the primary UID for a fingerprint in the keystore.
    /// Used at outbound encode time so we can populate
    /// `MEMessageSigner.emailAddresses` with a real RFC 822 address
    /// instead of the synthetic `openpgp:<fingerprint>` placeholder
    /// `makeSigners` falls back to. Mail's reader silently drops the
    /// signer indicator if the signer's email isn't a real address —
    /// the synthetic form is recognized as invalid and quietly elided
    /// (no badge, no signer info), even though the cached
    /// `MEDecodedMessage` is otherwise correct.
    ///
    /// Returns nil on miss; the caller falls back to fingerprint-only
    /// signers (which Mail will quietly hide but won't crash on).
    private func lookupSignerUid(fingerprint: String) async -> String? {
        guard let keys = try? await xpc.listKeys() else { return nil }
        return keys.first(where: { $0.fingerprint == fingerprint })?.primaryUid
    }

    /// Resolve the sender's encryption-capable cert fingerprint from
    /// the From address. Returns nil (not throws) on miss because the
    /// caller treats this as a defense-in-depth append, not a hard
    /// requirement — if the sender has no key, we still encrypt to
    /// the listed recipients. tumpa-cli's keystore stores certs
    /// uniformly, so the same `xpc.resolveRecipients` call surfaces
    /// the encryption fingerprint regardless of signing capability.
    private func resolveSenderEncryptionFingerprint(message: MEMessage) async throws -> String? {
        guard let from = message.fromAddress.addressString ?? message.fromAddress.rawString as String?,
              !from.isEmpty else {
            return nil
        }
        let resolved = try await xpc.resolveRecipients([from])
        return resolved[from]
    }

    /// Pick a signing fingerprint by matching the message's From
    /// address against the keystore. Returns `nil` when signing isn't
    /// requested; throws when signing IS requested but no certificate
    /// in the keystore has a UID for the From address.
    ///
    /// `xpc.resolveRecipients` matches against all certs (public or
    /// secret), so smartcard users — who keep only the public cert
    /// in the keystore while the secret material lives on the card —
    /// resolve correctly. tclig's sign path does card-first dispatch
    /// then falls back to a software secret if present.
    private func resolveSignerFingerprint(
        message: MEMessage,
        sign: Bool
    ) async throws -> String? {
        if !sign { return nil }

        let from = message.fromAddress.addressString ?? message.fromAddress.rawString
        let resolved = try await xpc.resolveRecipients([from])
        if let fp = resolved[from] {
            return fp
        }
        throw TumpaSendError.signing(
            "No OpenPGP certificate found for \(from). Import the certificate with `tcli import` (a public cert is enough if the secret lives on a smartcard)."
        )
    }

    /// Resolve every To / Cc / Bcc recipient, throw with the missing
    /// list if any is unresolvable.
    private func resolveRecipientFingerprints(
        message: MEMessage,
        encrypt: Bool
    ) async throws -> [String] {
        if !encrypt { return [] }
        let addrs = (message.toAddresses + message.ccAddresses + message.bccAddresses)
        let strings = addrs.compactMap { $0.addressString ?? $0.rawString }
        let resolved = try await xpc.resolveRecipients(strings)
        var fps: [String] = []
        var missing: [String] = []
        for s in strings {
            if let fp = resolved[s] {
                fps.append(fp)
            } else {
                missing.append(s)
            }
        }
        if !missing.isEmpty {
            throw TumpaSendError.encryption(
                "No usable key for: \(missing.joined(separator: ", "))"
            )
        }
        return fps
    }

    private func xpcSign(
        canon: Data,
        signer: String
    ) async throws -> (signature: Data, actualDigest: String) {
        do {
            return try await xpc.signDetached(
                canonicalizedBody: canon,
                signerFingerprint: signer,
                digest: preferredDigest
            )
        } catch {
            throw TumpaSendError.signing(error.localizedDescription)
        }
    }

    private func xpcEncrypt(
        plaintext: Data,
        recipients: [String],
        signer: String?
    ) async throws -> Data {
        do {
            return try await xpc.encrypt(
                plaintext: plaintext,
                recipientFingerprints: recipients,
                signerFingerprint: signer,
                armor: true
            )
        } catch {
            throw TumpaSendError.encryption(error.localizedDescription)
        }
    }

    // MARK: - Header helpers

    /// True when Mail handed us an auto-saved draft rather than a
    /// real send. Two markers (either is sufficient): the
    /// `X-Apple-Auto-Saved` header, or `X-Apple-Mail-Remote-Attachments:
    /// YES` (attachments still server-side, not inlined yet).
    private func isAutoSaveDraft(_ message: MEMessage) -> Bool {
        if headerValue("x-apple-auto-saved", in: message) != nil {
            return true
        }
        if let v = headerValue("x-apple-mail-remote-attachments", in: message),
           v.uppercased() == "YES" {
            return true
        }
        return false
    }

    /// Case-insensitive lookup against `MEMessage.headers`. Mail
    /// normalizes header capitalization (RFC 2822 keys are
    /// case-insensitive) so direct dictionary access by literal name
    /// is unreliable.
    private func headerValue(_ name: String, in message: MEMessage) -> String? {
        guard let headers = message.headers else { return nil }
        let lc = name.lowercased()
        guard let key = headers.keys.first(where: { $0.lowercased() == lc }) else {
            return nil
        }
        return headers[key]?.first
    }

    // MARK: - Errors

    enum TumpaSendError: Error {
        case signing(String)
        case encryption(String)
    }

    private func makeError(_ description: String) -> NSError {
        // `MEMessageSecurityEncodingError = 0` per MailKit's
        // `NS_ERROR_ENUM`. Swift import shape varies across Xcode
        // versions (`MEMessageSecurityErrorCode.encodingError` vs
        // `MEMessageSecurityError.encodingError`); pin the raw int
        // so the file builds against any 12.0+ SDK.
        NSError(
            domain: MEMessageSecurityErrorDomain,
            code: 0,
            userInfo: [NSLocalizedDescriptionKey: description]
        )
    }
}

// MARK: - MEMessageEncodingResult convenience

private extension MEMessageEncodingResult {
    /// Build a "send blocked" result with sign / encrypt errors. Mail
    /// shows these as a banner; the message is not sent.
    static func failure(signing: NSError?, encrypt: NSError?) -> MEMessageEncodingResult {
        MEMessageEncodingResult(
            encodedMessage: nil,
            signingError: signing,
            encryptionError: encrypt
        )
    }
}
