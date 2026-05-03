// SPDX-License-Identifier: GPL-3.0-or-later
//
// `NSXPCListenerDelegate` + `TumpaCryptoXPC` implementation. One
// instance per incoming connection (one for the host UI, one for the
// .appex). Each method dispatches to a background queue and calls the
// supplied reply block — XPC reply blocks are one-shot and must be
// invoked exactly once on every code path.

import Foundation
import os.log

private let svcLog = Logger(
    subsystem: "in.kushaldas.tumpamail.crypto",
    category: "service"
)

final class TumpaCryptoService: NSObject, TumpaCryptoXPC {

    private let runner = LibtumpaRunner()
    private let workQueue = DispatchQueue(label: "in.kushaldas.tumpamail.crypto.work",
                                          qos: .userInitiated,
                                          attributes: .concurrent)

    // MARK: - Agent cache (in-Mail unlock flow)

    func cachePassphrase(
        fingerprint: String,
        isPin: Bool,
        secret: Data,
        reply: @escaping (Bool, NSError?) -> Void
    ) {
        workQueue.async {
            // Store in the IN-MEMORY transient slot, NOT the agent
            // socket. Writing the popover-typed secret directly to
            // `~/.tumpa/agent.sock` would cache it before any
            // verification — and Mail's library indexer triggers
            // many decryptVerify calls in succession, so a wrong
            // PIN would burn N card attempts in a row and lock the
            // card. The transient slot is consumed by the next
            // libtumpa op; on success it gets promoted to the
            // agent, on failure it's wiped (max one card attempt
            // counter slot consumed per popover submission).
            let cacheKey = isPin
                ? TumpaAgentClient.pinKey(forFingerprint: fingerprint)
                : TumpaAgentClient.passphraseKey(forFingerprint: fingerprint)
            TumpaTransientStore.shared.put(cacheKey: cacheKey, secret: Array(secret))
            svcLog.info("cachePassphrase queued in transient slot for \(cacheKey, privacy: .public)")
            reply(true, nil)
        }
    }

    // MARK: - Health

    func agentSocketExists(reply: @escaping (Bool) -> Void) {
        workQueue.async {
            let path = ("~/.tumpa/agent.sock" as NSString).expandingTildeInPath
            reply(FileManager.default.fileExists(atPath: path))
        }
    }

    // MARK: - Sign

    func signDetached(
        canonicalizedBody: Data,
        signerFingerprint: String,
        digest: String,
        reply: @escaping (Data?, String?, String?, String?, Bool, NSError?) -> Void
    ) {
        workQueue.async {
            do {
                let out = try self.runner.signDetached(
                    body: canonicalizedBody,
                    signerFingerprint: signerFingerprint,
                    digest: digest
                )
                reply(out.armoredSignature, out.hashAlgorithm, nil, nil, false, nil)
            } catch let LibtumpaError.secretUnavailable(fp, uid, isPin, _) {
                svcLog.error("signDetached needs unlock for \(fp, privacy: .public) (isPin=\(isPin))")
                reply(
                    nil, nil,
                    fp, uid, isPin,
                    Self.nsError(LibtumpaError.secretUnavailable(
                        fingerprint: fp, uid: uid, isPin: isPin, message: "needs unlock"))
                )
            } catch {
                reply(nil, nil, nil, nil, false, Self.nsError(error))
            }
        }
    }

    // MARK: - Encrypt

    func encrypt(
        plaintext: Data,
        recipientFingerprints: [String],
        signerFingerprint: String?,
        armor: Bool,
        reply: @escaping (Data?, [String], String?, String?, Bool, NSError?) -> Void
    ) {
        workQueue.async {
            svcLog.info(
                "encrypt called — plaintextSize=\(plaintext.count) recipients=\(recipientFingerprints, privacy: .public) signer=\(signerFingerprint ?? "<none>", privacy: .public) armor=\(armor)"
            )
            do {
                let ct = try self.runner.encrypt(
                    plaintext: plaintext,
                    recipients: recipientFingerprints,
                    signerFingerprint: signerFingerprint,
                    armor: armor
                )
                svcLog.info("encrypt OK — ciphertextSize=\(ct.count)")
                reply(ct, [], nil, nil, false, nil)
            } catch let LibtumpaError.invalidRecipients(bad) {
                svcLog.error("encrypt FAILED with invalidRecipients=\(bad, privacy: .public)")
                reply(nil, bad, nil, nil, false, Self.nsError(LibtumpaError.invalidRecipients(bad)))
            } catch let LibtumpaError.secretUnavailable(fp, uid, isPin, _) {
                svcLog.error("encrypt needs unlock for \(fp, privacy: .public) (isPin=\(isPin))")
                reply(nil, [], fp, uid, isPin,
                      Self.nsError(LibtumpaError.secretUnavailable(
                        fingerprint: fp, uid: uid, isPin: isPin, message: "needs unlock")))
            } catch {
                svcLog.error(
                    "encrypt FAILED — \(error.localizedDescription, privacy: .public) :: \(String(describing: error), privacy: .public)"
                )
                reply(nil, [], nil, nil, false, Self.nsError(error))
            }
        }
    }

    // MARK: - Decrypt + verify

    func decryptVerify(
        armoredCiphertext: Data,
        reply: @escaping (Data?, String, String?, String?, String?, String?, String?, Bool, NSError?) -> Void
    ) {
        workQueue.async {
            do {
                let out = try self.runner.decryptVerify(ciphertext: armoredCiphertext)
                reply(
                    out.plaintext,
                    out.signatureStatus,
                    out.signerFingerprint,
                    out.signerKeyId,
                    out.signerUid,
                    nil,
                    nil,
                    false,
                    nil
                )
            } catch let LibtumpaError.secretUnavailable(fp, uid, isPin, _) {
                svcLog.error("decryptVerify needs unlock for \(fp, privacy: .public) (isPin=\(isPin))")
                reply(
                    nil,
                    TumpaSignatureStatus.unknown,
                    nil, nil, nil,
                    fp, uid, isPin,
                    Self.nsError(LibtumpaError.secretUnavailable(
                        fingerprint: fp, uid: uid, isPin: isPin, message: "needs unlock"))
                )
            } catch {
                // On decrypt failure we have no plaintext to surface
                // the signature status against. Caller renders an
                // error banner in the message viewer.
                reply(nil, TumpaSignatureStatus.unknown, nil, nil, nil, nil, nil, false, Self.nsError(error))
            }
        }
    }

    // MARK: - Verify detached

    func verifyDetached(
        signedBytes: Data,
        armoredSignature: Data,
        reply: @escaping (String, String?, String?, String?, NSError?) -> Void
    ) {
        workQueue.async {
            do {
                let out = try self.runner.verifyDetached(
                    signedBytes: signedBytes,
                    signature: armoredSignature
                )
                reply(out.status, out.signerFingerprint, out.signerKeyId, out.signerUid, nil)
            } catch {
                reply(TumpaSignatureStatus.unknown, nil, nil, nil, Self.nsError(error))
            }
        }
    }

    // MARK: - List keys

    func listKeys(reply: @escaping ([TumpaKeyInfo], NSError?) -> Void) {
        workQueue.async {
            do {
                let keys = try self.runner.listKeys()
                reply(keys, nil)
            } catch {
                reply([], Self.nsError(error))
            }
        }
    }

    // MARK: - Describe key

    func describeKey(
        fingerprint: String,
        reply: @escaping (String?, NSError?) -> Void
    ) {
        workQueue.async {
            do {
                let text = try self.runner.describeKey(fingerprint: fingerprint)
                reply(text, nil)
            } catch {
                reply(nil, Self.nsError(error))
            }
        }
    }

    // MARK: - Resolve recipients

    func resolveRecipients(
        emails: [String],
        reply: @escaping ([String: String], NSError?) -> Void
    ) {
        workQueue.async {
            svcLog.info("resolveRecipients called with \(emails.count) email(s): \(emails, privacy: .public)")
            do {
                let resolved = try self.runner.resolveRecipients(emails: emails)
                svcLog.info("resolveRecipients result: \(resolved, privacy: .public)")
                reply(resolved, nil)
            } catch {
                svcLog.error("resolveRecipients FAILED: \(error.localizedDescription, privacy: .public) :: \(String(describing: error), privacy: .public)")
                reply([:], Self.nsError(error))
            }
        }
    }

    // MARK: - Helpers

    private static func nsError(_ error: Error) -> NSError {
        // Always rebuild the NSError with the description in the
        // userInfo dictionary. The default `error as NSError` bridge
        // gets the right domain/code but the LocalizedError
        // `errorDescription` string lives in a Swift-side
        // _NSErrorRecoveryAttempting hook that DOESN'T survive the
        // XPC encode/decode trip — the receiving process sees a
        // generic "operation couldn't be completed (DOMAIN error N)".
        // Forcing the string into userInfo[NSLocalizedDescriptionKey]
        // makes it part of the encoded blob.
        let description = (error as? LocalizedError)?.errorDescription
            ?? error.localizedDescription
        let bridged = error as NSError
        return NSError(
            domain: bridged.domain,
            code: bridged.code,
            userInfo: [NSLocalizedDescriptionKey: description]
        )
    }
}

/// `NSXPCListenerDelegate` registered by `main.swift`. Vends one
/// `TumpaCryptoService` per incoming connection.
final class TumpaCryptoServiceDelegate: NSObject, NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let exported = NSXPCInterface(with: TumpaCryptoXPC.self)

        // Allow the `[TumpaKeyInfo]` and `[String: String]` reply slots
        // to cross — XPC requires explicit class allow-listing for
        // collection-shaped reply payloads.
        let listKeysSel = #selector(TumpaCryptoXPC.listKeys(reply:))
        exported.setClasses(
            NSSet(array: [NSArray.self, TumpaKeyInfo.self, NSString.self]) as! Set<AnyHashable>,
            for: listKeysSel,
            argumentIndex: 0,
            ofReply: true
        )

        let resolveSel = #selector(TumpaCryptoXPC.resolveRecipients(emails:reply:))
        exported.setClasses(
            NSSet(array: [NSDictionary.self, NSString.self]) as! Set<AnyHashable>,
            for: resolveSel,
            argumentIndex: 0,
            ofReply: true
        )

        connection.exportedInterface = exported
        connection.exportedObject = TumpaCryptoService()
        connection.resume()
        return true
    }
}
