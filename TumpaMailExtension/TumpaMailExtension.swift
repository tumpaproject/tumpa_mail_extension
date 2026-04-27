// SPDX-License-Identifier: GPL-3.0-or-later
//
// Principal class for the .appex. Apple Mail loads this class (named
// in Info.plist's `NSExtensionPrincipalClass`) at extension start.
//
// MailKit dispatches by NAMED SELECTOR, not by `handler(for:)`
// overload — for every entry in the `MEExtensionCapabilities` array
// of the .appex's Info.plist, MailKit looks up a method whose name
// derives from the protocol name. For `MEMessageSecurityHandler` the
// expected name is `handlerForMessageSecurity()`. Mismatched name →
// `NSInternalInconsistencyException` at message-encode time.
//
// The corresponding lookups (per Apple's Mail Extension Xcode
// template at
// `/Applications/Xcode.app/.../Mail Extension.xctemplate/MailExtension.swift`):
//   • MEMessageSecurityHandler   → handlerForMessageSecurity()
//   • MEMessageActionHandler     → handlerForMessageActions()
//   • MEContentBlocker           → handlerForContentBlocker()
//   • MEComposeSessionHandler    → handler(for: MEComposeSession)
// We only declare MEMessageSecurityHandler in Info.plist, so only
// that one matters today.

import Foundation
import MailKit

@objc(TumpaMailExtension)
final class TumpaMailExtension: NSObject, MEExtension {

    private let securityHandler = TumpaOutgoingSecurityHandler()

    /// Required by MailKit when the .appex declares
    /// `MEMessageSecurityHandler` in its Info.plist's
    /// `MEExtensionCapabilities`. The same instance is reused for the
    /// life of the extension process — the handler is stateless
    /// across messages (each XPC call passes its own `MEMessage`).
    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        securityHandler
    }
}
