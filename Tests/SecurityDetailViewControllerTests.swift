// SPDX-License-Identifier: GPL-3.0-or-later
//
// Regression guard for the Tahoe (macOS 26) ViewBridge crash hit when
// the user clicks the puzzle-piece "Details" button on a signed
// message. Mail's main thread crashed in
// `_swift_stdlib_bridgeErrorToNSError` while serializing our
// `MEExtensionViewController` reply across XPC. The fix in
// `SecurityDetailView.swift` was to switch from
// `loadView()` + bare `NSHostingView` to `viewDidLoad()` + child
// `NSHostingController` + Auto Layout + `preferredContentSize`.
//
// These tests don't reach Mail — they just instantiate the VC and
// assert the structural shape that ViewBridge expects:
//   1. The view has been loaded with at least one subview.
//   2. `preferredContentSize` is non-zero (ViewBridge uses it to size
//      the popover and to encode the VC's geometry across XPC).
//   3. The hosted SwiftUI view fills the parent (constraints active).
//
// If anyone reverts to the old `loadView()` shape, (2) regresses to
// `.zero` and these tests fail.

import XCTest
import AppKit
import MailKit
import SwiftUI

final class SecurityDetailViewControllerTests: XCTestCase {

    /// Read-only signed state — common case. Forces `viewDidLoad` and
    /// inspects the resulting view tree.
    func testSignedContext_viewLoadsWithChildHostingControllerAndPreferredSize() {
        let ctx = TumpaSecurityContext(
            status: .signed,
            signerEmail: "alice@example.com",
            signerLabel: "Alice <alice@example.com>",
            fingerprint: "1111222233334444555566667777888899990000"
        )
        let vc = TumpaSecurityDetailViewController(context: ctx)

        // Triggers viewDidLoad.
        _ = vc.view

        XCTAssertGreaterThan(
            vc.view.subviews.count, 0,
            "Hosting controller's view must be added as a subview; an empty subview list means we regressed to the bare-NSHostingView loadView() shape that crashed Mail on Tahoe."
        )
        XCTAssertGreaterThan(
            vc.preferredContentSize.width, 0,
            "preferredContentSize.width must be set so ViewBridge can size the popover."
        )
        XCTAssertGreaterThan(
            vc.preferredContentSize.height, 0,
            "preferredContentSize.height must be set so ViewBridge can size the popover."
        )
        XCTAssertEqual(
            vc.children.count, 1,
            "Exactly one child NSHostingController expected (mirrors mailgpg's working shape)."
        )
        XCTAssertTrue(
            vc.children.first is NSHostingController<SecurityDetailView>,
            "Child must be an NSHostingController hosting SecurityDetailView."
        )
    }

    /// Locked state has the SecureField + Unlock button — bigger
    /// intrinsic size than the read-only states. Just checks the same
    /// structural invariants hold; sizes will differ but stay non-zero.
    func testLockedWaitingContext_viewLoadsWithPreferredSize() {
        let ctx = TumpaSecurityContext(
            status: .lockedWaiting,
            signerEmail: nil,
            signerLabel: "Tumpa Test Key",
            fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
            isPin: false
        )
        let vc = TumpaSecurityDetailViewController(context: ctx)
        _ = vc.view

        XCTAssertGreaterThan(vc.view.subviews.count, 0)
        XCTAssertGreaterThan(vc.preferredContentSize.width, 0)
        XCTAssertGreaterThan(vc.preferredContentSize.height, 0)
        XCTAssertEqual(vc.children.count, 1)
    }

    /// The hosted view should be pinned to the parent on all four
    /// sides. We don't read the constraints array directly (Auto
    /// Layout reformulates them); instead we force a layout pass and
    /// check the host view's frame matches the parent.
    func testHostedView_PinnedToParentOnAllSides() {
        let ctx = TumpaSecurityContext(status: .signed)
        let vc = TumpaSecurityDetailViewController(context: ctx)
        _ = vc.view

        // Give the parent a definite size, then run Auto Layout.
        vc.view.frame = NSRect(x: 0, y: 0, width: 400, height: 300)
        vc.view.needsLayout = true
        vc.view.layoutSubtreeIfNeeded()

        guard let host = vc.children.first?.view else {
            XCTFail("Missing child hosting controller view")
            return
        }
        XCTAssertEqual(host.frame, vc.view.bounds,
                       "Hosting view must be pinned to the parent's bounds.")
    }
}
