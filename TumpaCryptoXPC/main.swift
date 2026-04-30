// SPDX-License-Identifier: GPL-3.0-or-later
//
// XPC Service Bundle entry point. macOS launches this binary on demand
// when a client (the host UI or the .appex) calls
// `NSXPCConnection(serviceName: TumpaCryptoXPCServiceName)`. We hand
// the listener over to the OS and run the runloop.

import Foundation

// Strip macOS-Sequoia `com.apple.provenance` xattrs from `~/.tumpa/`
// before the listener spins up. If the keystore was tagged by an
// older sandboxed creator, every cross-bundle access (i.e. our .appex
// / host UI calling into this service) triggers the "data from other
// apps" TCC prompt — sometimes on every send. Strip-on-launch makes
// the prompt non-recurring even on machines that came in tagged.
ProvenanceCleaner.sweepTumpaDirectory()

let delegate = TumpaCryptoServiceDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
