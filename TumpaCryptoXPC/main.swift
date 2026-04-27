// SPDX-License-Identifier: GPL-3.0-or-later
//
// XPC Service Bundle entry point. macOS launches this binary on demand
// when a client (the host UI or the .appex) calls
// `NSXPCConnection(serviceName: TumpaCryptoXPCServiceName)`. We hand
// the listener over to the OS and run the runloop.

import Foundation

let delegate = TumpaCryptoServiceDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
