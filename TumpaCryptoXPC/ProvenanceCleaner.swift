// SPDX-License-Identifier: GPL-3.0-or-later
//
// Strip `com.apple.provenance` xattrs from `~/.tumpa/` at XPC service
// startup.
//
// macOS Sequoia tags files created by sandboxed apps with the
// `com.apple.provenance` extended attribute, recording which sandboxed
// bundle wrote them. Subsequent accesses by a *different* bundle ID
// trigger the "<App> would like to access data from other apps." TCC
// prompt. The tumpa keystore at `~/.tumpa/keys.db` may have been
// created by an older sandboxed Tumpa GUI build (or an earlier dev
// rebuild whose code-design identity has since rotated), in which
// case the provenance points at a bundle that no longer matches our
// XPC service / .appex. macOS treats every keystore access as
// cross-app and prompts the user — sometimes once, sometimes (if the
// user-grant table can't anchor the access) on every send.
//
// The XPC service runs unsandboxed, so we can fix the file in place:
// remove the provenance xattr at service launch, before any libtumpa
// op touches the keystore. Idempotent — `removexattr` on an absent
// xattr returns ENOATTR, which we silently swallow.
//
// Sockets (`agent.sock`, `tcli-ssh.sock`) can't carry xattrs and
// return ENOTSUP from `removexattr` — also silently swallowed.

import Foundation
import os.log

private let cleanLog = Logger(
    subsystem: "in.kushaldas.tumpamail.crypto",
    category: "provenance-cleaner"
)

enum ProvenanceCleaner {

    /// Remove `com.apple.provenance` from `~/.tumpa/` and every entry
    /// directly inside it. Called once at XPC service launch from
    /// `main.swift`.
    static func sweepTumpaDirectory() {
        let tumpaDir = ("~/.tumpa" as NSString).expandingTildeInPath
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: tumpaDir, isDirectory: &isDir), isDir.boolValue else {
            return
        }

        // The directory itself.
        strip(at: tumpaDir)

        // Every immediate child. We don't recurse — the tumpa
        // keystore layout is flat (`keys.db`, `agent.sock`, …) and
        // recursion would slow startup if the user ever added
        // unrelated subdirectories there.
        guard let entries = try? fm.contentsOfDirectory(atPath: tumpaDir) else {
            return
        }
        for name in entries {
            strip(at: (tumpaDir as NSString).appendingPathComponent(name))
        }
    }

    /// `removexattr(2)` for one path, swallowing the two expected
    /// non-error outcomes:
    /// - `ENOATTR` (93): the xattr wasn't there to begin with.
    /// - `ENOTSUP` (102): unsupported on this filesystem entry
    ///   (sockets — `agent.sock` / `tcli-ssh.sock` hit this).
    private static func strip(at path: String) {
        // `XATTR_NOFOLLOW = 0x0001` keeps us from chasing symlinks
        // back into the user's home — defense-in-depth in case the
        // user has a symlink in `~/.tumpa/`.
        let result = path.withCString { cpath in
            removexattr(cpath, "com.apple.provenance", XATTR_NOFOLLOW)
        }
        if result == 0 {
            cleanLog.info("stripped com.apple.provenance from \(path, privacy: .public)")
        } else {
            let err = errno
            // 93 = ENOATTR (typedef'd from ENODATA on darwin), 102 = ENOTSUP.
            if err != 93 && err != 102 {
                cleanLog.error("removexattr(\(path, privacy: .public)) failed errno=\(err)")
            }
        }
    }
}
