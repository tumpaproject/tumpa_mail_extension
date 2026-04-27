// SPDX-License-Identifier: GPL-3.0-or-later
//
// Thin parser for the `[GNUPG:]` status lines `tclig` writes to stderr.
// The lines we care about for the Mail extension are:
//
//   [GNUPG:] SIG_CREATED <type> <pk_algo> <hash_algo> <class> <ts> <fpr>
//       Sign success. We pull <hash_algo> for the multipart/signed
//       `micalg` parameter and <fpr> for the signer.
//   [GNUPG:] GOODSIG <fingerprint> <uid…>
//   [GNUPG:] BADSIG  <fingerprint> <uid…>
//       Inner-signature verify result from `--decrypt --verify-decrypt`.
//   [GNUPG:] NO_PUBKEY <key_id>
//       Inner signature present, signer not in keystore.
//   [GNUPG:] DECRYPTION_OKAY
//       Confirms the decrypt phase itself succeeded.
//   [GNUPG:] INV_RECP 0 <recipient>
//       Per-recipient encrypt failure; collected so the .appex can
//       annotate compose chips.
//
// We deliberately ignore other GnuPG status lines tclig may emit; the
// parser is a "look for the lines we want" loop, not a full grammar.

import Foundation

struct StatusLines {
    /// SHA256 / SHA384 / SHA512, parsed from SIG_CREATED's GnuPG numeric
    /// hash-algo ID (RFC 4880 §9.4: 8=SHA256, 9=SHA384, 10=SHA512).
    var sigCreatedHash: String?
    var sigCreatedFingerprint: String?

    var goodsigFingerprint: String?
    var badsigFingerprint: String?
    var noPubKeyId: String?
    /// UID portion of GOODSIG / BADSIG, if present.
    var signerUid: String?

    var decryptionOkay: Bool = false

    /// Recipients that failed to resolve, in encounter order.
    var invalidRecipients: [String] = []
}

enum StatusLineParser {

    static func parse(_ raw: Data) -> StatusLines {
        let text = String(data: raw, encoding: .utf8) ?? ""
        return parse(text)
    }

    static func parse(_ text: String) -> StatusLines {
        var out = StatusLines()
        for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = String(line)
            guard let body = stripPrefix(line, "[GNUPG:] ") else { continue }
            let parts = body.split(separator: " ", maxSplits: Int.max, omittingEmptySubsequences: true)
                .map(String.init)
            guard let head = parts.first else { continue }

            switch head {
            case "SIG_CREATED":
                // Format: SIG_CREATED <type> <pk_algo> <hash_algo> <class> <ts> <fpr>
                if parts.count >= 4, let hashId = Int(parts[3]) {
                    out.sigCreatedHash = hashAlgoName(forGnupgId: hashId)
                }
                if parts.count >= 7 {
                    out.sigCreatedFingerprint = parts[6]
                }

            case "GOODSIG":
                // GOODSIG <fingerprint> <uid…>
                if parts.count >= 2 {
                    out.goodsigFingerprint = parts[1]
                }
                if parts.count >= 3 {
                    out.signerUid = parts.dropFirst(2).joined(separator: " ")
                }

            case "BADSIG":
                if parts.count >= 2 {
                    out.badsigFingerprint = parts[1]
                }
                if parts.count >= 3 {
                    out.signerUid = parts.dropFirst(2).joined(separator: " ")
                }

            case "NO_PUBKEY":
                if parts.count >= 2 {
                    out.noPubKeyId = parts[1]
                }

            case "DECRYPTION_OKAY":
                out.decryptionOkay = true

            case "INV_RECP":
                // INV_RECP <reason> <recipient>. We don't filter on the
                // reason (0 = unknown / 1 = ambiguous / etc.) — any
                // INV_RECP for a recipient means the compose UI should
                // mark it.
                if parts.count >= 3 {
                    out.invalidRecipients.append(
                        parts.dropFirst(2).joined(separator: " ")
                    )
                }

            default:
                continue
            }
        }
        return out
    }

    private static func stripPrefix(_ s: String, _ prefix: String) -> String? {
        guard s.hasPrefix(prefix) else { return nil }
        return String(s.dropFirst(prefix.count))
    }

    /// Map a GnuPG numeric hash-algo ID (RFC 4880 §9.4) back to a
    /// canonical name. Mirrors `gpg_hash_algo_id` in
    /// `tumpa-cli/src/gpg/sign.rs`.
    static func hashAlgoName(forGnupgId id: Int) -> String? {
        switch id {
        case 1:  return "MD5"
        case 2:  return "SHA1"
        case 3:  return "RIPEMD160"
        case 8:  return "SHA256"
        case 9:  return "SHA384"
        case 10: return "SHA512"
        case 11: return "SHA224"
        case 12: return "SHA3-256"
        case 14: return "SHA3-512"
        default: return nil
        }
    }
}

/// Parse `tclig --list-keys --with-colons` into `TumpaKeyInfo` rows.
///
/// tclig 0.5.0's colon output is leaner than full GnuPG: it emits
/// `pub`/`sec` rows with the 16-char key id in column 4, the primary
/// UID on a separate `uid` row immediately after, and any number of
/// `sub` rows we don't care about for the picker. There is **no**
/// `fpr` row in the current output (the parser will pick one up if
/// future tclig versions add it).
///
/// State machine: when we hit a `pub`/`sec` we start a pending row
/// holding the key id. The next `uid` line we see (before another
/// `pub`/`sec`) fills its `primaryUid`. When the row ends — at the
/// next `pub`/`sec` or EOF — we materialize and append. An optional
/// `fpr` row, if it shows up, upgrades the 16-char id to a full
/// 40-char fingerprint.
///
/// Example tclig 0.5.0 output:
///
/// ```text
/// pub:-:0:0:E3917C1325E60537:1777294917:1814400000:::::sc:
/// uid:-::::::::Kushal Das <kushal@civilized.systems>:
/// sub:-:0:0:7533F0A54A204200:1777294917:1814400000:::::e:
/// ```
enum ColonListingParser {

    static func parse(_ text: String) -> [TumpaKeyInfo] {
        var out: [TumpaKeyInfo] = []
        var pending: PendingRow?

        for raw in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = String(raw)
            let cols = line.split(separator: ":",
                                  maxSplits: Int.max,
                                  omittingEmptySubsequences: false).map(String.init)
            guard let kind = cols.first else { continue }

            switch kind {
            case "pub", "sec":
                // Flush any pending row that's now complete (every
                // pub/sec we've seen needs to be materialized when
                // the NEXT pub/sec arrives, since tclig's output
                // doesn't have a per-row terminator).
                if let p = pending { out.append(p.materialize()) }

                // The 16-char key id sits in column 4 of `pub`/`sec`.
                // tclig's `resolve_signer` accepts either 16-char key
                // ids or 40-char fingerprints for `-u`, so the
                // fallback identifier works for signing without an
                // `fpr` row.
                let validity = cols.count > 1 ? cols[1] : ""
                let identifier = cols.count > 4 ? cols[4] : ""
                guard !identifier.isEmpty,
                      identifier.allSatisfy({ $0.isHexDigit })
                else {
                    pending = nil
                    continue
                }

                pending = PendingRow(
                    fingerprint: identifier,         // upgraded by an `fpr` row if present
                    isSecret: kind == "sec",
                    isRevoked: validity == "r",
                    isExpired: validity == "e",
                    primaryUid: ""
                )

            case "uid":
                // Take the first uid we see for a key as primary.
                // Subsequent uids on the same key are non-primary
                // aliases the picker doesn't need to surface.
                guard var p = pending, p.primaryUid.isEmpty,
                      cols.count > 9
                else {
                    continue
                }
                let uid = cols[9]
                if !uid.isEmpty {
                    p.primaryUid = uid
                    pending = p
                }

            case "fpr":
                // Optional in tclig 0.5.0. When present it upgrades
                // the 16-char identifier to the full 40-char
                // fingerprint.
                guard var p = pending, cols.count > 9 else { continue }
                let fp = cols[9]
                if fp.count == 40, fp.allSatisfy({ $0.isHexDigit }) {
                    p.fingerprint = fp
                    pending = p
                }

            default:
                continue
            }
        }
        // Flush the final pending row (no more pub/sec to trigger it).
        if let p = pending { out.append(p.materialize()) }
        return out
    }

    private struct PendingRow {
        var fingerprint: String
        var isSecret: Bool
        var isRevoked: Bool
        var isExpired: Bool
        var primaryUid: String

        func materialize() -> TumpaKeyInfo {
            TumpaKeyInfo(
                fingerprint: fingerprint,
                primaryUid: primaryUid.isEmpty ? fingerprint : primaryUid,
                isSecret: isSecret,
                hasCard: false,           // colon listing doesn't surface card status; UI shows "—"
                isRevoked: isRevoked,
                isExpired: isExpired
            )
        }
    }
}

private extension Character {
    var isHexDigit: Bool {
        ("0"..."9").contains(self) || ("A"..."F").contains(self) || ("a"..."f").contains(self)
    }
}
