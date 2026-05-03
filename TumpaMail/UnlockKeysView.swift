// SPDX-License-Identifier: GPL-3.0-or-later
//
// Host-app pane that lets the user pre-cache passphrases and smartcard
// PINs into the tumpa agent BEFORE composing a signed/encrypted mail.
//
// Why this exists: MailKit's `encodedMessage(for:composeContext:)`
// callback is one-shot — it must return an encoded result or an error
// synchronously, and there is no MailKit hook to "stall the send and
// ask the user for a PIN." The .appex's in-Mail unlock popover only
// fires on the inbound *decode* path (we attach a synthetic signer to
// `MEDecodedMessage` whose context renders the SecureField). On the
// outbound side, when libtumpa needs a PIN that isn't cached, the
// signing call just errors out and Mail surfaces it as a system alert
// like "smartcard PIN required for Kushal Das <mail@kushaldas.in>"
// with no path to actually unlock.
//
// This pane closes that gap. The host app HAS an Aqua session so it
// can render a SecureField directly. The XPC service's transient
// store accepts the typed secret; a sentinel `signDetached` call
// verifies it; on success libtumpa's promote-on-success path writes
// to `~/.tumpa/agent.sock`. After that, every Mail send (and every
// `tcli`/`tpass` call) reuses the cached secret without prompting.
//
// State machine per row:
//
//   .probing             — running the sentinel sign to find out
//                          whether the key is locked or not.
//   .unlocked            — sentinel sign succeeded. Agent has the
//                          secret cached. (User can still re-enter
//                          via the manual "Lock" → "Unlock" cycle if
//                          they want to switch cards mid-session.)
//   .lockedNeedsPin      — sentinel sign returned needsUnlock with
//                          isPin=true. Card-backed key, no cached PIN.
//   .lockedNeedsPassphrase — needsUnlock with isPin=false. Software
//                          key, no cached passphrase.
//   .error(String)       — probe failed for some other reason
//                          (keystore broken, connection invalidated,
//                          etc.). Show the message; don't offer
//                          unlock since we don't know what's wrong.
//
// The sentinel payload is the same `"tumpa-mail-unlock-verify"`
// string `SecurityDetailView` uses for its in-Mail popover, so the
// two unlock paths share the verify-by-test-sign semantics exactly.

import SwiftUI

struct UnlockKeysView: View {

    @State private var keys: [TumpaKeyInfo] = []
    @State private var states: [String: LockState] = [:]
    @State private var loadingError: String?
    @State private var loading = true
    /// The key currently being unlocked via sheet. SwiftUI `.sheet(item:)`
    /// is driven off this — set non-nil to open, nil to close.
    @State private var unlockTarget: UnlockTarget?

    var body: some View {
        VStack(spacing: 0) {
            if loading && keys.isEmpty {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let err = loadingError, keys.isEmpty {
                emptyState(
                    icon: "exclamationmark.triangle",
                    title: "Could not load keys",
                    detail: err
                )
            } else if secretKeys.isEmpty {
                emptyState(
                    icon: "key.slash",
                    title: "No secret keys",
                    detail: "Import or generate a secret key with `tcli` first. Public-only keys don't need unlocking."
                )
            } else {
                List {
                    Section {
                        ForEach(secretKeys) { key in
                            row(for: key)
                        }
                    } header: {
                        Text("Secret keys")
                    } footer: {
                        Text("Unlocking writes the verified passphrase / PIN to the tumpa agent so subsequent Mail sends, decryptions, and tcli operations reuse it without prompting.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }

            Divider()
            HStack {
                Spacer()
                Button("Refresh") { Task { await reload() } }.disabled(loading)
            }
            .padding(8)
        }
        .navigationTitle("Unlock")
        .task { await reload() }
        .sheet(item: $unlockTarget) { target in
            UnlockSheet(
                target: target,
                onClose: { unlockTarget = nil },
                onUnlocked: { fp in
                    states[fp] = .unlocked
                    unlockTarget = nil
                }
            )
        }
    }

    private var secretKeys: [TumpaKeyInfo] {
        // Show keys the user can actually unlock: software keys with
        // secret material in the keystore (`isSecret`) AND
        // card-backed keys (`hasCard`) whose secret material is on a
        // smartcard. Without the `hasCard` half, card-only users see
        // an empty pane — `tcli card link` writes only the cert into
        // `~/.tumpa/keys.db`, so libtumpa reports `isSecret = false`
        // for those rows, and the secrets-only filter would hide them.
        //
        // Filter out revoked/expired: no useful unlock path for them
        // (signing/decrypting with them would fail anyway).
        keys.filter { ($0.isSecret || $0.hasCard) && !$0.isRevoked && !$0.isExpired }
    }

    @ViewBuilder
    private func row(for key: TumpaKeyInfo) -> some View {
        let state = states[key.fingerprint] ?? .probing
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: state.glyph)
                .font(.title3)
                .foregroundStyle(state.glyphColor)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(key.primaryUid).font(.body)
                Text(key.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Text(state.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            switch state {
            case .probing:
                ProgressView().controlSize(.small)
            case .unlocked:
                Text("Unlocked")
                    .font(.caption)
                    .foregroundStyle(.green)
            case .lockedNeedsPin, .lockedNeedsPassphrase:
                Button("Unlock") {
                    unlockTarget = UnlockTarget(
                        fingerprint: key.fingerprint,
                        uid: key.primaryUid,
                        isPin: state == .lockedNeedsPin
                    )
                }
                .buttonStyle(.borderedProminent)
            case .error:
                Button("Retry") {
                    Task { await probe(key) }
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    /// macOS-13 friendly stand-in for `ContentUnavailableView`. Same
    /// shape KeysView uses.
    private func emptyState(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(detail)
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @MainActor
    private func reload() async {
        loading = true
        defer { loading = false }
        loadingError = nil
        do {
            keys = try await XPCClient.shared.listKeys()
        } catch {
            keys = []
            loadingError = error.localizedDescription
            return
        }
        // Probe every secret key in parallel — keystores with many
        // keys would otherwise block on serial card I/O for each.
        // Each probe writes its own `states[fp]` entry, so concurrent
        // updates don't race meaningfully (last-writer-wins per key).
        await withTaskGroup(of: Void.self) { group in
            for key in secretKeys {
                group.addTask { await probe(key) }
            }
        }
    }

    @MainActor
    private func probe(_ key: TumpaKeyInfo) async {
        states[key.fingerprint] = .probing
        do {
            _ = try await XPCClient.shared.signDetached(
                canonicalizedBody: Self.sentinelPayload,
                signerFingerprint: key.fingerprint,
                digest: "SHA256"
            )
            states[key.fingerprint] = .unlocked
        } catch XPCClientError.needsUnlock(_, _, let isPin) {
            states[key.fingerprint] = isPin ? .lockedNeedsPin : .lockedNeedsPassphrase
        } catch {
            states[key.fingerprint] = .error(error.localizedDescription)
        }
    }

    /// The bytes signed by the probe. Identical to what
    /// `SecurityDetailView` uses on the inbound popover side, so the
    /// two unlock paths exercise the same verify-by-test-sign code in
    /// libtumpa.
    fileprivate static let sentinelPayload = Data("tumpa-mail-unlock-verify".utf8)
}

// MARK: - Per-row state

enum LockState: Equatable {
    case probing
    case unlocked
    case lockedNeedsPin
    case lockedNeedsPassphrase
    case error(String)

    var glyph: String {
        switch self {
        case .probing:                return "hourglass"
        case .unlocked:               return "lock.open.fill"
        case .lockedNeedsPin:         return "key.radiowaves.forward.fill"
        case .lockedNeedsPassphrase:  return "lock.fill"
        case .error:                  return "exclamationmark.triangle.fill"
        }
    }

    var glyphColor: Color {
        switch self {
        case .probing:                return .secondary
        case .unlocked:               return .green
        case .lockedNeedsPin,
             .lockedNeedsPassphrase:  return .orange
        case .error:                  return .red
        }
    }

    var detail: String {
        switch self {
        case .probing:
            return "Checking agent cache…"
        case .unlocked:
            return "Cached in the agent — sends and decrypts will not prompt."
        case .lockedNeedsPin:
            return "Smartcard locked. Click Unlock to enter the PIN."
        case .lockedNeedsPassphrase:
            return "Software key locked. Click Unlock to enter the passphrase."
        case .error(let msg):
            return msg
        }
    }
}

// MARK: - Unlock sheet

struct UnlockTarget: Identifiable {
    let fingerprint: String
    let uid: String
    let isPin: Bool

    var id: String { fingerprint }
}

private struct UnlockSheet: View {
    let target: UnlockTarget
    let onClose: () -> Void
    let onUnlocked: (String) -> Void

    @State private var secret: String = ""
    @State private var unlocking: Bool = false
    @State private var unlockError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: target.isPin ? "key.radiowaves.forward.fill" : "lock.fill")
                    .font(.title2)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(target.isPin ? "Unlock smartcard" : "Unlock key")
                        .font(.headline)
                    Text(target.uid)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(target.fingerprint)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text(target.isPin
                     ? "Enter the smartcard PIN. After verification, the PIN is cached in the tumpa agent so future sends and decryptions don't prompt."
                     : "Enter the key passphrase. After verification, the passphrase is cached in the tumpa agent so future sends and decryptions don't prompt.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                SecureField(
                    target.isPin ? "Smartcard PIN" : "Passphrase",
                    text: $secret
                )
                .textFieldStyle(.roundedBorder)
                .disabled(unlocking)
                .onSubmit { Task { await submit() } }

                if let err = unlockError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(20)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", action: onClose)
                    .keyboardShortcut(.cancelAction)
                    .disabled(unlocking)
                Button {
                    Task { await submit() }
                } label: {
                    if unlocking {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Unlock")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(secret.isEmpty || unlocking)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(minWidth: 460)
    }

    @MainActor
    private func submit() async {
        unlocking = true
        unlockError = nil
        defer { unlocking = false }

        // Step 1: queue the typed secret in the XPC service's
        // in-memory transient slot. cachePassphrase NEVER writes to
        // ~/.tumpa/agent.sock directly — that would let an unverified
        // wrong PIN burn smartcard attempt counter slots on every
        // subsequent libtumpa op.
        do {
            try await XPCClient.shared.cachePassphrase(
                fingerprint: target.fingerprint,
                isPin: target.isPin,
                secret: Data(secret.utf8)
            )
        } catch {
            unlockError = error.localizedDescription
            return
        }

        // Step 2: verify with a real libtumpa op. A wrong secret fails
        // here; LibtumpaRunner.signDetached's error branch wipes the
        // transient slot so we don't replay it. A right secret
        // succeeds and the runner's promote-on-success hook moves the
        // transient → ~/.tumpa/agent.sock for reuse.
        //
        // Cost calculus for cards: this consumes 1 attempt counter
        // slot — exactly the cost a real send would have paid. Net is
        // zero; UX is much better because the user gets feedback now
        // instead of mid-compose.
        do {
            _ = try await XPCClient.shared.signDetached(
                canonicalizedBody: UnlockKeysView.sentinelPayload,
                signerFingerprint: target.fingerprint,
                digest: "SHA256"
            )
            secret = "" // zeroize the View state.
            onUnlocked(target.fingerprint)
        } catch {
            unlockError = target.isPin
                ? "Wrong PIN. Please try again."
                : "Wrong passphrase. Please try again."
            // Don't clear the SecureField — let the user edit & retry.
        }
    }
}
