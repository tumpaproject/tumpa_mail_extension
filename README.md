# Tumpa Mail

OpenPGP for Apple Mail. Sign, encrypt, verify and decrypt email
without leaving Mail.app.

Tumpa Mail is a [MailKit extension](https://developer.apple.com/documentation/mailkit)
— it plugs into Apple Mail and adds PGP/MIME (RFC 3156) support
alongside Mail's built-in S/MIME. Your keys are managed by
[tumpa-cli](https://github.com/tumpaproject/tumpa-cli); Tumpa Mail
itself is just the bridge that lets Apple Mail use them.

## Requirements

- macOS Sequoia 15.x or Tahoe 26.x
- [tumpa-cli](https://github.com/tumpaproject/tumpa-cli) installed via
  Homebrew. The `tcli` agent (`brew services start tumpa-cli`) caches
  unlocked passphrases and PINs so you don't re-type them per
  message.
- A smartcard (YubiKey, Nitrokey) is supported but optional —
  software-only OpenPGP keys work too.

## Install

A signed and notarized DMG is the supported install path. Drop
`Tumpa Mail.app` into `/Applications`, then in Apple Mail:

1. Open Mail → **Settings** → **Extensions**.
2. Enable **Tumpa Mail** under **Mail Extensions**.

That's it. Apple Mail will load the extension on next message open
and on every compose.

If you want to build from source (developer flow), see
[CLAUDE.md](./CLAUDE.md).

## Setting up your keys

Tumpa Mail does not generate or import keys itself — that work
belongs to `tumpa-cli`. From a terminal:

```bash
# Generate a new key
tcli generate --uid "Alice <alice@example.com>"

# Or import an existing one
tcli import alice-secret.asc

# Confirm Tumpa Mail can see it
tcli list
```

Keys live in `~/.tumpa/keys.db`. Tumpa Mail reads the same database
through the agent.

## Daily use

### Sending mail

Compose a message in Apple Mail. The compose toolbar shows two
buttons next to the recipient field:

- **Sign** — attaches a PGP/MIME signature.
- **Encrypt** — encrypts to every recipient who has a public key in
  your keystore. Recipients without a key are flagged with a red
  dot in the chip; if any recipient is unresolvable, encryption is
  blocked until you remove or import their key.

Enable either or both, then **Send**. The first time you sign or
encrypt in a session, Tumpa Mail prompts for your key passphrase or
smartcard PIN inside Mail's window (see below). The unlocked secret
is cached by the `tcli` agent for the rest of the session, so
subsequent messages don't re-prompt.

### Reading mail

Encrypted and signed inbound messages are decoded automatically.
Click the security shield in the message header to see who signed,
which key it was encrypted to, and whether the signature verified.

If a message is encrypted to a key Tumpa Mail hasn't unlocked yet,
the body shows a placeholder ("This message is encrypted to your
OpenPGP key — click the security shield to enter your passphrase"),
and a banner appears at the top with an **Unlock** button. Either
route opens the unlock dialog.

### Unlocking your key

When Tumpa Mail needs your passphrase or smartcard PIN, a SwiftUI
form appears inside Mail's window with the key UID and fingerprint
already filled in. Type the secret, click **Unlock**.

Tumpa Mail does **not** cache the secret directly. It first runs a
quick test signature to confirm the secret is correct; only then
does it hand the verified secret to the `tcli` agent for caching.
This protects smartcards: a wrong PIN typed once consumes one card
attempt counter slot, not the cascade Apple Mail's library indexer
would otherwise trigger.

After a successful unlock:

- The popover shows "Unlocked — click the message again to decrypt
  it."
- The next message you click opens decrypted; the agent serves the
  cached secret.
- All other messages encrypted to the same key auto-decrypt for the
  rest of the agent session.

The agent forgets cached secrets when you stop it
(`brew services stop tumpa-cli`) or reboot.

## Privacy and security

- Your private keys never leave `~/.tumpa/keys.db` and your
  smartcard never has its PIN stored on disk.
- Tumpa Mail does not phone home, send telemetry, or contact any
  Tumpa-operated service. The only network traffic is the one Mail
  itself makes to send and fetch your email.
- The MailKit extension is sandboxed by Apple's runtime. All crypto
  runs in a separate XPC service that links libtumpa directly — no
  shell processes, no temp files for plaintext.
- Smartcard PINs and software passphrases are wrapped in
  `Zeroizing` containers throughout the Rust code; key material is
  zeroed on drop.

## Compatibility

Tumpa Mail produces standard PGP/MIME (RFC 3156) and verifies
against the same. Tested receivers:

- Thunderbird (built-in OpenPGP)
- gpg / GPG Suite
- Tumpa Mail itself

Inbound HTML and `multipart/alternative` messages are decoded but
have not been exhaustively round-tripped against every sender —
file an issue if you see a render glitch.

## Reporting issues

Issues, feature requests, and crash reports go to the
[Tumpa Mail GitHub issues](https://github.com/tumpaproject/tumpa-mail/issues).

When reporting a decryption or verification problem, include:

- macOS version and Mail.app version
- Tumpa Mail version (Mail → Settings → Extensions shows it)
- Output of `tcli --version`
- A live log capture taken while reproducing:
  ```bash
  log stream --predicate 'subsystem CONTAINS "in.kushaldas.tumpamail"' --info
  ```

Do **not** include your private key, your passphrase, or the
plaintext of any encrypted message. Logs are designed not to leak
those — they show fingerprints and key IDs but no secret material.

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).
