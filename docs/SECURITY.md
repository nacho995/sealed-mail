# Security model

The goal: **only the user can read their mail.** Not the server operator, not an
attacker who steals the database, not a company that wants to mine inboxes to train
models. This document is deliberately honest about what the design achieves and what
it does not.

## Keys and derivations

On registration, the browser:

1. Generates an **RSA-OAEP 2048** keypair (the account identity).
2. Derives two independent keys from the password with **PBKDF2-HMAC-SHA256,
   310 000 iterations**, using two different salts:
   - `authKey = PBKDF2(password, saltAuth)` — sent to the server as the login secret.
   - `wrapKey = PBKDF2(password, saltWrap)` — **never leaves the browser**.
3. Exports the private key, encrypts it with `wrapKey` (**AES-256-GCM**), and uploads
   only that ciphertext.
4. Uploads the public key in the clear (it is not secret).

The server stores `scrypt(authKey)` (N=16384) as the login verifier — a second,
memory-hard barrier. Because `authKey` and `wrapKey` use different salts, the value
the server receives (`authKey`) cannot be used to derive `wrapKey`, so the server
cannot decrypt the private key it stores.

## Sending a message

1. Browser generates a random **AES-256-GCM** message key and encrypts
   `{from, to, subject, body}`.
2. It fetches each recipient's public key and **RSA-wraps the message key** once per
   recipient (and once for the sender's own "Sent" copy).
3. It uploads `{ciphertext, iv, wrapped-keys}`. The server stores exactly that.

Reading reverses it: the browser RSA-unwraps the message key with its private key,
then AES-decrypts the body.

**The server only ever holds ciphertext and wrapped keys. It has no key to open any
of it.**

### Attachments

- Each file is encrypted in the browser under **the same message key**, with a fresh
  96-bit IV and its position (`sealed-mail attachment <n>`) as AES-GCM additional
  data. A file therefore cannot be presented as another file, or as the body.
- The body carries, for every file, its name, type, size and **SHA-256**. After
  decrypting a file, the reader checks it against that list and refuses anything that
  does not match, so the server cannot substitute, reorder or truncate files. It can
  only withhold one, and the reader then shows the download failing.
- Files are stored apart from the body (`attachments` table), so listing a folder
  does not download them, and are fetched one at a time by whoever the message was
  sent to or by. Anyone else gets the same 404 as for a file that does not exist.
- Saving a file always hands the browser `application/octet-stream` under a cleaned
  name (no path separators or control characters): nothing received is rendered or run
  by the page.
- Limits: 10 files and 10 MB per message. 250 MB of stored attachments per account,
  counted by the account that sent them, never by the From address (mail from outside
  can claim any From). One send with files to an outside address at a time per
  account, so parallel sends cannot overshoot the quota. The larger request body these
  routes need (16 MB; 30 MB to outside addresses, which carry each file twice) is only
  parsed after the session and CSRF checks, and sends are rate-limited per account.
- File names lose path separators, control characters and bidirectional overrides
  (which could make `fdp.exe` display as `.pdf`), both when shown and when saved.
- **What the server learns**: how many files a message has and their encrypted sizes
  (each is its plaintext size plus 16 bytes). Names, types and contents stay sealed.

## Login hardening

- `scrypt` verifier + `crypto.timingSafeEqual` comparison.
- **Account-enumeration resistance**: `/api/salt` returns a deterministic HMAC-based
  fake salt for unknown emails, and `/api/login` burns comparable CPU time and returns
  a generic error whether or not the account exists.
- **Sessions**: 256-bit random token in an `HttpOnly; SameSite=Strict` cookie; only
  `sha256(token)` is stored server-side; 12-hour expiry with periodic cleanup. Each
  session records which passkey opened it (if any). The Security panel can close
  every other session.
- **CSRF**: double-submit token (a readable `csrf` cookie echoed in `x-csrf-token`)
  on top of `SameSite=Strict`.
- **Rate limiting**: a separate counter per flow (login, sign-up, recovery,
  password re-checks, passkey sign-in, general API), so one busy flow cannot lock
  people out of another. IPv6 clients are grouped by `/64`. Recovery and password
  re-checks also have a per-account cap. `scrypt` runs at most 4 at a time with a
  bounded queue, so unauthenticated requests cannot exhaust CPU or memory.
- **Secrets**: the server refuses to start with a missing, weak (< 128-bit hex) or
  placeholder `SESSION_SECRET`, because a known secret would let anyone recompute the
  anti-enumeration fake salts. In production it also refuses to start without an
  explicit `RP_ID` and an `https` `ORIGIN`.
- **Errors**: any unhandled error or malformed body gets a short JSON reply. The
  server never shows Express's HTML page with a stack trace.
- **CSP**: `default-src 'self'`, no `unsafe-inline` (the frontend has zero inline
  script/style), `object-src 'none'`, `frame-ancestors 'none'`. This is the main
  barrier against an XSS stealing a message after it is decrypted in the DOM.
- **Input validation** on every field (email/hex/base64 shape + length caps);
  parameterized SQL everywhere (no string-built queries).
- Hashing and key derivation on the server use only Node's built-in `crypto`.
  WebAuthn signature verification is delegated to `@simplewebauthn/server`
  (pinned to an exact version) — that is not code to hand-roll.

## Account recovery and passkeys

The constraint: the server cannot hold anything that decrypts the mail. So every
way back into an account is just **another wrapped copy of the same private key**,
each wrapped under a secret only the user has. Old mail stays readable after any of
them, because the private key never changes.

| Unlock method | Wrapping secret | Where the secret lives |
|---|---|---|
| Password | PBKDF2(password) | the user's memory |
| Recovery code | PBKDF2(160-bit random code) | paper / password manager |
| Passkey (Face ID, Touch ID, security key) | HKDF(WebAuthn **PRF** output) | the device's secure chip |

**Recovery code.** Generated in the browser at registration (20 random bytes, base32,
shown once). It goes through the same derivation as the password: a recovery
`authKey` for the server (`scrypt` verifier) and a separate wrapping key that never
leaves the browser.
- **Recovering** re-wraps the private key under a new password **and a new code**.
  The used code is burned, and **every existing session and every passkey** is
  revoked, so a device someone else enrolled does not survive the reset.
- **The new code is shown before anything is written.** The server only stores it
  once the user confirms they have saved it. If that request fails, the old code is
  still valid; a code that nobody has can never be the only one on file.
- **Writes are compare-and-swap.** A write only applies if the verifier just checked
  is still in place, so two simultaneous requests with the same code cannot both
  succeed (tested), and a rotation cannot silently overwrite a recovery.
- **Rotating** the code while logged in requires the password again, checked on the
  server, so a stolen session cookie alone cannot swap in an attacker's code.

**Passkeys.** WebAuthn is used twice in one ceremony:
1. **Authentication**: the server checks the passkey signature against a
   single-use, 5-minute challenge, with `userVerification: required` (the device
   must actually check the face/fingerprint/PIN, not just a tap). The signature
   counter is updated compare-and-swap, so two cloned assertions cannot both pass.
2. **Key unlock**: the PRF extension makes the authenticator return a 32-byte secret,
   only after user verification, bound to this site and this credential. The browser
   derives an AES key from it (HKDF) and unwraps the private key. **The PRF output is
   never sent to the server**: the client serializers leave `clientExtensionResults`
   empty, and the server rejects any request whose `clientExtensionResults` mentions
   `prf` at all.

- **Enrolling a passkey requires the password, checked on the server** before the
  challenge is issued. Without that check, a stolen session cookie would be enough to
  register an attacker's authenticator and keep permanent access. It would not be
  able to read mail, but it could send mail as the user with a verified sender.
- **Sign-in is usernameless** (discoverable credentials). The browser offers this
  site's passkeys, the chosen one names its account through a random per-user handle
  (never the database row id), and the server checks that this handle owns the
  credential. The server is never asked "does this email have passkeys?", so that
  question cannot be used to enumerate accounts.
- **The PRF input is a public constant** (`SHA-256("sealed-mail/prf/v1")`). The
  authenticator mixes in a secret unique to each credential, so the outputs still
  differ per passkey. A per-credential random input added nothing, and it would have
  had to be sent before sign-in, which leaks.
- **Spotting a rogue device**: each passkey lists its authenticator model (AAGUID,
  with friendly names for common ones), when it was added, and when it was last used.
  Labels are stripped of control and bidirectional characters, so a label cannot
  imitate another device's name. Removing a passkey also ends the sessions it opened.

The face or fingerprint itself never leaves the device; the server stores no
biometric data at all.

### Why not SMS or server-side face recognition

- **SMS** can prove "someone has this phone number" but it cannot give back a
  decryption key unless the server keeps one, and that would break E2E. On top of
  that, SMS is weak against SIM swapping and SS7 interception. SMS would only make
  sense as an optional second login factor, and it would not help with a lost
  password.
- **Face matching on the server** would mean storing biometric templates (special
  category data under GDPR art. 9, and impossible to rotate if leaked), and the
  server could then unlock accounts by itself. Passkeys give the same experience with
  the biometric check confined to the user's device.

### Recovery-specific limitations

- **A leaked recovery code is as good as the password.** Store it offline. If it
  might have been seen, rotate it from the Security panel.
- **Synced passkeys inherit the sync account's security.** An iCloud Keychain or
  Google Password Manager passkey is end-to-end encrypted by that provider, but
  whoever controls that account and a device signed into it can use the passkey.
- **PRF support is required** (recent Safari / Chrome, or a FIDO2 security key with
  `hmac-secret`). The app detects missing support and refuses to enroll rather than
  enrolling a passkey that could log in but not decrypt.
- **No recovery path for losing everything.** Password, recovery code and every
  passkey gone means the mail is gone. That is the price of nobody else being able
  to read it.
- **Recovering removes your passkeys too.** After a recovery, add your devices again.
  This is deliberate: it is how a device that someone else enrolled gets removed.
- **Salt polling.** `/api/salt` and `/api/recover/salt` return fake salts that never
  change for unknown emails, while real salts change on recovery or rotation.
  Someone who polls an address over time can therefore tell that it exists and that
  its credentials changed. This adds to the metadata that is already visible (point 6
  below).
- **Not done yet (low value, noted from the audit)**: binding each AES-GCM wrap to
  its purpose with associated data (it would turn swapped blobs into clean decrypt
  failures), and an in-app notice when a new passkey is added.

## Honest limitations

These are inherent to browser-delivered E2E and are not bugs to "fix" silently:

1. **Lose every unlock method = lose the mail.** Password, recovery code and passkeys
   are the only ways back (see above). A recovery path that worked without one of
   them would mean someone other than the user could decrypt.
2. **Malicious/compromised server could serve bad JavaScript.** Any web-delivered
   E2E app (ProtonMail included) shares this: the server that ships the crypto code
   could ship code that captures the password. Mitigations in the real world:
   Subresource Integrity, reproducible builds, a browser extension / native client.
   Not solved here.
3. **Key substitution (distinct from #2).** The sender fetches the recipient's public
   key from the server (`GET /api/pubkey`). A malicious server can return *its own*
   public key, so the sender's honest, unmodified code encrypts to the attacker — no
   bad JS and no password capture needed. Code-integrity fixes (SRI, native client)
   do NOT close this; only **key authentication** does. Partial mitigation shipped:
   the compose view displays the recipient's **key fingerprint** and the Security panel
   shows your own, so two people can verify out-of-band that the server did not swap a key.
   A production system needs key pinning (TOFU) and/or a key-transparency log.
4. **No sender authentication (messages are not signed).** `from` inside the
   encrypted body is written by the sender's client and is not cryptographically
   bound to anyone. The UI therefore shows the **server-attested** sender
   (`sender_email`, taken from the authenticated session) as authoritative and flags
   any message whose embedded `from` disagrees. Full origin proof needs message
   signatures (RSA-PSS / Ed25519); not implemented yet.
5. **Offline brute force.** An attacker who steals the DB can try passwords against
   `scrypt(authKey)` offline; a cracked password yields `wrapKey` and the mail.
   PBKDF2 (310k) + scrypt slow this down, but **password strength is the ultimate
   backstop.** Consider adding a strength meter / minimum entropy.
6. **Metadata is not hidden.** The server sees who mailed whom and when (it must, to
   route), and any logged-in user can probe `/api/pubkey` to learn which addresses
   are registered. Only content is encrypted. Hiding metadata needs much more
   (mixnets, etc.).
7. **RSA-OAEP 2048** is fine today; a production build should consider 3072/4096 or a
   migration to hybrid ECDH (X25519) + per-message forward secrecy.
8. **No forward secrecy.** If a private key leaks, all past mail to that user is
   readable. ECDH ephemeral keys per message would fix this.

## Real email (SMTP)

End-to-end encryption only works between Sealed Mail users, because it needs the
recipient's public key. Ordinary email is plaintext by nature. The boundary works
like ProtonMail's: encrypted inside, ordinary email at the edge, and nothing written
in the clear on either side.

**Incoming** (`server/smtp-in.js`, default `127.0.0.1:2525`):
- Accepts mail **only for existing local accounts**. Mail for other domains gets
  `554 Relaying denied`, unknown users get `550`, and there is a 15 MB size cap and a
  limit of 20 recipients. It cannot be used as an open relay.
- Each message is parsed, sealed **in memory** with the recipients' public keys (the
  exact browser format, `server/sealing.js`), and only the ciphertext is stored. The
  raw buffer is zeroed afterwards (best effort). The test suite checks byte by byte
  that the text of an incoming message never appears in the database files.
- HTML is converted to text and never rendered. Attachments are sealed like the text
  (same format as the browser's, up to 10 files / 10 MB; extra ones are left out with
  a note), and their readable copy is zeroed after sealing (best effort). Each
  recipient may hold up to 250 MB of files from outside; past that the text still
  arrives, with a note instead of the files. There is no rate limit on inbound SMTP
  yet: an internet-facing deployment needs one per sending IP.
- **The sender is not verified.** Ordinary SMTP lets anyone claim any `From`, and
  SPF/DKIM/DMARC are not checked yet. These messages are flagged "from outside,
  sender not verified" in the UI. A production deployment should verify them, either
  with its own checks or using the relay's verdicts.
- Locally there is no AUTH and no STARTTLS. Exposed to the internet, it needs STARTTLS
  with a real certificate and an MX record for `MAIL_DOMAIN`.

**Outgoing** (`server/smtp-out.js`, `POST /api/messages/external`):
- Only for addresses outside `MAIL_DOMAIN`, and only after the UI has warned that the
  message will leave as an ordinary email. The browser sends the text to the server
  over the session. The server hands it to the SMTP relay and stores only the sender's
  copy, which the browser encrypted.
- The relay connection **must use TLS** unless the relay is localhost (Mailpit).
- CR/LF in the subject is rejected (header injection). Outgoing mail is limited to 30
  messages per account per 15 minutes, so a hijacked session cannot get the domain
  blacklisted for spam.
- Without a domain, `SMTP_OUT_FROM` sends from a sender address verified with the
  relay (for example SendGrid's Single Sender, or the Gmail account itself). The
  visible name is the Sealed Mail user, and replies go to that verified mailbox.
- **Gmail as the relay, what it exposes**: a Google app password is not scoped to
  sending; it also grants IMAP access to that whole mailbox. It is stored in `.env`
  (mode 600, git-ignored), so anyone who can read the server's `.env` can read that
  Gmail account. The setup script says so and recommends a Gmail account dedicated
  to Sealed Mail. A SendGrid key with only "Mail Send" is the narrower option.

**Receiving through Resend** (`server/resend-in.js`), when `RESEND_RECEIVE_KEY` is set:
- The MX of `MAIL_DOMAIN` points at Resend. The app polls Resend's Receiving API (no
  webhook, so no public URL to attack), downloads each new message in its original
  form and passes it to the same sealing code as the SMTP server. Each provider message
  id is recorded so it is sealed exactly once.
- The SPF/DKIM/DMARC verdicts Resend reports are sealed with the message. The UI marks
  an outside sender "verified" only when DMARC passed.
- **Accepted risks** (chosen by the operator):
  - Reading received mail requires a Resend key with **full access**. Resend has no
    read-only scope. That key can manage everything in the Resend account, including
    any other domain in it. A dedicated Resend account or team for this app would
    limit the damage if the key leaked.
  - **Resend keeps its own copy of incoming mail**: there is no API to delete a
    received message. That is inherent to ordinary email (it also passes through the
    sender's provider), but it means an outside message exists in plaintext outside
    this server.
- Outgoing mail uses a separate key with **sending access only, restricted to
  `MAIL_DOMAIN`**. Verified: Resend answers `401 restricted_api_key` if that key tries
  to read mail or manage domains.

**What this means**: while a message to or from an outside address is in transit,
the server holds its text in memory. It is never written in the clear, but a
compromised server could read it then. Mail between Sealed Mail users never gives
the server that chance.
