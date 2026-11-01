# Sealed Mail

A small, self-hosted **end-to-end encrypted** webmail service. Messages are encrypted
in the browser; the server stores only ciphertext and can never read a message body,
a private key, or a password.

This is the model ProtonMail and Tutanota use, built from scratch to be auditable.

## What works today

- Register / log in with a password (hardened: see `docs/SECURITY.md`).
- **Recovery code** shown once at sign-up: lose the password, keep the mail.
- **Face ID / Touch ID / security key** sign-in via passkeys (WebAuthn + PRF). The
  biometric never leaves the device and the server never sees the unlock secret.
- Security panel: rotate the recovery code, add or remove passkeys (re-asks the
  password for anything that changes credentials).
- Compose, encrypt, and send a message to another registered user, with the
  recipient's key fingerprint shown for out-of-band verification.
- Inbox and Sent, with per-message decryption in the browser.
- Full session, CSRF, rate-limit, and Content-Security-Policy hardening.

## What is intentionally out of scope (for now)

- **Talking to the outside world** (Gmail, Outlook, …). Real email delivery needs
  SMTP/IMAP servers, a domain, and DNS records (SPF, DKIM, DMARC). Sealed Mail is a
  closed system: you can only message users who have registered on this instance.
  `docs/SECURITY.md` sketches how the encryption model would extend to real SMTP.
- Attachments, threading, search over encrypted bodies, multi-device key sync.

## Requirements

- Node.js 22 or newer (uses the built-in `node:sqlite` module — no native build,
  no compiler, nothing to install beyond the pure-JS deps). Tested on Node 26.

## Run it

```bash
cd sealed-mail
npm install

# create .env from the example with a fresh random secret (the server refuses to
# start with the placeholder, a weak value, or no secret at all)
node -e "const fs=require('fs');const s=require('crypto').randomBytes(32).toString('hex');fs.writeFileSync('.env',fs.readFileSync('.env.example','utf8').replace(/^SESSION_SECRET=.*$/m,'SESSION_SECRET='+s))"

npm start
```

Open http://localhost:3000, create two accounts in two browser profiles (or two
private windows), and send mail between them.

### Trying Face ID / Touch ID

1. Open http://localhost:3000 in **Safari** or **Chrome** (use `localhost`, not
   `127.0.0.1`: passkeys are bound to the hostname).
2. Log in, open **Seguridad**, name the device, press **Añadir este dispositivo**,
   confirm your password, then press **Usar Face ID o Touch ID ahora** (two presses
   because Safari only starts the biometric prompt right after a click).
3. Log out and press **Entrar con Face ID o Touch ID**. No email needed: the browser
   lists the passkeys it holds for this site.

If the browser cannot do PRF the app says so and does not enroll the passkey.

For production set `RP_ID` (e.g. `mail.example.com`) and `ORIGIN`
(e.g. `https://mail.example.com`) in `.env`; passkeys only work on that exact domain.

> Local dev runs over plain HTTP. **In production you must put it behind HTTPS**
> (a reverse proxy such as Caddy or nginx). Cookies switch to `Secure` automatically
> when `NODE_ENV=production`.

## Layout

```
server/
  index.js    Express app, security middleware, routes
  config.js   env loading + limits
  db.js       SQLite schema (ciphertext only)
  auth.js     register/login/logout, sessions, CSRF, anti-enumeration
  recovery.js recovery code, re-auth ("sudo mode"), code rotation
  passkey.js  WebAuthn enrollment/login + PRF-wrapped key storage
  mail.js     send/list/read of encrypted messages
public/
  index.html  single-page shell (no inline scripts)
  css/        styles
  js/
    crypto.js  ALL cryptography (Web Crypto API) — the file to read first
    webauthn.js passkey ceremonies + PRF (never sends the PRF secret)
    api.js     fetch + CSRF wrapper
    app.js     UI logic
  fonts/      self-hosted (the CSP allows only same-origin resources)
docs/
  SECURITY.md  threat model, crypto design, honest limitations
```

## Design

Ink on paper. The one motif is the security tint printed inside envelopes so a
letter cannot be read against the light; in the UI it always means "this is what
everyone else sees" (the ciphertext on the sign-in page, a message your key cannot
open). The sign-in page encrypts its own headline live in the browser and shows the
result: that is literally all the server ever gets.

Type roles: **Source Serif 4** for what people write (subjects, bodies, headlines),
**Atkinson Hyperlegible Next** for the interface, and **Atkinson Hyperlegible Mono**
only for strings copied character by character (recovery codes, key fingerprints,
ciphertext). The Atkinson family was designed by the Braille Institute so that
`0/O` and `l/1/I` cannot be confused, which is exactly what matters when someone is
copying a recovery code onto paper.

All three fonts are licensed under the SIL Open Font License 1.1 and served from
`public/fonts/` (latin subset, variable weights, ~120 KB in total).

## Verify the crypto without a browser

`docs/SECURITY.md` explains the model. An end-to-end check (two users, send,
decrypt, assert) can be run with the Node Web Crypto API against a running server;
the project was validated this way during development.
