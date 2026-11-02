# Sealed Mail

Your own webmail, where **the server only ever stores ciphertext**. Write to anyone
(Gmail, Outlook, any address) and receive mail like any email service, with one
difference: nothing stored on the server can be read by the server, so there is
nothing on it worth reading, leaking or training a model on.

- **Between Sealed Mail users**: end-to-end encrypted. Messages are encrypted in the
  sender's browser and opened only in the recipient's.
- **With everyone else** (ordinary email over SMTP): mail that arrives is sealed with
  your key the moment it is received, so only ciphertext is ever written; mail you
  send out leaves as a normal email (the other side cannot read anything else), the
  app warns you before sending, and your Sent copy is stored encrypted.

> [!IMPORTANT]
> **Sending to anyone works; receiving from the internet is still pending.**
>
> | | Status |
> |---|---|
> | Mail between Sealed Mail users (end-to-end encrypted, with attachments) | ✅ works |
> | Writing to any Gmail, Outlook… address over the internet, through your own Gmail account (`npm run setup:gmail`, no domain needed) | ✅ works |
> | Writing to / receiving from outside addresses **on your machine** (Mailpit, `npm run mail:test`) | ✅ works |
> | Receiving from Gmail, Outlook… **over the internet** | ❌ **not active: needs a domain you own** |
>
> Receiving is written and tested (inbound SMTP, and polling Resend's receiving API).
> What is missing is infrastructure: **a domain whose MX record points at the mail
> provider**. To turn it on:
> 1. Add a domain or subdomain you own in Resend, with receiving enabled (a subdomain
>    such as `mail.example.com` keeps your existing mailboxes untouched).
> 2. Create the DNS records Resend lists at your DNS provider and verify the domain.
> 3. Set the Resend block of `.env.example` in your `.env` and restart.
>
> Until then, replies to what you send go to your Gmail inbox, not to the app.

## The app

| Sign in | Inbox | Security |
|---|---|---|
| ![Sign-in: the headline decrypts itself and is shown encrypted as an armored block and an xxd dump, next to the sign-in pane where a kid juggles 0s and 1s](docs/images/app-sign-in.jpg) | ![Folder and open message side by side: new mail flagged N, an unverified outside sender ?, a spoofed sender !, an unreadable message shown as cipher, and an attachment ready to save](docs/images/app-inbox.jpg) | ![Security panel: key fingerprint, recovery code, passkeys, sessions](docs/images/app-security.jpg) |

- **Write to any address.** Sealed Mail recipients get end-to-end encryption; any
  other address gets an ordinary email through your SMTP relay (Mailpit locally,
  Gmail, SendGrid or any SMTP provider for real delivery).
- **Receive from anyone.** A built-in SMTP server accepts mail for your accounts
  only (never an open relay), seals it on arrival and flags it "from outside,
  sender not verified", because ordinary email cannot prove who sent it.
- Register and log in with a password; a **recovery code** shown once at sign-up.
- **Face ID / Touch ID / security keys** through WebAuthn passkeys with the PRF
  extension: the biometric never leaves the device, the unlock secret never reaches
  the server.
- **Attachments**, encrypted in the browser like the text (up to 10 files and 10 MB
  per message). The reader checks every file against a hash sealed inside the
  message, so the server cannot swap one without replacing the whole message.
- Compose, send, read. Recipient **key fingerprints** for out-of-band verification;
  the sender shown is the one the server authenticated, and a client-claimed
  `from` that disagrees is flagged.
- Security panel: your fingerprint, rotate the recovery code, add or remove devices,
  sign out other sessions. Anything that changes how the account opens re-checks the
  password on the server.

## How it works

```mermaid
sequenceDiagram
    participant A as Alice's browser
    participant S as Server
    participant B as Bob's browser
    A->>S: ask for Bob's public key
    S-->>A: Bob's public key (Alice can check its fingerprint)
    Note over A: fresh AES-256-GCM key K<br/>encrypt the message with K<br/>wrap K with Bob's RSA-OAEP key
    A->>S: ciphertext + wrapped K
    Note over S: stores bytes it cannot open
    B->>S: fetch inbox
    S-->>B: ciphertext + wrapped K
    Note over B: unwrap K with his private key<br/>(unlocked by password, recovery code or passkey)<br/>decrypt and verify
```

Bob's private key exists on the server only as three wrapped copies, each under a
secret that never leaves his side:

| Copy | Wrapped under | Where that secret lives |
|---|---|---|
| password | PBKDF2-SHA256, 310 000 rounds | Bob's memory |
| recovery code | PBKDF2 of 160 random bits | paper / password manager |
| each passkey | HKDF of the WebAuthn PRF output | the device's secure chip |

## What the server can and cannot do

| | |
|---|---|
| Read stored mail | **No**: ciphertext only |
| Read mail exchanged with outside addresses | **In transit, yes**: ordinary email is plaintext by nature, so the server holds it in memory while delivering or sealing it. It is never written in the clear |
| Alter a stored message unnoticed | **No**: AES-GCM rejects any change to it |
| Replace a message with one it sealed itself | **Yes**: it has your public key and messages are not signed, so AES-GCM proves a message was not changed, not who wrote it |
| Learn passwords | **No**: it receives a key derived with PBKDF2 and then HKDF, and stores `scrypt` of it |
| Tell which addresses have accounts | **Partly**: login, recovery and passkey sign-in give constant-shape answers (fake salts, usernameless passkeys), but sign-up says when an address is taken and logged-in users can look up recipients |
| Hand out a fake public key | **Yes**, unless users compare fingerprints |
| Serve malicious JavaScript | **Yes**: inherent to web-delivered E2E, not solved here |
| See who mails whom, and when | **Yes**: metadata is not hidden |

The full threat model, every hardening measure and the honest limitations are in
[`docs/SECURITY.md`](docs/SECURITY.md).

## How it was built

Built with an agentic workflow: one coding agent implementing, and a separate
read-only application-security agent auditing each finished feature without sharing
the implementer's reasoning. Three audits so far:

- The second one found a high-severity flaw: enrolling a passkey required the password
  only in the UI, not on the server.
- The third, on attachments, found that mail from outside claiming to be a user could
  exhaust that user's attachment quota, and that a right-to-left override could make
  `fdp.exe` display as `.pdf`.

An outside tester then found three more:
- A message whose encrypted body had a non-text `from` stopped the recipient's folder from rendering.
- An invisible character let a second account pass for an existing address.
- A malicious server could get the private-key wrapping key sent to it by answering
  the login salt request with the wrapping salt.

The tester also pointed out that the table above overstated what AES-GCM proves.

Every finding was fixed and is covered by a test.

## Run it

Requires Node.js **22.13 or newer** (uses the built-in `node:sqlite`, so there is no
native build and nothing to compile).

```bash
git clone https://github.com/nacho995/sealed-mail.git
cd sealed-mail
npm install

# .env from the example with a fresh random secret (the server refuses to start
# with the placeholder, a weak value, or no secret at all)
node -e "const fs=require('fs');const s=require('crypto').randomBytes(32).toString('hex');fs.writeFileSync('.env',fs.readFileSync('.env.example','utf8').replace(/^SESSION_SECRET=.*$/m,'SESSION_SECRET='+s))"

npm start
```

Open http://localhost:3000/ and create an account (your address will be
`nombre@sealed.local`). From there you can write to anyone.

### Email with the outside world

Out of the box everything stays on your machine. Outgoing mail is caught by Mailpit
(web inbox at http://localhost:8025/):

```bash
brew install mailpit && mailpit
```

To simulate someone outside writing to you (as another mail server would):

```bash
npm run mail:test -- nombre@sealed.local "Hola" "Escrito desde fuera"
```

**Sending for real (to any Gmail, Outlook… address) with your Gmail account**, no
domain needed:

1. Turn on 2-Step Verification in your Google account, then create an app password
   at myaccount.google.com/apppasswords (16 letters).
2. Run `npm run setup:gmail` in your terminal. It asks for the address and the app
   password (not shown while you type), logs in to `smtp.gmail.com` over TLS to check
   them, writes `.env` with permissions 600 and can send you a test email.
3. Restart. Mail now goes out from your Gmail address, signed by Google, so it is not
   flagged as spoofed, and replies arrive in that Gmail inbox.

An app password is not limited to sending: it also opens the whole mailbox over IMAP,
and it sits in this server's `.env`. Prefer a Gmail account created only for this.

**Or with SendGrid**, also without a domain:

1. In SendGrid, *Settings → Sender Authentication → Single Sender Verification*:
   verify an address you own (for example your Gmail).
2. *Settings → API Keys*: create a key with the **Mail Send** permission only.
3. Run `npm run setup:sendgrid` in your terminal. It asks for the verified address and
   the key (the key is not shown while you type), checks the key with SendGrid,
   writes `.env` with permissions 600 and can send you a test email. Or edit `.env`
   by hand (never commit it), replacing the two `SMTP_OUT_*` lines with:
   ```
   SMTP_OUT_HOST=smtp.sendgrid.net
   SMTP_OUT_PORT=587
   SMTP_OUT_USER=apikey
   SMTP_OUT_PASS=<your API key>
   SMTP_OUT_FROM=<the address you verified>
   ```
4. Restart. Mail now goes out from the verified address, showing your Sealed Mail
   name, and replies arrive at that address. The connection to the relay must use
   TLS: the app refuses to send in clear text to any relay other than localhost.

**Sending and receiving with your own domain through Resend** (recommended): add a
subdomain you own in Resend with sending and receiving enabled (for example
`mail.example.com`, so the main domain's existing mailboxes are untouched), create the
DNS records Resend lists, then set in `.env` the Resend block shown in
`.env.example`. Outgoing mail leaves from each user's own address. Incoming mail is
**polled** from Resend's API every 15 seconds, so the app needs no public URL. Each
message is sealed on arrival like any other, and the sender is marked verified when
DMARC passed.

Without a domain of your own, deliverability is limited (a gmail.com sender sent
through SendGrid fails DMARC and may land in spam; through Gmail itself it does not).
**Receiving mail from the internet** needs a
domain whose MX record points at this server, with the SMTP port exposed over TLS;
set `MAIL_DOMAIN` to it and the same code handles it.

### Face ID / Touch ID

1. Use **Safari** or **Chrome** on `localhost` (not `127.0.0.1`: passkeys are bound
   to the hostname).
2. Log in, open **Seguridad**, name the device, press **Añadir este dispositivo**,
   confirm the password, then **Usar Face ID o Touch ID ahora** (two presses because
   Safari only starts the biometric prompt right after a click).
3. Log out and press **Entrar con Face ID o Touch ID**. No email needed.

If the browser cannot do PRF, the app says so instead of enrolling a passkey that
could sign in but not decrypt. In production set `RP_ID` and an `https` `ORIGIN` in
`.env`, and put the app behind HTTPS.

### Tests

```bash
npm test
```

Starts the real server on a free port with a throwaway database, then drives it with
the real browser crypto module: sending and decrypting, real SMTP in and out (with a
stand-in outside mail server, a byte-level check that incoming plaintext never
reaches the database, and open-relay refusal), recovery (including two simultaneous
recoveries racing for the same code), password re-checks, passkey defences, session
revocation, encrypted attachments (round trip, a stranger gets 404, a swapped or
substituted file is rejected, limits and quotas, files in and out by SMTP) and error
handling: 49 checks. CI runs it on Node 22 and 24.

## Out of scope (for now)

- **Receiving from the internet** needs a domain (MX record) and the SMTP port
  exposed with TLS, or Resend's receiving API; sending already works through your
  Gmail or any SMTP relay.
- HTML mail (shown as text), previews of attached images, threads, search over
  encrypted bodies, forward secrecy.

## Layout

```
server/        Express app: auth, recovery, passkeys, mail, rate limits, CSP,
               SMTP in (smtp-in.js) and out (smtp-out.js)
scripts/       send-test-mail.mjs: "someone outside writes to you";
               setup-smtp.mjs: connects Gmail or SendGrid for outgoing mail
public/        the web app (no inline scripts); js/crypto.js holds ALL cryptography
tests/e2e.mjs  end-to-end test suite
docs/          SECURITY.md and README images
```

## Design

A professional security console, in the spirit of the tools people who do security
work use every day: tmux-style panes with their title in the border, a powerline
status bar, keys shown as keycaps, steel grey on navy. Colour is kept for meaning:
signal green for the one thing to act on (the main button, the pane you are in, new
mail), teal for ciphertext, amber for "not verified", red for spoofed.

The app is driven from the keyboard (`c` write, `e` inbox, `v` sent, `s` security,
`a` attach, `j`/`k` or arrows to move, Enter to open, `q` or Esc to go back), and every
key is also a button for touch screens. On a wide screen an open message sits beside
its folder, as in mutt. The flag column is never truncated, so warnings live there:
`N` new, `!` the message claims a different sender, `?` from outside and not verified.

The motion always shows something real: the headline decrypts itself and is then
encrypted in your browser (shown as an armored block and an `xxd` dump, with the
measured time); a message crumbles into ciphertext as you send it; an opened letter
decrypts on screen. A kid juggling 0s and 1s keeps the sign-in and an empty inbox
company. All of it stops for anyone who asks for reduced motion.

Type: **Martian Mono** for titles, labels and bars, **Atkinson Hyperlegible Mono** for
everything you read, designed so `0/O` and `l/1/I` cannot be confused in recovery
codes and fingerprints. All fonts are SIL Open Font License 1.1, self-hosted.
