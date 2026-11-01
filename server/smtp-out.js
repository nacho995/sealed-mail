const nodemailer = require('nodemailer');
const db = require('./db');
const config = require('./config');
const { helpers: h } = require('./auth');
const attachments = require('./attachments');

// Outbound SMTP: writing to someone OUTSIDE Sealed Mail (a Gmail or Outlook address).
// Their mail server cannot read our format, so this message necessarily leaves as an
// ordinary email: the browser sends the text to this server over the session, the
// server hands it to the relay, and nothing but the sender's own encrypted "Sent"
// copy is stored. The UI warns before sending.

const { domain, outbound } = config.mail;
const isLoopback = (host) => ['127.0.0.1', 'localhost', '::1'].includes(host);

const transport = nodemailer.createTransport({
  host: outbound.host,
  port: outbound.port,
  secure: outbound.secure,
  // Never send mail in clear text to a remote relay: require STARTTLS unless the relay
  // is this machine (the local Mailpit catcher during development).
  requireTLS: !outbound.secure && !isLoopback(outbound.host),
  auth: outbound.user ? { user: outbound.user, pass: outbound.pass } : undefined,
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 20_000,
});

const insertMessage = db.prepare('INSERT INTO messages (sender_email, ciphertext, iv, created_at, external) VALUES (?,?,?,?,1)');
const insertRecipient = db.prepare('INSERT INTO message_recipients (message_id,user_id,box,enc_key,read_flag) VALUES (?,?,?,?,0)');

const MAX_SUBJECT = 300;
const sendingWithFiles = new Set(); // user ids with a send-with-attachments in flight
const MAX_BODY_CHARS = 100_000;

async function sendExternal(req, res) {
  try {
    const { to, subject, body, selfCopy, files } = req.body || {};
    const recipient = String(to || '').trim().toLowerCase();
    if (!h.validEmail(recipient) || recipient.endsWith(`@${domain}`)) {
      return res.status(400).json({ error: 'not an external address' });
    }
    // CR/LF in a header is how header injection works; refuse it outright.
    if (typeof subject !== 'string' || subject.length > MAX_SUBJECT || /[\r\n]/.test(subject) ||
        typeof body !== 'string' || body.length > MAX_BODY_CHARS) {
      return res.status(400).json({ error: 'invalid message' });
    }
    if (!selfCopy || !h.validB64(selfCopy.ciphertext, config.limits.ciphertextBytes) ||
        !h.validB64(selfCopy.iv, 64) || !h.validB64(selfCopy.encKey, config.limits.encKeyB64)) {
      return res.status(400).json({ error: 'invalid sent copy' });
    }
    // The files twice: readable for the other mail system, and encrypted for the
    // sender's own Sent copy. Both lists must describe the same files.
    const plainFiles = attachments.parsePlain(files);
    const sealedFiles = attachments.parseSealed(selfCopy.attachments);
    if (!plainFiles || !sealedFiles || plainFiles.length !== sealedFiles.length) {
      return res.status(400).json({ error: 'invalid attachments' });
    }
    // One send with files per account at a time: the quota is checked here but the
    // copy is stored only after the relay answers, so parallel sends could overshoot.
    if (sealedFiles.length && sendingWithFiles.has(req.user.id)) {
      plainFiles.forEach((f) => f.content.fill(0));
      return res.status(429).json({ error: 'another send with attachments is in progress' });
    }
    if (attachments.overQuota(req.user.id, sealedFiles)) {
      plainFiles.forEach((f) => f.content.fill(0));
      return res.status(413).json({ error: 'attachment quota exceeded' });
    }
    if (sealedFiles.length) sendingWithFiles.add(req.user.id);

    // With a verified relay sender (no domain of our own), the visible name says who
    // wrote it and replies go back to that verified mailbox, since our own addresses
    // cannot receive from the internet yet.
    const envelope = outbound.from
      ? { from: { name: `${req.user.email} (Sealed Mail)`, address: outbound.from }, replyTo: outbound.from }
      : { from: req.user.email };
    try {
      await transport.sendMail({ ...envelope, to: recipient, subject, text: body, attachments: plainFiles });
    } catch {
      return res.status(502).json({ error: 'the mail relay did not accept the message' });
    } finally {
      for (const f of plainFiles) f.content.fill(0); // best effort: drop the readable copy
      sendingWithFiles.delete(req.user.id);
    }

    // Delivered: keep only the sender's own copy, which the browser encrypted.
    db.transaction(() => {
      const { lastInsertRowid } = insertMessage.run(req.user.email, selfCopy.ciphertext, selfCopy.iv, Date.now());
      insertRecipient.run(lastInsertRowid, req.user.id, 'sent', selfCopy.encKey);
      attachments.store(lastInsertRowid, sealedFiles);
    })();
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'send failed' });
  }
}

module.exports = { sendExternal };
