const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const db = require('./db');
const config = require('./config');
const { sealForRecipients } = require('./sealing');

// Inbound SMTP: how ordinary email (Gmail, Outlook, any mail client) reaches a Sealed
// Mail inbox. Each message is parsed and sealed with the recipients' public keys in
// memory; only the ciphertext is written. The plaintext never touches the disk.
//
// It only accepts mail FOR local accounts, so it can never be used as an open relay
// to send spam elsewhere.

const getUser = db.prepare('SELECT id, email, pub_key FROM users WHERE email = ?');
const insertMessage = db.prepare('INSERT INTO messages (sender_email, ciphertext, iv, created_at, external) VALUES (?,?,?,?,1)');
const insertRecipient = db.prepare('INSERT INTO message_recipients (message_id,user_id,box,enc_key,read_flag) VALUES (?,?,?,?,0)');

const MAX_RECIPIENTS = 20;
const MAX_SUBJECT = 300;
const MAX_BODY_CHARS = 200_000;

// An SMTP error with a status code the sending server will understand.
function smtpError(code, message) {
  return Object.assign(new Error(message), { responseCode: code });
}

function cleanAddress(addr) {
  const a = String(addr || '').trim().toLowerCase();
  return a.length <= config.limits.emailLen && /^[^\s@<>"]+@[^\s@<>"]+$/.test(a) ? a : '';
}

async function deliver(raw, session) {
  const mail = await simpleParser(raw, { skipImageLinks: true, skipTextLinks: true });
  const recipients = [...new Set(session.envelope.rcptTo.map((r) => cleanAddress(r.address)))]
    .map((a) => getUser.get(a))
    .filter(Boolean);
  if (!recipients.length) throw smtpError(550, 'No such user here');

  // The From header is whatever the sender claims: ordinary SMTP does not prove it.
  // It is stored as the sender but the message is flagged external, and the UI says so.
  const from = cleanAddress(mail.from && mail.from.value && mail.from.value[0] && mail.from.value[0].address)
    || cleanAddress(session.envelope.mailFrom && session.envelope.mailFrom.address)
    || 'remitente-desconocido@invalid';
  const attachments = (mail.attachments || []).length;
  let body = (mail.text || '').slice(0, MAX_BODY_CHARS); // HTML-only mail arrives converted to text
  if (attachments) body += `\n\n[${attachments} adjunto(s) no incluido(s): Sealed Mail todavía no admite adjuntos]`;

  const content = {
    from,
    to: recipients.map((u) => u.email),
    subject: String(mail.subject || '').slice(0, MAX_SUBJECT),
    body,
  };
  const sealed = await sealForRecipients(content, recipients.map((u) => u.pub_key));
  db.transaction(() => {
    const { lastInsertRowid } = insertMessage.run(from, sealed.ciphertext, sealed.iv, Date.now());
    recipients.forEach((u, i) => insertRecipient.run(lastInsertRowid, u.id, 'inbox', sealed.encKeys[i]));
  })();
}

function startInboundSmtp() {
  const { domain, inbound } = config.mail;
  const server = new SMTPServer({
    name: domain,
    banner: 'Sealed Mail',
    size: inbound.maxBytes,
    authOptional: true,
    // Local development: no AUTH (nobody logs in to deliver mail) and no STARTTLS.
    // Exposed to the internet this needs STARTTLS with a real certificate.
    disabledCommands: ['AUTH', 'STARTTLS'],
    disableReverseLookup: true,
    maxClients: 20,
    socketTimeout: 30_000,
    logger: false,

    onRcptTo(address, session, callback) {
      const addr = cleanAddress(address.address);
      if (!addr.endsWith(`@${domain}`)) return callback(smtpError(554, 'Relaying denied'));
      if (session.envelope.rcptTo.length >= MAX_RECIPIENTS) return callback(smtpError(452, 'Too many recipients'));
      if (!getUser.get(addr)) return callback(smtpError(550, 'No such user here'));
      return callback();
    },

    onData(stream, session, callback) {
      const chunks = [];
      let size = 0;
      stream.on('data', (chunk) => {
        size += chunk.length;
        if (size <= inbound.maxBytes) chunks.push(chunk);
      });
      stream.on('end', async () => {
        const raw = Buffer.concat(chunks);
        chunks.length = 0;
        try {
          if (stream.sizeExceeded || size > inbound.maxBytes) return callback(smtpError(552, 'Message too large'));
          await deliver(raw, session);
          return callback();
        } catch (err) {
          return callback(err.responseCode ? err : smtpError(451, 'Temporary failure, try again later'));
        } finally {
          raw.fill(0); // best effort: do not leave the plaintext lying in this buffer
        }
      });
    },
  });
  server.on('error', (err) => {
    // eslint-disable-next-line no-console
    console.error(`inbound SMTP error: ${err.code || err.message}`);
  });
  server.listen(inbound.port, inbound.host, () => {
    // eslint-disable-next-line no-console
    console.log(`receiving mail for @${domain} on smtp://${inbound.host}:${inbound.port}`);
  });
  return server;
}

module.exports = { startInboundSmtp };
