const db = require('./db');
const config = require('./config');

// Attachments are stored apart from the message body so that listing a folder does
// not download every file. Each one is AES-GCM ciphertext under the message's own key
// (the browser encrypts it; see public/js/crypto.js). Its name, type, size and SHA-256
// travel inside the encrypted message body, so the server sees only how many there are
// and roughly how big, and cannot swap, reorder or replace them unnoticed: the
// recipient's browser checks each file against that list.

const LIMITS = {
  count: 10,
  totalBytes: 10 * 1024 * 1024,        // plaintext, per message
  accountBytes: config.limits.attachmentQuotaBytes,
};
const GCM_TAG = 16;
// Largest JSON body a message with attachments can need: the files in base64 (4/3)
// plus room for the body and keys. A message to an outside address carries every
// file twice (readable for the other mail system, sealed for the Sent copy).
const MAX_REQUEST = '16mb';
const MAX_REQUEST_EXTERNAL = '30mb';

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const b64Bytes = (s) => Math.floor((s.length * 3) / 4) - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0);

const insertAttachment = db.prepare('INSERT INTO attachments (message_id, idx, ciphertext, iv, bytes) VALUES (?,?,?,?,?)');
// Counted by the account that sent the message (its 'sent' row), never by the From
// address: mail from outside can claim any From, and must not spend someone's quota.
const sentBytes = db.prepare(`
  SELECT COALESCE(SUM(a.bytes), 0) AS total
  FROM attachments a JOIN message_recipients r ON r.message_id = a.message_id
  WHERE r.user_id = ? AND r.box = 'sent'`);
const receivedFromOutsideBytes = db.prepare(`
  SELECT COALESCE(SUM(a.bytes), 0) AS total
  FROM attachments a
  JOIN message_recipients r ON r.message_id = a.message_id
  JOIN messages m ON m.id = a.message_id
  WHERE r.user_id = ? AND r.box = 'inbox' AND m.external = 1`);
const getForUser = db.prepare(`
  SELECT a.ciphertext AS ciphertext, a.iv AS iv
  FROM attachments a
  WHERE a.message_id = ? AND a.idx = ?
    AND EXISTS (SELECT 1 FROM message_recipients r WHERE r.message_id = a.message_id AND r.user_id = ?)`);

// Checks a client-supplied list of encrypted attachments. Returns the list ready to
// store ([{ ciphertext: Buffer, iv }]), [] when there is none, or null when invalid.
function parseSealed(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > LIMITS.count) return null;
  let total = 0;
  const out = [];
  for (const a of list) {
    if (!a || typeof a.ciphertext !== 'string' || !B64_RE.test(a.ciphertext) ||
        typeof a.iv !== 'string' || a.iv.length > 64 || !B64_RE.test(a.iv)) return null;
    const bytes = b64Bytes(a.ciphertext);
    if (bytes < GCM_TAG) return null; // an empty file is just the 16-byte tag
    total += bytes - GCM_TAG;
    if (total > LIMITS.totalBytes) return null;
    out.push({ ciphertext: Buffer.from(a.ciphertext, 'base64'), iv: a.iv });
  }
  return out;
}

// File names and types come from the sender and end up in MIME headers and on the
// recipient's disk: no control characters, no path separators, bounded length, and
// no bidirectional overrides (which can make "fdp.exe" display as ".pdf").
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
function cleanName(name) {
  const n = String(name || '').replace(UNSAFE_NAME_CHARS, '').replace(/[\\/]/g, '_').trim().slice(0, 200);
  return n && n !== '.' && n !== '..' ? n : 'adjunto';
}
function cleanType(type) {
  const t = String(type || '').toLowerCase();
  return t.length <= 100 && /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/.test(t) ? t : 'application/octet-stream';
}

// Checks the plaintext files of a message going OUTSIDE Sealed Mail, which the other
// mail system needs readable. Returns [{ filename, contentType, content }] for
// nodemailer, [] when there is none, or null when invalid.
function parsePlain(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > LIMITS.count) return null;
  let total = 0;
  const out = [];
  for (const f of list) {
    if (!f || typeof f.data !== 'string' || !B64_RE.test(f.data)) return null;
    total += b64Bytes(f.data);
    if (total > LIMITS.totalBytes) return null;
    out.push({ filename: cleanName(f.name), contentType: cleanType(f.type), content: Buffer.from(f.data, 'base64') });
  }
  return out;
}

// True when storing `incoming` more attachments would take this account over quota.
function overQuota(userId, incoming) {
  const adding = incoming.reduce((n, a) => n + a.ciphertext.length, 0);
  return adding > 0 && sentBytes.get(userId).total + adding > LIMITS.accountBytes;
}
// Same for mail from outside, per recipient: an internet sender cannot fill the disk.
function inboundOverQuota(userIds, plaintextBytes) {
  return plaintextBytes > 0 && userIds.some((id) => receivedFromOutsideBytes.get(id).total + plaintextBytes > LIMITS.accountBytes);
}

// At most one attachment-bearing send per account may sit between its quota check and
// its commit. The external-send path (smtp-out.js) awaits the mail relay in that window;
// without this lock a concurrent send would pass the same quota check against the same
// committed state and both commit past the limit (TOCTOU). Internal sends (mail.js) are
// synchronous — no await between check and insert — so they only honour the lock, never
// hold it, and so cannot overshoot on their own.
const sendingWithFiles = new Set();
const sendInProgress = (userId) => sendingWithFiles.has(userId);
const beginSendWithFiles = (userId) => { sendingWithFiles.add(userId); };
const endSendWithFiles = (userId) => { sendingWithFiles.delete(userId); };

// Must run inside the transaction that inserts the message.
function store(messageId, sealed) {
  sealed.forEach((a, idx) => insertAttachment.run(messageId, idx, a.ciphertext, a.iv, a.ciphertext.length));
}

// GET /api/messages/:id/attachments/:idx — only for someone the message was sent to
// or by (anyone with a message_recipients row). Same 404 whether the attachment does
// not exist or belongs to someone else, so ids cannot be probed.
function download(req, res) {
  const id = Number(req.params.id);
  const idx = Number(req.params.idx);
  if (!Number.isInteger(id) || id < 1 || !Number.isInteger(idx) || idx < 0 || idx >= LIMITS.count) {
    return res.status(400).json({ error: 'bad id' });
  }
  const row = getForUser.get(id, idx, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.set('Cache-Control', 'no-store');
  res.json({ ciphertext: Buffer.from(row.ciphertext).toString('base64'), iv: row.iv });
}

module.exports = {
  LIMITS, MAX_REQUEST, MAX_REQUEST_EXTERNAL, parseSealed, parsePlain, cleanName, cleanType,
  overQuota, inboundOverQuota, store, download,
  sendInProgress, beginSendWithFiles, endSendWithFiles,
};
