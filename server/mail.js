const db = require('./db');
const config = require('./config');

const getUserByEmail = db.prepare('SELECT id, email, pub_key FROM users WHERE email = ?');
const insertMessage = db.prepare('INSERT INTO messages (sender_email, ciphertext, iv, created_at) VALUES (?,?,?,?)');
const insertRecipient = db.prepare('INSERT INTO message_recipients (message_id,user_id,box,enc_key,read_flag) VALUES (?,?,?,?,0)');
const listBox = db.prepare(`
  SELECT m.id AS id, m.sender_email AS sender, m.ciphertext AS ciphertext, m.iv AS iv,
         m.created_at AS createdAt, r.enc_key AS encKey, r.read_flag AS read
  FROM message_recipients r JOIN messages m ON m.id = r.message_id
  WHERE r.user_id = ? AND r.box = ?
  ORDER BY m.created_at DESC
  LIMIT 200`);
const markRead = db.prepare('UPDATE message_recipients SET read_flag = 1 WHERE message_id = ? AND user_id = ? AND box = ?');

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && B64_RE.test(s);
const isEmail = (s) => typeof s === 'string' && s.length <= config.limits.emailLen && EMAIL_RE.test(s);

function pubkeyLookup(req, res) {
  const email = (req.query.email || '').toString().toLowerCase();
  const user = getUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: 'recipient not found' });
  res.json({ email: user.email, pubKey: user.pub_key });
}

function send(req, res) {
  const { ciphertext, iv, recipients, selfEncKey } = req.body || {};
  const L = config.limits;
  if (!isB64(ciphertext, L.ciphertextBytes) || !isB64(iv, 64) || !isB64(selfEncKey, L.encKeyB64)) {
    return res.status(400).json({ error: 'invalid message payload' });
  }
  if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > L.recipients) {
    return res.status(400).json({ error: 'invalid recipient list' });
  }
  // Resolve every recipient up front; reject the whole message if any is unknown
  // or malformed, so a message is never half-delivered.
  const resolved = [];
  for (const r of recipients) {
    if (!r || !isEmail(r.email) || !isB64(r.encKey, L.encKeyB64)) {
      return res.status(400).json({ error: 'invalid recipient entry' });
    }
    const u = getUserByEmail.get(r.email.toLowerCase());
    if (!u) return res.status(404).json({ error: `unknown recipient: ${r.email}` });
    resolved.push({ user: u, encKey: r.encKey });
  }
  const tx = db.transaction(() => {
    const info = insertMessage.run(req.user.email, ciphertext, iv, Date.now());
    const messageId = info.lastInsertRowid;
    insertRecipient.run(messageId, req.user.id, 'sent', selfEncKey);
    for (const { user, encKey } of resolved) {
      insertRecipient.run(messageId, user.id, 'inbox', encKey);
    }
    return messageId;
  });
  res.json({ ok: true, id: Number(tx()) });
}

function list(req, res) {
  const box = req.query.box === 'sent' ? 'sent' : 'inbox';
  res.json({ box, messages: listBox.all(req.user.id, box) });
}

function read(req, res) {
  const box = req.query.box === 'sent' ? 'sent' : 'inbox';
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'bad id' });
  markRead.run(id, req.user.id, box);
  res.json({ ok: true });
}

module.exports = { pubkeyLookup, send, list, read };
