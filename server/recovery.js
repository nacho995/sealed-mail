const crypto = require('node:crypto');
const db = require('./db');
const { helpers: h } = require('./auth');

// Recovery-code flow. The code is generated in the browser at registration and the
// account private key is wrapped under it, exactly like the password copy. The
// server only stores scrypt(recAuthKey) and the wrapped blob, so it cannot use the
// recovery path to read mail any more than it can use the password path.

const getUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const getUserById = db.prepare('SELECT * FROM users WHERE id = ?');

// Every credential write is conditional on the verifier that was just checked still
// being in place (compare-and-swap). Two concurrent requests with the same code or
// password cannot both succeed, and a rotation cannot silently overwrite a recovery.
const resetCredentials = db.prepare(`UPDATE users SET
  salt_auth = ?, salt_wrap = ?, auth_hash = ?, auth_salt_srv = ?, enc_priv_key = ?, priv_iv = ?,
  rec_salt_auth = ?, rec_salt_wrap = ?, rec_auth_hash = ?, rec_auth_salt_srv = ?,
  rec_enc_priv_key = ?, rec_priv_iv = ?
  WHERE id = ? AND rec_auth_hash = ?`);
const replaceRecovery = db.prepare(`UPDATE users SET
  rec_salt_auth = ?, rec_salt_wrap = ?, rec_auth_hash = ?, rec_auth_salt_srv = ?,
  rec_enc_priv_key = ?, rec_priv_iv = ?
  WHERE id = ? AND auth_hash = ?`);
const deleteUserSessions = db.prepare('DELETE FROM sessions WHERE user_id = ?');
const deleteUserPasskeys = db.prepare('DELETE FROM passkeys WHERE user_id = ?');

function validPasswordBundle(p) {
  return !!p && h.validHex(p.saltAuth, 64) && h.validHex(p.saltWrap, 64) && h.validHex(p.authKey, 512) &&
    h.validB64(p.encPrivKey, 8192) && h.validB64(p.privIv, 64);
}

// Constant-shape check: unknown user, user without a recovery code, and wrong code
// all burn scrypt and return false, so the endpoint is not an existence oracle.
async function checkRecovery(user, recAuthKey) {
  if (!user || !user.rec_auth_hash) { await h.burnScrypt(recAuthKey); return false; }
  return h.verifyAuthHash(recAuthKey, user.rec_auth_salt_srv, user.rec_auth_hash);
}

function recoverySalt(req, res) {
  const email = (req.query.email || '').toString().toLowerCase();
  if (!h.validEmail(email)) return res.status(400).json({ error: 'invalid email' });
  const user = getUserByEmail.get(email);
  const real = user && user.rec_salt_auth;
  res.json({ saltAuth: real || h.fakeSalt('rec-salt-auth', email) });
}

// Step 1: prove knowledge of the recovery code, receive the code-wrapped private key.
async function recoverBegin(req, res) {
  try {
    const { email, recAuthKey } = req.body || {};
    if (!h.validEmail(email) || !h.validHex(recAuthKey, 512)) {
      return res.status(401).json({ error: 'invalid recovery code' });
    }
    const user = getUserByEmail.get(email.toLowerCase());
    if (!(await checkRecovery(user, recAuthKey))) return res.status(401).json({ error: 'invalid recovery code' });
    res.json({ saltWrap: user.rec_salt_wrap, encPrivKey: user.rec_enc_priv_key, privIv: user.rec_priv_iv });
  } catch {
    res.status(500).json({ error: 'recovery failed' });
  }
}

// Step 2: the browser has unwrapped the private key with the code and re-wrapped it
// under a NEW password and a NEW recovery code (which the user has already confirmed
// saving). The used code is burned, and every way in that existed before is closed:
// all sessions AND all passkeys, so a device someone else enrolled does not survive.
async function recoverComplete(req, res) {
  try {
    const { email, recAuthKey, password, recovery } = req.body || {};
    if (!h.validEmail(email) || !h.validHex(recAuthKey, 512) ||
        !validPasswordBundle(password) || !h.validRecoveryBundle(recovery)) {
      return res.status(400).json({ error: 'invalid recovery payload' });
    }
    const user = getUserByEmail.get(email.toLowerCase());
    if (!(await checkRecovery(user, recAuthKey))) return res.status(401).json({ error: 'invalid recovery code' });

    const pwSaltSrv = crypto.randomBytes(16).toString('hex');
    const pwHash = await h.scryptHash(password.authKey, pwSaltSrv);
    const rec = await h.hashRecoveryBundle(recovery);
    const applied = db.transaction(() => {
      const { changes } = resetCredentials.run(
        password.saltAuth, password.saltWrap, pwHash, pwSaltSrv, password.encPrivKey, password.privIv,
        rec.saltAuth, rec.saltWrap, rec.authHash, rec.authSaltSrv, rec.encPrivKey, rec.privIv,
        user.id, user.rec_auth_hash);
      if (Number(changes) !== 1) return false; // the code was spent by a concurrent request
      deleteUserSessions.run(user.id);
      deleteUserPasskeys.run(user.id);
      return true;
    })();
    if (!applied) return res.status(401).json({ error: 'invalid recovery code' });
    h.createSession(req, res, user.id);
    res.json({ ok: true, email: user.email });
  } catch {
    res.status(500).json({ error: 'recovery failed' });
  }
}

// "Sudo mode": a logged-in user re-proves the password to get the password-wrapped
// private key back. The in-memory key is non-extractable on purpose, so enrolling a
// passkey or rotating the recovery code needs a fresh, explicit unwrap.
async function reauth(req, res) {
  try {
    const { authKey } = req.body || {};
    if (!(await h.verifyPassword(req.user.id, authKey))) return res.status(401).json({ error: 'invalid credentials' });
    const user = getUserById.get(req.user.id);
    res.json({ saltWrap: user.salt_wrap, encPrivKey: user.enc_priv_key, privIv: user.priv_iv });
  } catch {
    res.status(500).json({ error: 'reauth failed' });
  }
}

// Replace the recovery code (lost or possibly seen). Requires the password again so
// a hijacked session alone cannot swap in an attacker's code. The client only calls
// this after the user has confirmed saving the new code, so the old one stays valid
// until the new one is safely written down.
async function rotateRecovery(req, res) {
  try {
    const { authKey, recovery } = req.body || {};
    if (!h.validRecoveryBundle(recovery)) return res.status(400).json({ error: 'invalid payload' });
    const user = getUserById.get(req.user.id);
    if (!(await h.verifyPassword(req.user.id, authKey))) return res.status(401).json({ error: 'invalid credentials' });
    const rec = await h.hashRecoveryBundle(recovery);
    const { changes } = replaceRecovery.run(rec.saltAuth, rec.saltWrap, rec.authHash, rec.authSaltSrv,
      rec.encPrivKey, rec.privIv, user.id, user.auth_hash);
    if (Number(changes) !== 1) return res.status(409).json({ error: 'credentials changed, try again' });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'rotation failed' });
  }
}

function recoveryStatus(req, res) {
  const user = getUserById.get(req.user.id);
  res.json({ hasRecoveryCode: !!(user && user.rec_auth_hash) });
}

module.exports = { recoverySalt, recoverBegin, recoverComplete, reauth, rotateRecovery, recoveryStatus };
