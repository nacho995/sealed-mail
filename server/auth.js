const crypto = require('node:crypto');
const { promisify } = require('node:util');
const db = require('./db');
const config = require('./config');

const scryptAsync = promisify(crypto.scrypt);

// scrypt parameters for the server-side login verifier. The input (authKey) is
// already a 256-bit PBKDF2 output from the client, so this is a second, memory-hard
// barrier against an attacker who steals the database. Run ASYNC so the memory-hard
// work lands on the libuv threadpool instead of blocking the single event loop.
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

// Each scrypt job holds ~16 MiB and a threadpool thread. Unauthenticated endpoints
// trigger it, so cap concurrency (matches libuv's default 4 threads) and bound the
// queue: past that, requests fail fast instead of piling up memory.
const MAX_SCRYPT_JOBS = 4;
const MAX_SCRYPT_QUEUE = 64;
let scryptRunning = 0;
const scryptWaiting = [];
async function withScryptSlot(fn) {
  if (scryptRunning < MAX_SCRYPT_JOBS) {
    scryptRunning++;
  } else {
    if (scryptWaiting.length >= MAX_SCRYPT_QUEUE) throw new Error('scrypt queue full');
    // The releasing job hands its slot straight to us, so the count stays exact.
    await new Promise((resolve) => scryptWaiting.push(resolve));
  }
  try {
    return await fn();
  } finally {
    const next = scryptWaiting.shift();
    if (next) next(); else scryptRunning--;
  }
}

async function scryptHash(authKeyHex, saltHex) {
  const derived = await withScryptSlot(() => scryptAsync(
    Buffer.from(authKeyHex, 'hex'),
    Buffer.from(saltHex, 'hex'),
    SCRYPT.keylen,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem },
  ));
  return derived.toString('hex');
}

// Constant-ish work regardless of outcome: used on the register-duplicate and
// unknown-user paths so timing does not reveal whether an account exists.
function burnScrypt(authKeyHex) {
  return scryptHash(authKeyHex, crypto.randomBytes(16).toString('hex')).catch(() => {});
}

async function verifyAuthHash(authKeyHex, saltHex, expectedHex) {
  const actual = Buffer.from(await scryptHash(authKeyHex, saltHex), 'hex');
  const expected = Buffer.from(expectedHex, 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

// Deterministic fake salt for unknown emails: the /api/salt response looks the same
// whether or not the account exists, so it cannot be used to enumerate users.
// `label` separates the fake-salt namespaces (password login vs recovery code).
function fakeSalt(label, email) {
  return crypto.createHmac('sha256', config.sessionSecret)
    .update(label + ':' + email.toLowerCase())
    .digest('hex')
    .slice(0, 32);
}

const insertUser = db.prepare(`INSERT INTO users
  (email, salt_auth, salt_wrap, auth_hash, auth_salt_srv, pub_key, enc_priv_key, priv_iv,
   rec_salt_auth, rec_salt_wrap, rec_auth_hash, rec_auth_salt_srv, rec_enc_priv_key, rec_priv_iv,
   created_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
const getUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
// Session middleware only ever needs these three columns. Selecting the secrets
// (auth_hash, enc_priv_key, priv_iv) into req.user on every request would be a leak
// footgun, so keep them out of the hot path.
const getUserByIdSafe = db.prepare('SELECT id, email, pub_key FROM users WHERE id = ?');
const getUserAuth = db.prepare('SELECT auth_hash, auth_salt_srv FROM users WHERE id = ?');
const insertSession = db.prepare('INSERT INTO sessions (token_hash,user_id,passkey_id,created_at,expires_at) VALUES (?,?,?,?,?)');
const getSession = db.prepare('SELECT * FROM sessions WHERE token_hash = ?');
const deleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
const deleteOtherSessions = db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?');
const deleteExpired = db.prepare('DELETE FROM sessions WHERE expires_at < ?');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Set Secure whenever the edge is HTTPS, not only when NODE_ENV=production. A
// client-spoofed x-forwarded-proto can only ADD the flag (making the cookie more
// restrictive), never strip it, so trusting the raw header here is safe.
function isHttps(req) {
  if (config.isProd || req.secure) return true;
  const xfp = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return xfp === 'https';
}

function setSessionCookies(res, token, csrf, secure) {
  const maxAge = Math.floor(config.sessionTtlMs / 1000);
  const s = secure ? '; Secure' : '';
  // sid is HttpOnly (JS cannot read it). csrf is readable by JS so the client can
  // echo it back in a header: the classic double-submit defense.
  res.append('Set-Cookie', `sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${s}`);
  res.append('Set-Cookie', `csrf=${csrf}; Path=/; SameSite=Strict; Max-Age=${maxAge}${s}`);
}
function clearSessionCookies(res) {
  res.append('Set-Cookie', 'sid=; Path=/; HttpOnly; Max-Age=0');
  res.append('Set-Cookie', 'csrf=; Path=/; Max-Age=0');
}

// passkeyId records which passkey opened the session, so removing that passkey can
// also end the sessions it created.
function createSession(req, res, userId, passkeyId = null) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  insertSession.run(hashToken(token), userId, passkeyId, now, now + config.sessionTtlMs);
  setSessionCookies(res, token, csrf, isHttps(req));
}

// Server-side password check for "sudo" operations. Never trust a UI prompt alone:
// anything that changes how the account can be opened must re-prove the password here.
async function verifyPassword(userId, authKeyHex) {
  if (!validHex(authKeyHex, 512)) return false;
  const row = getUserAuth.get(userId);
  if (!row) { await burnScrypt(authKeyHex); return false; }
  return verifyAuthHash(authKeyHex, row.auth_salt_srv, row.auth_hash);
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.sid;
  if (!token) return res.status(401).json({ error: 'not authenticated' });
  const row = getSession.get(hashToken(token));
  if (!row || row.expires_at < Date.now()) {
    if (row) deleteSession.run(hashToken(token));
    clearSessionCookies(res);
    return res.status(401).json({ error: 'not authenticated' });
  }
  req.user = getUserByIdSafe.get(row.user_id);
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  req.sessionTokenHash = row.token_hash;
  next();
}

// Double-submit CSRF check for state-changing requests. Combined with the
// SameSite=Strict cookie this is belt-and-braces against cross-site forgery.
function requireCsrf(req, res, next) {
  const header = req.get('x-csrf-token');
  const cookie = req.cookies && req.cookies.csrf;
  if (!header || !cookie || header.length !== cookie.length ||
      !crypto.timingSafeEqual(Buffer.from(header), Buffer.from(cookie))) {
    return res.status(403).json({ error: 'bad csrf token' });
  }
  next();
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX_RE = /^[0-9a-f]+$/i;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function validEmail(e) { return typeof e === 'string' && e.length <= config.limits.emailLen && EMAIL_RE.test(e); }
function validHex(s, max) { return typeof s === 'string' && s.length > 0 && s.length <= max && HEX_RE.test(s); }
function validB64(s, max) { return typeof s === 'string' && s.length > 0 && s.length <= max && B64_RE.test(s); }

// A recovery bundle is the recovery-code twin of the password material: salts, the
// client-derived recovery authKey, and the private key wrapped under the code.
function validRecoveryBundle(r) {
  return !!r && validHex(r.saltAuth, 64) && validHex(r.saltWrap, 64) && validHex(r.authKey, 512) &&
    validB64(r.encPrivKey, 8192) && validB64(r.privIv, 64);
}

// Turns a client bundle into the columns we store (authKey -> scrypt verifier).
async function hashRecoveryBundle(r) {
  const authSaltSrv = crypto.randomBytes(16).toString('hex');
  return {
    saltAuth: r.saltAuth, saltWrap: r.saltWrap,
    authHash: await scryptHash(r.authKey, authSaltSrv), authSaltSrv,
    encPrivKey: r.encPrivKey, privIv: r.privIv,
  };
}

async function register(req, res) {
  try {
    const { email, saltAuth, saltWrap, authKey, pubKey, encPrivKey, privIv, recovery } = req.body || {};
    if (!validEmail(email) || !validHex(saltAuth, 64) || !validHex(saltWrap, 64) ||
        !validHex(authKey, 512) || !validB64(pubKey, 2048) ||
        !validB64(encPrivKey, 8192) || !validB64(privIv, 64) || !validRecoveryBundle(recovery)) {
      return res.status(400).json({ error: 'invalid registration payload' });
    }
    const normEmail = email.toLowerCase();
    if (getUserByEmail.get(normEmail)) {
      // A new account runs scrypt twice (password + recovery verifier); burn the same
      // amount so timing matches. The 409 itself still says "taken", which sign-up
      // forms inherently reveal; this only removes the extra timing signal.
      await burnScrypt(authKey);
      await burnScrypt(recovery.authKey);
      return res.status(409).json({ error: 'cannot register with these details' });
    }
    const authSaltSrv = crypto.randomBytes(16).toString('hex');
    const authHash = await scryptHash(authKey, authSaltSrv);
    const rec = await hashRecoveryBundle(recovery);
    insertUser.run(normEmail, saltAuth, saltWrap, authHash, authSaltSrv, pubKey, encPrivKey, privIv,
      rec.saltAuth, rec.saltWrap, rec.authHash, rec.authSaltSrv, rec.encPrivKey, rec.privIv, Date.now());
    const user = getUserByEmail.get(normEmail);
    createSession(req, res, user.id);
    res.json({ ok: true, email: normEmail });
  } catch {
    res.status(500).json({ error: 'registration failed' });
  }
}

function saltLookup(req, res) {
  const email = (req.query.email || '').toString().toLowerCase();
  if (!validEmail(email)) return res.status(400).json({ error: 'invalid email' });
  const user = getUserByEmail.get(email);
  // Always return a salt (real or deterministic fake) to prevent account enumeration.
  res.json({ saltAuth: user ? user.salt_auth : fakeSalt('salt-auth', email) });
}

async function login(req, res) {
  try {
    const { email, authKey } = req.body || {};
    if (!validEmail(email) || !validHex(authKey, 512)) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const user = getUserByEmail.get(email.toLowerCase());
    if (!user) {
      // Burn comparable time to a real verify so timing does not reveal existence.
      await burnScrypt(authKey);
      return res.status(401).json({ error: 'invalid credentials' });
    }
    if (!(await verifyAuthHash(authKey, user.auth_salt_srv, user.auth_hash))) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    createSession(req, res, user.id);
    // The encrypted private key is handed back ONLY after a successful login.
    res.json({
      ok: true,
      email: user.email,
      saltWrap: user.salt_wrap,
      encPrivKey: user.enc_priv_key,
      privIv: user.priv_iv,
    });
  } catch {
    res.status(500).json({ error: 'login failed' });
  }
}

function logout(req, res) {
  const token = req.cookies && req.cookies.sid;
  if (token) deleteSession.run(hashToken(token));
  clearSessionCookies(res);
  res.json({ ok: true });
}

function me(req, res) {
  res.json({ email: req.user.email, pubKey: req.user.pub_key });
}

// "Sign out everywhere else": keeps only the session making this request.
function revokeOtherSessions(req, res) {
  const { changes } = deleteOtherSessions.run(req.user.id, req.sessionTokenHash);
  res.json({ ok: true, revoked: Number(changes) });
}

// Periodic cleanup of expired sessions; unref so it never holds the process open.
setInterval(() => { try { deleteExpired.run(Date.now()); } catch { /* ignore */ } }, 60 * 60 * 1000).unref();

module.exports = {
  register, login, logout, me, saltLookup, revokeOtherSessions,
  requireAuth, requireCsrf,
  // shared with recovery.js / passkey.js
  helpers: {
    scryptHash, verifyAuthHash, verifyPassword, burnScrypt, fakeSalt, createSession,
    validEmail, validHex, validB64, validRecoveryBundle, hashRecoveryBundle,
  },
};
