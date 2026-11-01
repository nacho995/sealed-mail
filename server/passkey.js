const crypto = require('node:crypto');
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const db = require('./db');
const config = require('./config');
const { helpers: h } = require('./auth');

// Passkeys do two jobs here:
//   1. Authenticate the user (standard WebAuthn signature check, done by
//      @simplewebauthn/server — never hand-rolled).
//   2. Unlock the private key via the PRF extension: the authenticator returns a
//      secret only after user verification (Face ID / Touch ID / PIN). The browser
//      turns it into an AES key and unwraps the private key. That secret NEVER
//      reaches the server; we only store the blob it encrypts.
//
// Sign-in is usernameless (discoverable credentials): the browser offers the
// passkeys it holds for this site and the chosen one tells us whose account it is.
// The server never answers "does this email have passkeys?", so there is nothing to
// enumerate. The PRF input is a fixed, public constant (see webauthn.js): PRF output
// is already unique per credential, so a per-credential salt added nothing.

const { rpName, rpID, origin } = config.webauthn;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const isB64url = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && B64URL_RE.test(s);
const KNOWN_TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card', 'cable']);

// A few well-known authenticator models, so a user can tell their own devices from
// one they did not add. Unknown models are shown as such.
const AAGUID_NAMES = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Llavero de iCloud',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Gestor de contraseñas de Google',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome en Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
};
const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

const getUserById = db.prepare('SELECT id, email, webauthn_user_id FROM users WHERE id = ?');
const setWebauthnUserId = db.prepare('UPDATE users SET webauthn_user_id = ? WHERE id = ? AND webauthn_user_id IS NULL');
const listUserPasskeys = db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at');
const getPasskeyByCredential = db.prepare('SELECT * FROM passkeys WHERE credential_id = ?');
const insertPasskey = db.prepare(`INSERT INTO passkeys
  (user_id, credential_id, public_key, counter, transports, aaguid, enc_priv_key, priv_iv, label, created_at)
  VALUES (?,?,?,?,?,?,?,?,?,?)`);
const advanceCounter = db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ? AND counter < ?');
const touchPasskey = db.prepare('UPDATE passkeys SET last_used_at = ? WHERE id = ?');
const deletePasskey = db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?');
const deletePasskeySessions = db.prepare('DELETE FROM sessions WHERE passkey_id = ? AND user_id = ?');
const insertChallenge = db.prepare('INSERT INTO webauthn_challenges (id,user_id,purpose,challenge,expires_at) VALUES (?,?,?,?,?)');
const getChallenge = db.prepare('SELECT * FROM webauthn_challenges WHERE id = ?');
const deleteChallenge = db.prepare('DELETE FROM webauthn_challenges WHERE id = ?');
const deleteExpiredChallenges = db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < ?');

function storeChallenge(userId, purpose, challenge) {
  const id = crypto.randomBytes(18).toString('base64url');
  insertChallenge.run(id, userId, purpose, challenge, Date.now() + CHALLENGE_TTL_MS);
  return id;
}

// Single use: the row is deleted on first read whether or not verification succeeds.
// node:sqlite is synchronous and nothing awaits between get and delete, so two
// requests cannot both consume the same challenge.
function consumeChallenge(id, purpose, userId) {
  if (typeof id !== 'string' || id.length > 64) return null;
  const row = getChallenge.get(id);
  if (!row) return null;
  deleteChallenge.run(id);
  if (row.purpose !== purpose || row.user_id !== userId || row.expires_at < Date.now()) return null;
  return row.challenge;
}

// Tripwire: PRF results are a decryption secret. If a client ever puts anything PRF
// related in the response we refuse the request instead of storing or logging it.
function mentionsPrf(response) {
  const ext = response && response.clientExtensionResults;
  return !!(ext && typeof ext === 'object' && Object.prototype.hasOwnProperty.call(ext, 'prf'));
}

function cleanTransports(t) {
  if (!Array.isArray(t)) return null;
  const ok = [...new Set(t.filter((x) => typeof x === 'string' && KNOWN_TRANSPORTS.has(x)))].slice(0, 6);
  return ok.length ? ok : null;
}

// Strip control / formatting characters (incl. bidi overrides) so a label cannot
// visually impersonate another device name.
function cleanLabel(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/\p{C}/gu, '').replace(/\s+/g, ' ').trim().slice(0, 60);
}

function deviceKind(aaguid) {
  if (!aaguid || aaguid === ZERO_AAGUID) return 'Modelo no informado';
  return AAGUID_NAMES[aaguid] || `Autenticador ${aaguid.slice(0, 8)}`;
}

function webauthnUserId(user) {
  if (user.webauthn_user_id) return user.webauthn_user_id;
  setWebauthnUserId.run(crypto.randomBytes(32).toString('base64url'), user.id);
  return getUserById.get(user.id).webauthn_user_id;
}

function toPublicCredential(row) {
  return {
    id: row.credential_id,
    publicKey: new Uint8Array(Buffer.from(row.public_key, 'base64url')),
    counter: row.counter,
    transports: row.transports ? JSON.parse(row.transports) : undefined,
  };
}

// ---- enrollment (logged-in user, password re-checked on the server) ----

async function registerOptions(req, res) {
  try {
    const { authKey } = req.body || {};
    if (!(await h.verifyPassword(req.user.id, authKey))) return res.status(401).json({ error: 'invalid credentials' });
    const user = getUserById.get(req.user.id);
    const existing = listUserPasskeys.all(user.id);
    const options = await generateRegistrationOptions({
      rpName, rpID,
      userName: user.email,
      userID: new Uint8Array(Buffer.from(webauthnUserId(user), 'base64url')),
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({ id: p.credential_id, transports: p.transports ? JSON.parse(p.transports) : undefined })),
      // Discoverable credential required: sign-in does not ask for the email.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    // The single-use, 5-minute challenge is the proof that the password was just checked.
    const challengeId = storeChallenge(user.id, 'register', options.challenge);
    res.json({ challengeId, options });
  } catch {
    res.status(500).json({ error: 'could not start passkey enrollment' });
  }
}

async function registerVerify(req, res) {
  try {
    const { challengeId, response, encPrivKey, privIv } = req.body || {};
    const label = cleanLabel(req.body && req.body.label);
    if (!response || typeof response !== 'object' || !h.validB64(encPrivKey, 8192) ||
        !h.validB64(privIv, 64) || !label) {
      return res.status(400).json({ error: 'invalid passkey payload' });
    }
    if (mentionsPrf(response)) return res.status(400).json({ error: 'client sent PRF data; refusing' });
    const expectedChallenge = consumeChallenge(challengeId, 'register', req.user.id);
    if (!expectedChallenge) return res.status(400).json({ error: 'challenge expired or invalid' });

    const result = await verifyRegistrationResponse({
      response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
    });
    if (!result.verified) return res.status(400).json({ error: 'passkey verification failed' });

    const info = result.registrationInfo;
    const transports = cleanTransports(info.credential.transports);
    insertPasskey.run(req.user.id, info.credential.id, Buffer.from(info.credential.publicKey).toString('base64url'),
      info.credential.counter, transports ? JSON.stringify(transports) : null, info.aaguid || null,
      encPrivKey, privIv, label, Date.now());
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'passkey verification failed' });
  }
}

function list(req, res) {
  const rows = listUserPasskeys.all(req.user.id);
  res.json({
    passkeys: rows.map((r) => ({
      id: r.id, label: r.label, kind: deviceKind(r.aaguid), createdAt: r.created_at, lastUsedAt: r.last_used_at,
    })),
  });
}

// Removing a passkey also ends every session that passkey opened.
function remove(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'bad id' });
  db.transaction(() => {
    deletePasskeySessions.run(id, req.user.id);
    deletePasskey.run(id, req.user.id);
  })();
  res.json({ ok: true });
}

// ---- usernameless sign-in ----

async function loginOptions(req, res) {
  try {
    const options = await generateAuthenticationOptions({ rpID, allowCredentials: [], userVerification: 'required' });
    const challengeId = storeChallenge(null, 'login', options.challenge);
    res.json({ challengeId, options });
  } catch {
    res.status(500).json({ error: 'could not start passkey login' });
  }
}

async function loginVerify(req, res) {
  const fail = () => res.status(401).json({ error: 'passkey login failed' });
  try {
    const { challengeId, response } = req.body || {};
    if (!response || typeof response !== 'object' || !isB64url(response.id, 1024)) return fail();
    if (mentionsPrf(response)) return res.status(400).json({ error: 'client sent PRF data; refusing' });
    const expectedChallenge = consumeChallenge(challengeId, 'login', null);
    if (!expectedChallenge) return fail();

    const row = getPasskeyByCredential.get(response.id);
    if (!row) return fail();
    const user = getUserById.get(row.user_id);
    // The authenticator's user handle must name the account that owns the credential.
    const handle = response.response && response.response.userHandle;
    if (!user || !user.webauthn_user_id || handle !== user.webauthn_user_id) return fail();

    const result = await verifyAuthenticationResponse({
      response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID,
      credential: toPublicCredential(row), requireUserVerification: true,
    });
    if (!result.verified) return fail();

    const now = Date.now();
    const newCounter = result.authenticationInfo.newCounter;
    if (newCounter > 0) {
      // Compare-and-swap: two parallel assertions from a cloned authenticator cannot both win.
      if (Number(advanceCounter.run(newCounter, now, row.id, newCounter).changes) !== 1) return fail();
    } else {
      touchPasskey.run(now, row.id); // synced passkeys report 0 forever
    }
    h.createSession(req, res, user.id, row.id);
    res.json({ ok: true, email: user.email, encPrivKey: row.enc_priv_key, privIv: row.priv_iv });
  } catch {
    return fail();
  }
}

setInterval(() => { try { deleteExpiredChallenges.run(Date.now()); } catch { /* ignore */ } }, 10 * 60 * 1000).unref();

module.exports = { registerOptions, registerVerify, list, remove, loginOptions, loginVerify };
