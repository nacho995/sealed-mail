const path = require('node:path');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22+ (no native build needed)

const db = new DatabaseSync(path.join(__dirname, '..', 'sealed-mail.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// Small helper so call sites read like better-sqlite3: db.transaction(fn)(...args)
// runs fn atomically and returns its result, rolling back on throw.
db.transaction = (fn) => (...args) => {
  db.exec('BEGIN');
  try {
    const result = fn(...args);
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
};

// Schema. Note what the server CAN and CANNOT read:
//   - pub_key is public by nature.
//   - enc_priv_key / ciphertext / enc_key are all ciphertext the server cannot open.
//   - auth_hash is scrypt(authKey); authKey itself is a client-side PBKDF2 output.
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  salt_auth     TEXT NOT NULL,   -- client-side PBKDF2 salt for the auth key
  salt_wrap     TEXT NOT NULL,   -- client-side PBKDF2 salt for the private-key wrapping key
  auth_hash     TEXT NOT NULL,   -- scrypt(authKey): server-side login verifier
  auth_salt_srv TEXT NOT NULL,   -- scrypt salt
  pub_key       TEXT NOT NULL,   -- RSA public key (SPKI, base64): not secret
  enc_priv_key  TEXT NOT NULL,   -- RSA private key, AES-GCM encrypted with the wrapping key
  priv_iv       TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,  -- sha256 of the cookie token; the raw token is never stored
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_email TEXT NOT NULL,
  ciphertext   TEXT NOT NULL,    -- AES-GCM ciphertext of {from,to,subject,body} (base64)
  iv           TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS message_recipients (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  box         TEXT NOT NULL CHECK (box IN ('inbox','sent')),
  enc_key     TEXT NOT NULL,     -- per-message AES key, RSA-OAEP wrapped for THIS user
  read_flag   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mr_user_box ON message_recipients(user_id, box);

-- One row per passkey. enc_priv_key is the account private key wrapped under a key
-- derived from the authenticator's PRF output; the PRF output itself never reaches
-- the server, so this blob is as opaque to us as the password-wrapped one.
CREATE TABLE IF NOT EXISTS passkeys (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,  -- base64url
  public_key    TEXT NOT NULL,         -- COSE public key, base64url
  counter       INTEGER NOT NULL,
  transports    TEXT,                  -- JSON array of known transport names only
  aaguid        TEXT,                  -- authenticator model id, shown to spot rogue devices
  enc_priv_key  TEXT NOT NULL,
  priv_iv       TEXT NOT NULL,
  label         TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);

-- Single-use WebAuthn challenges with a short expiry. Login challenges have no
-- user yet (usernameless sign-in: the passkey itself says whose it is).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL CHECK (purpose IN ('register','login')),
  challenge   TEXT NOT NULL,
  expires_at  INTEGER NOT NULL
);
`);

// A database created by the pre-release passkey schema (per-credential PRF salts,
// user-bound login challenges) cannot be migrated in place by SQLite. That schema
// never held real users, so stop with a clear instruction instead of failing later.
const passkeyCols = new Set(db.prepare('PRAGMA table_info(passkeys)').all().map((c) => c.name));
if (passkeyCols.has('prf_salt')) {
  throw new Error('sealed-mail.db uses the pre-release passkey schema. Delete sealed-mail.db* and restart.');
}

// Columns added after the first release, by migration so older databases keep working.
function addMissingColumns(table, columns) {
  const have = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
  for (const [name, type] of columns) {
    if (!have.has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
}
addMissingColumns('users', [
  // recovery code (users created earlier can generate one from the Security panel)
  ['rec_salt_auth', 'TEXT'], ['rec_salt_wrap', 'TEXT'], ['rec_auth_hash', 'TEXT'],
  ['rec_auth_salt_srv', 'TEXT'], ['rec_enc_priv_key', 'TEXT'], ['rec_priv_iv', 'TEXT'],
  // random WebAuthn user handle; never the sequential row id
  ['webauthn_user_id', 'TEXT'],
]);
// which passkey opened a session (NULL for password / recovery sessions)
addMissingColumns('sessions', [['passkey_id', 'INTEGER']]);

module.exports = db;
