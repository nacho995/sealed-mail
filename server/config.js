const fs = require('node:fs');
const path = require('node:path');

// Minimal .env loader so we don't pull in a dependency just to read KEY=VALUE lines.
function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  const text = fs.readFileSync(envPath, 'utf8');
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadEnv();

const isProd = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;

// Fail fast: the secret keys the anti-enumeration salt HMAC. A missing, weak or
// publicly known value (e.g. the .env.example placeholder left in place) lets anyone
// recompute the fake salts and tell real accounts from unknown ones, so refuse to
// boot. Require at least 128 bits of hex.
const PLACEHOLDER_SECRET = 'replace_me_with_64_hex_chars';
if (!sessionSecret || sessionSecret === PLACEHOLDER_SECRET || !/^[0-9a-f]{32,}$/i.test(sessionSecret)) {
  throw new Error('SESSION_SECRET missing, placeholder or too weak. Set at least 32 hex chars, e.g. ' +
    'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}

const port = Number(process.env.PORT) || 3000;

// In production the passkey domain must be stated explicitly and served over HTTPS;
// silently falling back to localhost would make every passkey fail (or bind to the
// wrong origin).
if (isProd && (!process.env.RP_ID || !/^https:\/\//.test(process.env.ORIGIN || ''))) {
  throw new Error('In production set RP_ID (e.g. mail.example.com) and an https ORIGIN (e.g. https://mail.example.com).');
}

module.exports = {
  isProd,
  sessionSecret,
  port,
  // WebAuthn relying-party identity. A passkey is bound to this domain, so these
  // MUST match the public hostname/origin in production (e.g. mail.example.com).
  webauthn: {
    rpName: 'Sealed Mail',
    rpID: process.env.RP_ID || 'localhost',
    origin: process.env.ORIGIN || `http://localhost:${port}`,
  },
  sessionTtlMs: 1000 * 60 * 60 * 12, // 12 hours
  limits: {
    ciphertextBytes: 256 * 1024,
    encKeyB64: 2048,
    recipients: 20,
    emailLen: 254,
  },
};
