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

// How many reverse-proxy hops sit in front of the app in production, so Express trusts
// exactly that many X-Forwarded-For entries. Getting this wrong lets a client spoof its
// IP and defeat the per-IP rate limits (too high) or breaks limiting (too low). Set
// TRUST_PROXY_HOPS to the real hop count of your deployment; default 1.
const trustProxyHops = Math.max(Number(process.env.TRUST_PROXY_HOPS) || 1, 1);

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
  trustProxyHops,
  // WebAuthn relying-party identity. A passkey is bound to this domain, so these
  // MUST match the public hostname/origin in production (e.g. mail.example.com).
  webauthn: {
    rpName: 'Sealed Mail',
    rpID: process.env.RP_ID || 'localhost',
    origin: process.env.ORIGIN || `http://localhost:${port}`,
  },
  sessionTtlMs: 1000 * 60 * 60 * 12, // 12 hours
  // Real email (SMTP). Accounts are addresses on mailDomain. Defaults are for local
  // use: inbound mail is accepted on 127.0.0.1:2525 and outbound mail goes to a local
  // catcher (Mailpit on :1025). With a real domain, point MAIL_DOMAIN at it and the
  // outbound settings at a relay such as SendGrid (smtp.sendgrid.net:587, user
  // "apikey", password = the API key).
  mail: {
    domain: (process.env.MAIL_DOMAIN || 'sealed.local').toLowerCase(),
    inbound: {
      host: process.env.SMTP_IN_HOST || '127.0.0.1',
      port: Number(process.env.SMTP_IN_PORT) || 2525,
      maxBytes: 15 * 1024 * 1024, // room for 10 MB of attachments once MIME-encoded
    },
    outbound: {
      host: process.env.SMTP_OUT_HOST || '127.0.0.1',
      port: Number(process.env.SMTP_OUT_PORT) || 1025,
      secure: process.env.SMTP_OUT_SECURE === 'true', // implicit TLS (port 465)
      user: process.env.SMTP_OUT_USER || '',
      pass: process.env.SMTP_OUT_PASS || '',
      // Without a domain of your own, relays like SendGrid only send FROM an address
      // you verified with them (e.g. your Gmail). Set it here: outside mail then goes
      // out from that address, showing the Sealed Mail sender's name, and replies come
      // back to it. Leave empty when MAIL_DOMAIN is a real, authenticated domain.
      from: (process.env.SMTP_OUT_FROM || '').trim().toLowerCase(),
    },
    // Receiving through Resend (MX of MAIL_DOMAIN pointing at Resend). The app polls
    // Resend's API instead of exposing a webhook, so it can run without a public URL.
    // Reading received mail needs a FULL-ACCESS key: see docs/SECURITY.md.
    resend: {
      receiveKey: process.env.RESEND_RECEIVE_KEY || '',
      apiBase: (process.env.RESEND_API_BASE || 'https://api.resend.com').replace(/\/+$/, ''),
      pollMs: Math.max(Number(process.env.RESEND_POLL_MS) || 15_000, 250),
      // Optional: pin the raw-download host(s). Empty means "any public https host"
      // (private/loopback/link-local addresses are refused either way). Set it to
      // Resend's download host(s), comma-separated, to lock it down tighter.
      rawHosts: (process.env.RESEND_RAW_DOWNLOAD_HOSTS || '')
        .split(',').map((x) => x.trim().toLowerCase()).filter(Boolean),
    },
  },
  limits: {
    ciphertextBytes: 256 * 1024,
    encKeyB64: 2048,
    recipients: 20,
    emailLen: 254,
    // Stored attachment bytes per account, counted separately for what it sends and
    // for what it receives from outside. Overridable so the tests can reach it.
    attachmentQuotaBytes: Number(process.env.ATTACHMENT_QUOTA_BYTES) || 250 * 1024 * 1024,
  },
};
