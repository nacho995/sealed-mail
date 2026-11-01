const path = require('node:path');
const net = require('node:net');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const config = require('./config');
const auth = require('./auth');
const mail = require('./mail');
const recovery = require('./recovery');
const passkey = require('./passkey');
const smtpOut = require('./smtp-out');
const { startInboundSmtp } = require('./smtp-in');

const app = express();
app.disable('x-powered-by');
// Only trust X-Forwarded-* in production (where a reverse proxy sets them). Trusting
// them when directly exposed would let a client spoof its IP and defeat rate limits.
app.set('trust proxy', config.isProd ? 1 : false);

// Strict Content-Security-Policy: everything is same-origin and there is NO inline
// script or style anywhere in the frontend, so 'unsafe-inline' is not needed. This
// is the main line of defense against XSS stealing a decrypted message in the DOM.
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use(express.json({ limit: '512kb' }));
app.use(cookieParser());

// ---- rate limiting ----
// Key by client network: IPv4 as-is, IPv6 grouped by /64. One subscriber normally
// gets a whole /64, so per-address keys would let them rotate past every limit.
function ipv6Prefix64(ip) {
  const parts = ip.split('%')[0].split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const tailGroups = tail.reduce((n, g) => n + (g.includes('.') ? 2 : 1), 0); // embedded IPv4 = 2 groups
  const missing = parts.length > 1 ? 8 - head.length - tailGroups : 0;
  return [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail]
    .slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(':') + '::/64';
}
function clientKey(req) {
  const ip = req.ip || '';
  const v4 = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  if (net.isIPv4(v4)) return v4;
  return net.isIPv6(ip) ? ipv6Prefix64(ip) : ip;
}

const WINDOW_MS = 15 * 60 * 1000;
// Each call creates its own counter, so one busy flow cannot lock users out of another.
const limitBy = (max, keyGenerator = clientKey) =>
  rateLimit({ windowMs: WINDOW_MS, max, keyGenerator, standardHeaders: true, legacyHeaders: false });
const limit = {
  salt: limitBy(60),
  register: limitBy(10),
  login: limitBy(30),
  recover: limitBy(15),
  sudo: limitBy(15),
  passkeyLogin: limitBy(30),
  api: limitBy(600),
  // Per-account caps on the guessing surfaces, independent of how many IPs try.
  recoverAccount: limitBy(10, (req) => 'acct:' + String((req.body && req.body.email) || '').toLowerCase()),
  sudoAccount: limitBy(10, (req) => 'user:' + req.user.id), // mounted after requireAuth
  // Mail that leaves the system: capped per account so a hijacked session cannot be
  // turned into a spam cannon that gets the domain blacklisted.
  outbound: limitBy(30, (req) => 'out:' + req.user.id),     // mounted after requireAuth
};

// Public auth endpoints.
app.get('/api/config', limit.api, auth.publicConfig);
app.get('/api/salt', limit.salt, auth.saltLookup);
app.post('/api/register', limit.register, auth.register);
app.post('/api/login', limit.login, auth.login);
app.post('/api/logout', auth.requireAuth, auth.requireCsrf, auth.logout);

// Authenticated endpoints.
app.get('/api/me', auth.requireAuth, auth.me);
app.get('/api/pubkey', limit.api, auth.requireAuth, mail.pubkeyLookup);
app.get('/api/messages', limit.api, auth.requireAuth, mail.list);
app.post('/api/messages', limit.api, auth.requireAuth, auth.requireCsrf, mail.send);
app.post('/api/messages/:id/read', limit.api, auth.requireAuth, auth.requireCsrf, mail.read);
// Ordinary email to an address outside Sealed Mail (see smtp-out.js).
app.post('/api/messages/external', limit.api, auth.requireAuth, limit.outbound, auth.requireCsrf, smtpOut.sendExternal);
app.post('/api/sessions/revoke-others', limit.api, auth.requireAuth, auth.requireCsrf, auth.revokeOtherSessions);

// Account recovery with the recovery code.
app.get('/api/recover/salt', limit.salt, recovery.recoverySalt);
app.post('/api/recover/begin', limit.recover, limit.recoverAccount, recovery.recoverBegin);
app.post('/api/recover/complete', limit.recover, limit.recoverAccount, recovery.recoverComplete);

// Security settings. Anything that changes how the account can be opened
// re-verifies the password ON THE SERVER ("sudo"), not just in the UI.
app.get('/api/recovery/status', limit.api, auth.requireAuth, recovery.recoveryStatus);
app.post('/api/recovery/rotate', limit.sudo, auth.requireAuth, limit.sudoAccount, auth.requireCsrf, recovery.rotateRecovery);
app.post('/api/reauth', limit.sudo, auth.requireAuth, limit.sudoAccount, auth.requireCsrf, recovery.reauth);

// Passkeys (Face ID / Touch ID / security key).
app.post('/api/passkeys/register/options', limit.sudo, auth.requireAuth, limit.sudoAccount, auth.requireCsrf, passkey.registerOptions);
app.post('/api/passkeys/register/verify', limit.api, auth.requireAuth, auth.requireCsrf, passkey.registerVerify);
app.get('/api/passkeys', limit.api, auth.requireAuth, passkey.list);
app.post('/api/passkeys/:id/delete', limit.api, auth.requireAuth, auth.requireCsrf, passkey.remove);
app.post('/api/passkeys/login/options', limit.passkeyLogin, passkey.loginOptions);
app.post('/api/passkeys/login/verify', limit.passkeyLogin, passkey.loginVerify);

// JSON 404 for unknown API routes (before the static handler).
app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

// Static frontend. no-store because the app shell must never be cached with stale state.
app.use(express.static(path.join(__dirname, '..', 'public'), {
  setHeaders: (res) => res.setHeader('Cache-Control', 'no-store'),
}));

// Last resort: anything that escapes a handler, or a malformed/oversized JSON body,
// becomes a short JSON reply instead of Express's HTML page with a stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err && (err.type === 'entity.parse.failed' || err.status === 400) ? 400
    : err && err.status === 413 ? 413 : 500;
  res.status(status).json({ error: status === 500 ? 'internal error' : 'bad request' });
});

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`sealed-mail listening on http://localhost:${config.port} (${config.isProd ? 'production' : 'development'})`);
});

// Real email in: other mail servers (or any mail client) deliver to our addresses here.
startInboundSmtp();
