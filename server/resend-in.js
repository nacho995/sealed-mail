const db = require('./db');
const config = require('./config');
const { deliverRaw, cleanAddress } = require('./smtp-in');

// Inbound mail through Resend. The MX of MAIL_DOMAIN points at Resend; this module
// polls Resend's Receiving API, downloads each new message in its original form and
// hands it to the same sealing path as the built-in SMTP server: sealed in memory with
// the recipients' keys, only ciphertext stored. Polling means the app needs no public
// URL. Resend itself keeps its copy (there is no delete API): see docs/SECURITY.md.

const { domain, inbound } = config.mail;
const { receiveKey, apiBase, pollMs } = config.mail.resend;

const isSeen = db.prepare('SELECT 1 FROM inbound_seen WHERE provider_id = ?');
const markSeen = db.prepare('INSERT OR IGNORE INTO inbound_seen (provider_id, seen_at) VALUES (?, ?)');

const MAX_PAGES = 4;          // up to 200 messages per poll
const MAX_ATTEMPTS = 5;       // then the message is skipped (and logged) instead of retried forever
const failures = new Map();   // provider id -> failed attempts

const isLocalHttp = (u) => /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//.test(u); // test doubles only

async function api(path) {
  const res = await fetch(`${apiBase}${path}`, {
    headers: { Authorization: `Bearer ${receiveKey}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Resend API ${res.status}`);
  return res.json();
}

// The original message (RFC 822). The URL is a short-lived signed link from Resend.
async function download(url) {
  if (typeof url !== 'string' || !(url.startsWith('https://') || isLocalHttp(url))) {
    throw new Error('missing or insecure raw download URL');
  }
  const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`raw download ${res.status}`);
  const declared = Number(res.headers.get('content-length') || 0);
  if (declared > inbound.maxBytes) throw Object.assign(new Error('message too large'), { permanent: true });
  const raw = Buffer.from(await res.arrayBuffer());
  if (raw.length > inbound.maxBytes) throw Object.assign(new Error('message too large'), { permanent: true });
  return raw;
}

// Every address field Resend reports, reduced to local mailboxes on MAIL_DOMAIN.
function localRecipients(email) {
  const fields = [email.to, email.cc, email.bcc, email.received_for].flat().filter(Boolean);
  const found = fields.join(' ').match(/[^\s<>"',;]+@[^\s<>"',;]+/g) || [];
  return [...new Set(found.map(cleanAddress))].filter((a) => a && a.endsWith(`@${domain}`));
}

async function processOne(id) {
  const email = await api(`/emails/receiving/${encodeURIComponent(id)}`);
  const recipients = localRecipients(email);
  if (!recipients.length) return; // nobody here to deliver to
  const raw = await download(email.raw && email.raw.download_url);
  try {
    await deliverRaw(raw, { recipients, envelopeFrom: email.from, authentication: email.authentication });
  } finally {
    raw.fill(0); // best effort: do not leave the plaintext in this buffer
  }
}

async function pollOnce() {
  let after;
  for (let page = 0; page < MAX_PAGES; page++) {
    const list = await api(`/emails/receiving?limit=50${after ? `&after=${encodeURIComponent(after)}` : ''}`);
    const items = Array.isArray(list.data) ? list.data : [];
    for (const item of items) {
      if (!item || typeof item.id !== 'string' || isSeen.get(item.id)) continue;
      try {
        await processOne(item.id);
        markSeen.run(item.id, Date.now());
        failures.delete(item.id);
      } catch (err) {
        const n = (failures.get(item.id) || 0) + 1;
        failures.set(item.id, n);
        if (err.permanent || n >= MAX_ATTEMPTS) {
          markSeen.run(item.id, Date.now());
          failures.delete(item.id);
          // eslint-disable-next-line no-console
          console.error(`inbound message skipped after ${n} attempt(s): ${err.message}`);
        }
      }
    }
    if (!list.has_more || !items.length) break;
    after = items[items.length - 1].id;
  }
}

function startResendInbound() {
  if (!receiveKey) return null;
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      await pollOnce();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`Resend inbound poll failed: ${err.message}`);
    } finally {
      running = false;
    }
  };
  // eslint-disable-next-line no-console
  console.log(`receiving mail for @${domain} from Resend every ${Math.round(pollMs / 1000)} s`);
  tick();
  return setInterval(tick, pollMs).unref();
}

module.exports = { startResendInbound };
