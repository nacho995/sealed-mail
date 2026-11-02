// End-to-end test of Sealed Mail. Starts the real server on a free port with a
// throwaway database and secret, then drives it with the REAL browser crypto module
// (public/js/crypto.js) through Node's Web Crypto API.
//
//   npm test
import assert from 'node:assert';
import { webcrypto, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import nodemailer from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import http from 'node:http';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

globalThis.window = { crypto: webcrypto };
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// The client module is written as an ES module but the package is CommonJS, so the
// exact file is loaded through a data: URL instead of keeping a copy in sync.
const src = fs.readFileSync(path.join(root, 'public/js/crypto.js'), 'utf8');
const seal = (await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'))).crypto;

// ---- a private server for this run ----
const freePort = () => new Promise((resolve) => {
  const probe = net.createServer().listen(0, '127.0.0.1', () => {
    const { port: p } = probe.address();
    probe.close(() => resolve(p));
  });
});
const port = await freePort();
const smtpInPort = await freePort();

// "The outside world": an SMTP server standing in for Gmail's, catching whatever the
// app sends to external addresses.
const outsideMail = [];
const outside = new SMTPServer({
  authOptional: true,
  disabledCommands: ['AUTH', 'STARTTLS'],
  logger: false,
  onData(stream, session, cb) {
    simpleParser(stream).then((mail) => { outsideMail.push(mail); cb(); }, cb);
  },
});
const outsidePort = await freePort();
await new Promise((resolve) => outside.listen(outsidePort, '127.0.0.1', resolve));

// A stand-in for Resend's Receiving API: list, detail, and the raw message download.
// Push { id, to, from, subject, text, auth } into fakeResendInbox to "receive" mail.
const RESEND_TEST_KEY = 'test-resend-key';
const fakeResendInbox = [];
const fakeResendAuth = { ok: 0, rejected: 0 };
const resendPort = await freePort();
const resendBase = `http://127.0.0.1:${resendPort}`;
const fakeResend = http.createServer(async (req, res) => {
  const url = new URL(req.url, resendBase);
  const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (url.pathname.startsWith('/raw/')) {
    const m = fakeResendInbox.find((x) => x.id === url.pathname.slice(5));
    if (!m) return send(404, {});
    const raw = await new MailComposer({ from: m.from, to: m.to, subject: m.subject, text: m.text }).compile().build();
    res.writeHead(200, { 'Content-Type': 'message/rfc822' });
    return res.end(raw);
  }
  if (req.headers.authorization !== `Bearer ${RESEND_TEST_KEY}`) { fakeResendAuth.rejected++; return send(401, { name: 'invalid_api_key' }); }
  fakeResendAuth.ok++;
  if (url.pathname === '/emails/receiving') {
    return send(200, { object: 'list', has_more: false, data: fakeResendInbox.map((m) => ({ id: m.id, to: [m.to], from: m.from, subject: m.subject })) });
  }
  const m = fakeResendInbox.find((x) => `/emails/receiving/${x.id}` === url.pathname);
  if (!m) return send(404, {});
  return send(200, {
    id: m.id, to: [m.to], from: m.from, subject: m.subject, text: m.text, html: null,
    authentication: m.auth, raw: { download_url: `${resendBase}/raw/${m.id}` },
  });
});
await new Promise((resolve) => fakeResend.listen(resendPort, '127.0.0.1', resolve));

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sealed-mail-test-'));
const server = spawn(process.execPath, [path.join(root, 'server/index.js')], {
  env: {
    ...process.env,
    // Every setting the server reads is pinned here, so a developer's .env cannot leak
    // into the run (the .env loader only fills keys that are missing).
    PORT: String(port),
    DB_PATH: path.join(tmp, 'test.db'),
    SESSION_SECRET: randomBytes(32).toString('hex'),
    NODE_ENV: 'development',
    RP_ID: 'localhost',
    ORIGIN: `http://localhost:${port}`,
    MAIL_DOMAIN: 'sealed.local',
    SMTP_IN_HOST: '127.0.0.1',
    SMTP_IN_PORT: String(smtpInPort),
    SMTP_OUT_HOST: '127.0.0.1',
    SMTP_OUT_PORT: String(outsidePort),
    SMTP_OUT_SECURE: 'false',
    SMTP_OUT_USER: '',
    SMTP_OUT_PASS: '',
    SMTP_OUT_FROM: '',
    RESEND_RECEIVE_KEY: RESEND_TEST_KEY,
    RESEND_API_BASE: resendBase,
    RESEND_POLL_MS: '300',
    ATTACHMENT_QUOTA_BYTES: String(30 * 1024 * 1024), // small enough for the quota tests
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
// Runs on success and on a failed assertion alike.
process.on('exit', () => { server.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });
let serverErr = '';
server.stderr.on('data', (d) => { serverErr += d; });
await new Promise((resolve, reject) => {
  // ready once both the web app and the inbound mail server are listening
  let out = '';
  server.stdout.on('data', (d) => { out += d; if (out.includes('listening') && out.includes('receiving mail')) resolve(); });
  server.on('exit', (code) => reject(new Error(`server exited early (${code}): ${serverErr}`)));
  setTimeout(() => reject(new Error('server did not start within 10 s')), 10000);
});
const BASE = `http://localhost:${port}`;

function makeClient() {
  const jar = {};
  const cookieHeader = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  function store(res) {
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(';')[0];
      const i = pair.indexOf('=');
      const k = pair.slice(0, i).trim();
      const v = pair.slice(i + 1).trim();
      if (v === '') delete jar[k]; else jar[k] = v;
    }
  }
  async function req(method, path, body, { csrf = true } = {}) {
    const headers = {};
    const opts = { method, headers };
    const c = cookieHeader();
    if (c) headers.Cookie = c;
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    if (method !== 'GET' && csrf) headers['x-csrf-token'] = jar.csrf || '';
    const res = await fetch(BASE + path, opts);
    store(res);
    let data = null; try { data = await res.json(); } catch { /* none */ }
    return { status: res.status, data };
  }
  return { req, jar };
}

let passed = 0;
function ok(msg) { passed++; console.log('[OK] ' + msg); }

async function registerRaw(client, email, password) {
  const id = await seal.generateIdentity();
  const pubKey = await seal.exportPublicKey(id.publicKey);
  const pkcs8 = await seal.exportPkcs8(id.privateKey);
  const pw = await seal.secretBundle(password, pkcs8);
  const code = seal.generateRecoveryCode();
  const recovery = await seal.secretBundle(seal.normalizeRecoveryCode(code), pkcs8);
  const r = await client.req('POST', '/api/register', {
    email, pubKey, saltAuth: pw.saltAuth, saltWrap: pw.saltWrap, authKey: pw.authKey,
    encPrivKey: pw.encPrivKey, privIv: pw.privIv, recovery,
  });
  return { r, pkcs8, pubKey, code };
}
async function register(client, email, password) {
  const { r, pkcs8, pubKey, code } = await registerRaw(client, email, password);
  assert.equal(r.status, 200, 'register -> ' + JSON.stringify(r.data));
  return { privKey: await seal.importPrivateKey(pkcs8), pubKeyB64: pubKey, email: email.toLowerCase(), code };
}

async function loginRaw(client, email, password) {
  const s = await client.req('GET', `/api/salt?email=${encodeURIComponent(email)}`);
  const authKey = await seal.authKeyHex(password, s.data.saltAuth);
  return { authKey, r: await client.req('POST', '/api/login', { email, authKey }) };
}
async function login(client, email, password) {
  const { r } = await loginRaw(client, email, password);
  assert.equal(r.status, 200, 'login -> ' + JSON.stringify(r.data));
  const key = await seal.decryptPrivateKey(r.data.encPrivKey, r.data.privIv, await seal.wrapKey(password, r.data.saltWrap));
  return { privKey: key };
}

async function send(client, fromEmail, myPubB64, toEmail, subject, body) {
  const pk = await client.req('GET', `/api/pubkey?email=${encodeURIComponent(toEmail)}`);
  assert.equal(pk.status, 200, 'pubkey -> ' + JSON.stringify(pk.data));
  const recipientPub = await seal.importPublicKey(pk.data.pubKey);
  const myPub = await seal.importPublicKey(myPubB64);
  const content = { from: fromEmail, to: [toEmail.toLowerCase()], subject, body };
  const { messageKey, ciphertext, iv } = await seal.encryptBody(content);
  const encKey = await seal.wrapMessageKey(messageKey, recipientPub);
  const selfEncKey = await seal.wrapMessageKey(messageKey, myPub);
  const r = await client.req('POST', '/api/messages', { ciphertext, iv, recipients: [{ email: toEmail, encKey }], selfEncKey });
  assert.equal(r.status, 200, 'send -> ' + JSON.stringify(r.data));
  return { ciphertext };
}

async function readBox(client, privKey, box) {
  const r = await client.req('GET', `/api/messages?box=${box}`);
  assert.equal(r.status, 200, 'list ' + box + ' -> ' + r.status);
  const out = [];
  for (const m of r.data.messages) {
    const mk = await seal.unwrapMessageKey(m.encKey, privKey);
    out.push(await seal.decryptBody(mk, m.ciphertext, m.iv));
  }
  return out;
}

// Full recovery: returns the new recovery code.
async function recover(client, email, code, newPassword) {
  const norm = seal.normalizeRecoveryCode(code);
  const s = await client.req('GET', `/api/recover/salt?email=${encodeURIComponent(email)}`);
  const recAuthKey = await seal.authKeyHex(norm, s.data.saltAuth);
  const b = await client.req('POST', '/api/recover/begin', { email, recAuthKey });
  if (b.status !== 200) return { status: b.status };
  const pkcs8 = await seal.decryptPkcs8(b.data.encPrivKey, b.data.privIv, await seal.wrapKey(norm, b.data.saltWrap));
  const password = await seal.secretBundle(newPassword, pkcs8);
  const newCode = seal.generateRecoveryCode();
  const recovery = await seal.secretBundle(seal.normalizeRecoveryCode(newCode), pkcs8);
  const c = await client.req('POST', '/api/recover/complete', { email, recAuthKey, password, recovery });
  return { status: c.status, newCode, privKey: await seal.importPrivateKey(pkcs8) };
}

const stamp = Date.now();
const aliceEmail = `a${stamp}@sealed.local`;
const bobEmail = `b${stamp}@sealed.local`;
const alicePw = 'alice-correct-horse-battery-staple';
const bobPw = 'bob-correct-horse-battery-staple';

// ---------- core mail ----------
const A = makeClient();
const B = makeClient();
const alice = await register(A, aliceEmail, alicePw);
const bob = await register(B, bobEmail, bobPw);
ok('two accounts registered (each with a recovery code)');
assert.match(bob.code, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/, 'recovery code format');
ok('recovery code is 8 groups of 4 base32 chars (160 bits)');

const secret = 'Mensaje secreto: el servidor NO deberia poder leer esto 42';
const { ciphertext } = await send(A, alice.email, alice.pubKeyB64, bobEmail, 'Hola Bob', secret);
const inbox = await readBox(B, bob.privKey, 'inbox');
assert.equal(inbox.length, 1);
assert.equal(inbox[0].body, secret);
ok('message sent and decrypted by the recipient');
assert.equal((await readBox(A, alice.privKey, 'sent'))[0].body, secret);
ok("sender decrypted their own Sent copy");
assert.ok(!ciphertext.includes(secret) && !Buffer.from(ciphertext, 'base64').toString('latin1').includes('servidor'));
ok('stored ciphertext does not contain the plaintext');

// ---------- issues reported from outside ----------
// A message body is sealed by whoever sent it, so its JSON can have any shape. The
// reader keeps only the fields it uses, with the types it expects: a body such as
// {"from":{"toString":1}} used to throw while the folder was drawn and stop the rest
// of the mailbox from rendering.
const erinPw = 'erin-correct-horse-battery-staple';
// One account mailing itself keeps the sign-up rate limit (10 per IP) in budget.
const Cc = makeClient();
const erin = await register(Cc, `erin.d-${stamp}@sealed.local`, erinPw);
async function sendRaw(content) {
  const erinKey = await seal.importPublicKey(erin.pubKeyB64);
  const { messageKey, ciphertext: ct, iv } = await seal.encryptBody(content);
  const encKey = await seal.wrapMessageKey(messageKey, erinKey);
  const r = await Cc.req('POST', '/api/messages', { ciphertext: ct, iv, selfEncKey: encKey, recipients: [{ email: erin.email, encKey }] });
  assert.equal(r.status, 200);
}
await sendRaw({ from: { toString: 1 }, to: 'x', subject: 7, body: ['b'], auth: 'pass', attachments: [{ name: {}, size: '1' }, 5] });
const [crafted] = await readBox(Cc, erin.privKey, 'inbox');
assert.doesNotThrow(() => `${crafted.from}${crafted.to}${crafted.subject}${crafted.body}`);
assert.equal(crafted.from, undefined);
assert.equal(crafted.to, undefined);
assert.equal(crafted.auth, undefined);
assert.equal(typeof crafted.attachments[0].name, 'undefined');
assert.equal(crafted.attachments.length, 2);
await sendRaw(null);
await assert.rejects(readBox(Cc, erin.privKey, 'inbox'), /malformed message body/);
ok('a decrypted body keeps only well-typed fields; one that is not an object is refused');

// A repeated recipient address must not fan one send into several inbox copies.
{
  const dupKey = await seal.wrapMessageKey((await seal.encryptBody({ from: erin.email, to: [erin.email], subject: 'd', body: 'd' })).messageKey, await seal.importPublicKey(erin.pubKeyB64));
  const mk = await seal.encryptBody({ from: erin.email, to: [erin.email], subject: 'dup', body: 'dup' });
  const ek = await seal.wrapMessageKey(mk.messageKey, await seal.importPublicKey(erin.pubKeyB64));
  const r = await Cc.req('POST', '/api/messages', { ciphertext: mk.ciphertext, iv: mk.iv, selfEncKey: ek, recipients: Array.from({ length: 10 }, () => ({ email: erin.email, encKey: ek })) });
  assert.equal(r.status, 200);
  const inbox = (await Cc.req('GET', '/api/messages?box=inbox')).data.messages.filter((m) => m.id === r.data.id);
  assert.equal(inbox.length, 1, `a 10x-repeated recipient produced ${inbox.length} inbox copies`);
  void dupKey;
}
ok('a repeated recipient address is delivered to exactly once (no inbox amplification)');

// Look-alike addresses: the part before @ is plain ASCII, so an invisible or
// Cyrillic character cannot register a second "alice" that reads the same.
for (const local of [`ali\u200bce${stamp}`, `\u0430lice${stamp}`]) {
  const { r } = await registerRaw(makeClient(), `${local}@sealed.local`, 'whatever-password-123');
  assert.equal(r.status, 400, `${JSON.stringify(local)} must be refused`);
}
ok('addresses with invisible or look-alike (non-ASCII) characters are refused at sign-up');

// A malicious server can answer /api/salt with the account's saltWrap. What the
// browser then sends as authKey must still not open the private key.
const erinLogin = await loginRaw(makeClient(), erin.email, erinPw);
assert.equal(erinLogin.r.status, 200);
const asSentWithWrapSalt = await seal.authKeyHex(erinPw, erinLogin.r.data.saltWrap);
const asAesKey = await webcrypto.subtle.importKey('raw', Buffer.from(asSentWithWrapSalt, 'hex'), 'AES-GCM', false, ['decrypt']);
await assert.rejects(seal.decryptPkcs8(erinLogin.r.data.encPrivKey, erinLogin.r.data.privIv, asAesKey));
ok('the login key derived with the wrapping salt cannot open the private key');

// SSRF guard for the Resend raw-download URL (server/net-guard.js). A tampered API
// response must not be able to make the server fetch an internal address.
{
  const { assertPublicHttpsUrl } = await import(pathToFileURL(path.join(root, 'server/net-guard.js')).href);
  const mustReject = [
    'http://host.example/raw',                       // not https
    'https://host.example:8080/raw',                 // non-default port
    'https://user:pass@host.example/raw',            // embedded credentials
    'https://169.254.169.254/latest/meta-data/',     // cloud metadata (IMDS)
    'https://127.0.0.1/raw',
    'https://[::1]/raw',
    'https://10.0.0.5/raw',
    'https://192.168.1.1/raw',
    'https://[::ffff:169.254.169.254]/raw',          // IPv4-mapped metadata
    'definitely not a url',
  ];
  for (const u of mustReject) await assert.rejects(assertPublicHttpsUrl(u), /insecure fetch URL/, `should reject ${u}`);
  await assert.doesNotReject(assertPublicHttpsUrl('https://1.1.1.1/raw'));        // public literal, no DNS
  await assert.rejects(assertPublicHttpsUrl('https://host.example/raw', { allowlist: ['resend.com'] }), /not in allowlist/);
  ok('SSRF guard refuses non-https, private/loopback/link-local, metadata (incl. v4-mapped), creds, odd ports and off-allowlist hosts');
}

// ---------- attachments ----------
// Two files: random bytes with a marker inside, and a small text file.
const fileMarker = `adjunto-secreto-${randomBytes(6).toString('hex')}`;
const fileA = Buffer.concat([randomBytes(150_000), Buffer.from(fileMarker), randomBytes(150_000)]);
const fileB = Buffer.from(`notas ${fileMarker}\n`);
async function sendWithFiles(client, from, myPubB64, toEmail, subject, files) {
  const pk = await client.req('GET', `/api/pubkey?email=${encodeURIComponent(toEmail)}`);
  const content = { from: from, to: [toEmail], subject, body: 'con adjuntos',
    attachments: await Promise.all(files.map((f) => seal.describeFile(f.name, f.type, f.bytes))) };
  const { messageKey, ciphertext, iv } = await seal.encryptBody(content);
  const sealed = [];
  for (const [i, f] of files.entries()) sealed.push(await seal.encryptAttachment(messageKey, f.bytes, i));
  return client.req('POST', '/api/messages', {
    ciphertext, iv, attachments: sealed,
    recipients: [{ email: toEmail, encKey: await seal.wrapMessageKey(messageKey, await seal.importPublicKey(pk.data.pubKey)) }],
    selfEncKey: await seal.wrapMessageKey(messageKey, await seal.importPublicKey(myPubB64)),
  });
}
// Lists a box and returns the newest message with its key, body and attachment list.
async function newest(client, privKey, box) {
  const m = (await client.req('GET', `/api/messages?box=${box}`)).data.messages[0];
  const key = await seal.unwrapMessageKey(m.encKey, privKey);
  return { m, key, content: await seal.decryptBody(key, m.ciphertext, m.iv) };
}
const withFiles = await sendWithFiles(A, alice.email, alice.pubKeyB64, bobEmail, 'Con adjuntos', [
  { name: 'foto.bin', type: 'application/octet-stream', bytes: fileA },
  { name: 'notas.txt', type: 'text/plain', bytes: fileB },
]);
assert.equal(withFiles.status, 200, 'send with files -> ' + JSON.stringify(withFiles.data));
const got = await newest(B, bob.privKey, 'inbox');
assert.deepEqual(got.content.attachments.map((a) => [a.name, a.size]), [['foto.bin', fileA.length], ['notas.txt', fileB.length]]);
for (const [i, original] of [fileA, fileB].entries()) {
  const r = await B.req('GET', `/api/messages/${got.m.id}/attachments/${i}`);
  assert.equal(r.status, 200);
  const bytes = await seal.decryptAttachment(got.key, r.data.ciphertext, r.data.iv, i, got.content.attachments[i]);
  assert.ok(Buffer.from(bytes).equals(original), `attachment ${i} round-trips`);
}
ok('attachments are sealed in the browser and the recipient opens each one, byte for byte');

const sentFiles = await newest(A, alice.privKey, 'sent');
const sentA = await A.req('GET', `/api/messages/${sentFiles.m.id}/attachments/0`);
assert.ok(Buffer.from(await seal.decryptAttachment(sentFiles.key, sentA.data.ciphertext, sentA.data.iv, 0, sentFiles.content.attachments[0])).equals(fileA));
const Carol = makeClient();
await register(Carol, `stranger${stamp}@sealed.local`, 'carol-correct-horse-battery-staple');
assert.equal((await Carol.req('GET', `/api/messages/${got.m.id}/attachments/0`)).status, 404, 'a stranger must not get the file');
assert.equal((await makeClient().req('GET', `/api/messages/${got.m.id}/attachments/0`)).status, 401);
ok('the sender opens their own copy; anyone else gets 404 (and 401 without a session)');

// The server cannot swap files around: file 1 offered as file 0 fails (position is
// authenticated), and a file that does not match the body's hash is refused.
const f1 = await B.req('GET', `/api/messages/${got.m.id}/attachments/1`);
await assert.rejects(seal.decryptAttachment(got.key, f1.data.ciphertext, f1.data.iv, 0, got.content.attachments[0]));
await assert.rejects(seal.decryptAttachment(got.key, f1.data.ciphertext, f1.data.iv, 1, { ...got.content.attachments[1], sha256: '0'.repeat(64) }));
ok('a reordered or substituted attachment is rejected by the reader');

const tooMany = await sendWithFiles(A, alice.email, alice.pubKeyB64, bobEmail, 'x',
  Array.from({ length: 11 }, (_, i) => ({ name: `f${i}`, type: 'text/plain', bytes: Buffer.from('x') })));
assert.equal(tooMany.status, 400);
const tooBig = await sendWithFiles(A, alice.email, alice.pubKeyB64, bobEmail, 'x',
  [{ name: 'grande.bin', type: 'application/octet-stream', bytes: randomBytes(10 * 1024 * 1024 + 1) }]);
assert.equal(tooBig.status, 400);
assert.equal((await A.req('POST', '/api/messages', { ciphertext: 'QUJD', iv: 'QUJD', recipients: [], selfEncKey: 'QUJD',
  attachments: [{ ciphertext: 'not base64!', iv: 'QUJD' }] })).status, 400);
ok('more than 10 files, more than 10 MB, or a malformed file is refused');

const anonBig = await makeClient().req('POST', '/api/messages', { pad: 'A'.repeat(2 * 1024 * 1024) }, { csrf: false });
assert.equal(anonBig.status, 401, 'a large anonymous body is refused before it is parsed');
ok('large message bodies are only accepted from a signed-in session');

const dbWithFiles = fs.readdirSync(tmp).filter((f) => f.startsWith('test.db'))
  .map((f) => fs.readFileSync(path.join(tmp, f)).toString('latin1')).join('');
assert.ok(!dbWithFiles.includes(fileMarker), 'attachment plaintext found in the database!');
ok('attachment contents are nowhere in the database files');

// ---------- password login checks ----------
const bad = await loginRaw(makeClient(), bobEmail, 'totally-wrong');
assert.equal(bad.r.status, 401);
ok('wrong password rejected (401)');

// ---------- recovery with the code ----------
const wrongCode = await recover(makeClient(), bobEmail, seal.generateRecoveryCode(), 'irrelevant-password-1');
assert.equal(wrongCode.status, 401, 'wrong recovery code should be 401');
ok('wrong recovery code rejected (401)');

const unkSalt = await makeClient().req('GET', '/api/recover/salt?email=nobody-here@sealed.local');
assert.equal(unkSalt.status, 200);
assert.ok(unkSalt.data.saltAuth.length > 0);
ok('recovery salt returned for unknown email (non-enumerable)');

const R = makeClient();
const bobNewPw = 'bob-brand-new-password-after-recovery';
const rec1 = await recover(R, bobEmail, bob.code.toLowerCase().replace(/-/g, ' '), bobNewPw);
assert.equal(rec1.status, 200, 'recovery should succeed');
ok('recovered with the code (typed lower-case with spaces: normalization works)');

const afterRec = await readBox(R, rec1.privKey, 'inbox');
assert.ok(afterRec.some((c) => c.body === secret), 'the first message is still readable');
ok('after recovery the OLD mail is still readable (same private key, re-wrapped)');

const oldSession = await B.req('GET', '/api/messages?box=inbox');
assert.equal(oldSession.status, 401, 'old sessions must be revoked');
ok('all previous sessions revoked by the recovery');

assert.equal((await loginRaw(makeClient(), bobEmail, bobPw)).r.status, 401);
ok('old password no longer works');

const N = makeClient();
const bobN = await login(N, bobEmail, bobNewPw);
assert.ok((await readBox(N, bobN.privKey, 'inbox')).some((c) => c.body === secret));
ok('new password logs in and decrypts old mail');

const reuse = await recover(makeClient(), bobEmail, bob.code, 'another-new-password-2');
assert.equal(reuse.status, 401, 'a used recovery code must be burned');
ok('the used recovery code is burned (cannot be reused)');

// ---------- sudo / reauth ----------
const s = await N.req('GET', `/api/salt?email=${encodeURIComponent(bobEmail)}`);
const goodAuth = await seal.authKeyHex(bobNewPw, s.data.saltAuth);
const badAuth = await seal.authKeyHex('not-the-password', s.data.saltAuth);
assert.equal((await N.req('POST', '/api/reauth', { authKey: badAuth })).status, 401);
assert.equal((await N.req('POST', '/api/reauth', { authKey: goodAuth }, { csrf: false })).status, 403);
const ra = await N.req('POST', '/api/reauth', { authKey: goodAuth });
assert.equal(ra.status, 200);
const raPkcs8 = await seal.decryptPkcs8(ra.data.encPrivKey, ra.data.privIv, await seal.wrapKey(bobNewPw, ra.data.saltWrap));
ok('reauth: wrong password 401, missing CSRF 403, correct password returns the wrapped key');

// ---------- rotate recovery code ----------
const rotatedCode = seal.generateRecoveryCode();
const rotBundle = await seal.secretBundle(seal.normalizeRecoveryCode(rotatedCode), raPkcs8);
assert.equal((await N.req('POST', '/api/recovery/rotate', { authKey: badAuth, recovery: rotBundle })).status, 401);
assert.equal((await N.req('POST', '/api/recovery/rotate', { authKey: goodAuth, recovery: rotBundle })).status, 200);
assert.equal((await recover(makeClient(), bobEmail, rec1.newCode, 'yet-another-password-3')).status, 401);
const rot = await recover(makeClient(), bobEmail, rotatedCode, 'final-password-after-rotation');
assert.equal(rot.status, 200);
ok('rotation needs the password; afterwards only the NEW code works');

// ---------- recovery race: the same code spent twice in parallel ----------
const C = makeClient();
const carol = await register(C, `c${stamp}@sealed.local`, 'carol-correct-horse-battery-staple');
{
  const norm = seal.normalizeRecoveryCode(carol.code);
  const s2 = await C.req('GET', `/api/recover/salt?email=${encodeURIComponent(carol.email)}`);
  const recAuthKey = await seal.authKeyHex(norm, s2.data.saltAuth);
  const b = await C.req('POST', '/api/recover/begin', { email: carol.email, recAuthKey });
  const pkcs8 = await seal.decryptPkcs8(b.data.encPrivKey, b.data.privIv, await seal.wrapKey(norm, b.data.saltWrap));
  // Build both request bodies first (slow PBKDF2), then fire them at the same instant.
  const bodies = await Promise.all(['race-a-password-1', 'race-b-password-2'].map(async (pw) => ({
    email: carol.email, recAuthKey,
    password: await seal.secretBundle(pw, pkcs8),
    recovery: await seal.secretBundle(seal.normalizeRecoveryCode(seal.generateRecoveryCode()), pkcs8),
  })));
  const results = await Promise.all(bodies.map((body) => makeClient().req('POST', '/api/recover/complete', body)));
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 401], 'exactly one concurrent recovery may win, got ' + statuses);
}
ok('two simultaneous recoveries with the same code: exactly one succeeds');

// ---------- passkey server-side defenses (no authenticator needed) ----------
const optsA = await makeClient().req('POST', '/api/passkeys/login/options', {});
const optsB = await makeClient().req('POST', '/api/passkeys/login/options', { email: aliceEmail });
for (const o of [optsA, optsB]) {
  assert.equal(o.status, 200);
  assert.deepEqual(o.data.options.allowCredentials, []);
  assert.equal(o.data.options.userVerification, 'required');
  assert.deepEqual(Object.keys(o.data).sort(), ['challengeId', 'options']);
}
ok('passkey sign-in options never depend on an email (nothing to enumerate)');

const forged = await makeClient().req('POST', '/api/passkeys/login/verify', {
  challengeId: optsA.data.challengeId,
  response: { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { userHandle: 'AAAA' }, clientExtensionResults: {} },
});
assert.equal(forged.status, 401);
ok('passkey sign-in with a forged response fails (401)');

const A2 = makeClient();
await login(A2, aliceEmail, alicePw);
const sA = await A2.req('GET', `/api/salt?email=${encodeURIComponent(aliceEmail)}`);
const aliceAuthKey = await seal.authKeyHex(alicePw, sA.data.saltAuth);
const aliceWrongKey = await seal.authKeyHex('not-alices-password', sA.data.saltAuth);
assert.equal((await A2.req('POST', '/api/passkeys/register/options', {})).status, 401, 'no password');
assert.equal((await A2.req('POST', '/api/passkeys/register/options', { authKey: aliceWrongKey })).status, 401, 'wrong password');
assert.equal((await A2.req('POST', '/api/passkeys/register/options', { authKey: aliceAuthKey }, { csrf: false })).status, 403);
const regOpts = await A2.req('POST', '/api/passkeys/register/options', { authKey: aliceAuthKey });
assert.equal(regOpts.status, 200);
assert.equal(regOpts.data.options.authenticatorSelection.userVerification, 'required');
assert.equal(regOpts.data.options.authenticatorSelection.residentKey, 'required');
assert.equal(regOpts.data.options.rp.id, 'localhost');
assert.ok(!regOpts.data.options.user.id.includes('user-'), 'WebAuthn user id must be random, not the row id');
ok('enrolling a passkey needs the PASSWORD on the server (a session alone gets 401)');

const leak = await A2.req('POST', '/api/passkeys/register/verify', {
  challengeId: regOpts.data.challengeId, encPrivKey: 'QUJD', privIv: 'QUJD', label: 'x',
  response: { id: 'AAAA', clientExtensionResults: { prf: { enabled: true } } },
});
assert.equal(leak.status, 400);
assert.match(leak.data.error, /PRF/);
ok('server refuses any request that carries PRF data');

assert.equal((await fetch(BASE + '/api/passkeys')).status, 401);
ok('passkey list requires a session (401)');

// ---------- sign out everywhere else ----------
const A3 = makeClient();
await login(A3, aliceEmail, alicePw);
const rv = await A2.req('POST', '/api/sessions/revoke-others', {});
assert.equal(rv.status, 200);
assert.ok(rv.data.revoked >= 1);
assert.equal((await A3.req('GET', '/api/messages?box=inbox')).status, 401, 'other session must be closed');
assert.equal((await A2.req('GET', '/api/messages?box=inbox')).status, 200, 'current session must survive');
ok('"close the other sessions" ends them and keeps the current one');

// ---------- error handling ----------
const badJson = await fetch(BASE + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' });
assert.equal(badJson.status, 400);
assert.match(badJson.headers.get('content-type') || '', /application\/json/);
assert.ok(!(await badJson.text()).includes('at '), 'no stack trace');
ok('malformed JSON gets a short JSON 400, never an HTML stack trace');

// ---------- real email: in from outside, out to outside ----------
const fromOutside = nodemailer.createTransport({ host: '127.0.0.1', port: smtpInPort, secure: false, ignoreTLS: true });
const marker = `marca-${randomBytes(6).toString('hex')}`;

await fromOutside.sendMail({
  from: 'amiga@gmail.com', to: bobEmail, subject: 'Desde Gmail',
  text: `Hola Bob, te escribo desde fuera. ${marker}`,
});
// Bob's last recovery (above) closed every session he had, so he signs in again.
const BF = makeClient();
const bobFinal = await login(BF, bobEmail, 'final-password-after-rotation');
const bobInbox = await BF.req('GET', '/api/messages?box=inbox');
assert.equal(bobInbox.status, 200, 'bob inbox -> ' + bobInbox.status);
const ext = bobInbox.data.messages.find((m) => m.external === 1);
assert.ok(ext, 'the outside mail is in the inbox, flagged external');
assert.equal(ext.sender, 'amiga@gmail.com');
const extContent = await seal.decryptBody(await seal.unwrapMessageKey(ext.encKey, bobFinal.privKey), ext.ciphertext, ext.iv);
assert.equal(extContent.subject, 'Desde Gmail');
assert.ok(extContent.body.includes(marker));
ok('mail from outside (SMTP) lands in the inbox, decryptable only with the recipient key');

// The plaintext must never have been written: scan the database files for the marker.
const dbBytes = fs.readdirSync(tmp).filter((f) => f.startsWith('test.db'))
  .map((f) => fs.readFileSync(path.join(tmp, f)).toString('latin1')).join('');
assert.ok(dbBytes.length > 0, 'database files were read');
assert.ok(!dbBytes.includes(marker) && !dbBytes.includes('te escribo desde fuera'), 'plaintext found in the database!');
ok('incoming mail is sealed in memory: its text is nowhere in the database files');

await assert.rejects(fromOutside.sendMail({ from: 'x@gmail.com', to: 'nadie@sealed.local', subject: 's', text: 't' }),
  (err) => err.responseCode === 550, 'unknown local user must be refused');
await assert.rejects(fromOutside.sendMail({ from: 'x@gmail.com', to: 'victima@yahoo.com', subject: 's', text: 't' }),
  (err) => err.responseCode === 554, 'relaying to another domain must be refused');
ok('inbound SMTP refuses unknown users (550) and relaying to other domains (554): not an open relay');

// Out: Alice writes to someone outside. The outside server must get the real message,
// and Alice keeps only her own encrypted copy.
const outBody = `Te escribo desde Sealed Mail. ${marker}-out`;
const alicePubKey = await seal.importPublicKey(alice.pubKeyB64);
const outSealed = await seal.encryptBody({ from: alice.email, to: ['amiga@gmail.com'], subject: 'Hola desde Sealed', body: outBody });
const selfCopy = { ciphertext: outSealed.ciphertext, iv: outSealed.iv, encKey: await seal.wrapMessageKey(outSealed.messageKey, alicePubKey) };
const sent = await A2.req('POST', '/api/messages/external', { to: 'amiga@gmail.com', subject: 'Hola desde Sealed', body: outBody, selfCopy });
assert.equal(sent.status, 200, 'external send -> ' + JSON.stringify(sent.data));
const caught = outsideMail.find((m) => m.subject === 'Hola desde Sealed');
assert.ok(caught, 'the outside mail server received it');
assert.equal(caught.from.value[0].address, alice.email);
assert.ok(caught.text.includes(outBody));
const aliceSent = (await A2.req('GET', '/api/messages?box=sent')).data.messages.find((m) => m.external === 1);
const aliceCopy = await seal.decryptBody(await seal.unwrapMessageKey(aliceSent.encKey, alice.privKey), aliceSent.ciphertext, aliceSent.iv);
assert.equal(aliceCopy.body, outBody);
ok('mail to an outside address is delivered by SMTP, and the Sent copy is stored encrypted');

// Out, with a file: the outside server gets it readable; Alice's copy keeps it sealed.
const outFile = Buffer.from(`informe ${marker}-file`);
const outContent = { from: alice.email, to: ['amiga@gmail.com'], subject: 'Con informe', body: 'Te lo adjunto.',
  attachments: [await seal.describeFile('informe.txt', 'text/plain', outFile)] };
const outSealedF = await seal.encryptBody(outContent);
const sentOut = await A2.req('POST', '/api/messages/external', {
  to: 'amiga@gmail.com', subject: 'Con informe', body: 'Te lo adjunto.',
  files: [{ name: '../informe.txt', type: 'text/plain', data: outFile.toString('base64') }],
  selfCopy: { ciphertext: outSealedF.ciphertext, iv: outSealedF.iv, encKey: await seal.wrapMessageKey(outSealedF.messageKey, alicePubKey),
    attachments: [await seal.encryptAttachment(outSealedF.messageKey, outFile, 0)] },
});
assert.equal(sentOut.status, 200, 'external send with file -> ' + JSON.stringify(sentOut.data));
const caughtFile = outsideMail.find((m) => m.subject === 'Con informe');
assert.equal(caughtFile.attachments.length, 1);
assert.equal(caughtFile.attachments[0].filename, '.._informe.txt', 'path separators are stripped from file names');
assert.ok(caughtFile.attachments[0].content.equals(outFile));
const aliceOut = (await A2.req('GET', '/api/messages?box=sent')).data.messages.find((m) => m.external === 1 && m.id !== aliceSent.id);
const aliceOutKey = await seal.unwrapMessageKey(aliceOut.encKey, alice.privKey);
const aliceOutContent = await seal.decryptBody(aliceOutKey, aliceOut.ciphertext, aliceOut.iv);
const aliceOutFile = await A2.req('GET', `/api/messages/${aliceOut.id}/attachments/0`);
assert.ok(Buffer.from(await seal.decryptAttachment(aliceOutKey, aliceOutFile.data.ciphertext, aliceOutFile.data.iv, 0, aliceOutContent.attachments[0])).equals(outFile));
assert.equal((await A2.req('POST', '/api/messages/external', { to: 'a@gmail.com', subject: 's', body: 'b', files: [{ name: 'a', type: 'text/plain', data: 'QUJD' }], selfCopy })).status, 400,
  'files without their sealed copy are refused');
ok('a file sent outside arrives readable there, and the Sent copy keeps it encrypted');

// In, with a file: sealed on arrival like the text.
const inMarker = `${marker}-in-file`;
await fromOutside.sendMail({ from: 'amiga@gmail.com', to: bobEmail, subject: 'Te paso el PDF', text: 'Adjunto.',
  attachments: [{ filename: 'contrato.pdf', contentType: 'application/pdf', content: Buffer.from(`%PDF-1.4 ${inMarker}`) }] });
const inbound = (await BF.req('GET', '/api/messages?box=inbox')).data.messages;
let inFile = null;
for (const m of inbound.filter((x) => x.external === 1)) {
  const key = await seal.unwrapMessageKey(m.encKey, bobFinal.privKey);
  const c = await seal.decryptBody(key, m.ciphertext, m.iv);
  if (c.subject === 'Te paso el PDF') inFile = { m, key, c };
}
assert.ok(inFile, 'mail with a file reached the inbox');
assert.deepEqual(inFile.c.attachments.map((a) => [a.name, a.type]), [['contrato.pdf', 'application/pdf']]);
const inBytes = await BF.req('GET', `/api/messages/${inFile.m.id}/attachments/0`);
assert.equal(Buffer.from(await seal.decryptAttachment(inFile.key, inBytes.data.ciphertext, inBytes.data.iv, 0, inFile.c.attachments[0])).toString(), `%PDF-1.4 ${inMarker}`);
const dbInFile = fs.readdirSync(tmp).filter((f) => f.startsWith('test.db'))
  .map((f) => fs.readFileSync(path.join(tmp, f)).toString('latin1')).join('');
assert.ok(!dbInFile.includes(inMarker), 'incoming attachment plaintext found in the database!');
ok('a file arriving from outside is sealed on arrival, opens for the recipient and is never stored readable');

// An empty file is valid (its ciphertext is just the 16-byte tag).
const emptyFile = await sendWithFiles(A2, alice.email, alice.pubKeyB64, bobEmail, 'Vacío',
  [{ name: 'vacio.txt', type: 'text/plain', bytes: Buffer.alloc(0) }]);
assert.equal(emptyFile.status, 200, 'empty file -> ' + JSON.stringify(emptyFile.data));
ok('an empty file can be attached');

// A large file to an outside address travels twice (readable and sealed) and still fits;
// a right-to-left override in its name is stripped.
const bigOut = randomBytes(8 * 1024 * 1024);
const bigContent = { from: alice.email, to: ['amiga@gmail.com'], subject: 'Grande', body: 'b',
  attachments: [await seal.describeFile('factura\u202efdp.exe', 'application/octet-stream', bigOut)] };
const bigSealed = await seal.encryptBody(bigContent);
const bigSent = await A2.req('POST', '/api/messages/external', {
  to: 'amiga@gmail.com', subject: 'Grande', body: 'b',
  files: [{ name: 'factura\u202efdp.exe', type: 'application/octet-stream', data: bigOut.toString('base64') }],
  selfCopy: { ciphertext: bigSealed.ciphertext, iv: bigSealed.iv, encKey: await seal.wrapMessageKey(bigSealed.messageKey, alicePubKey),
    attachments: [await seal.encryptAttachment(bigSealed.messageKey, bigOut, 0)] },
});
assert.equal(bigSent.status, 200, 'external 8 MB -> ' + JSON.stringify(bigSent.data));
const bigCaught = outsideMail.find((m) => m.subject === 'Grande');
assert.equal(bigCaught.attachments[0].filename, 'facturafdp.exe', 'bidi override stripped from the name');
assert.ok(bigCaught.attachments[0].content.equals(bigOut));
ok('an 8 MB file goes out to an outside address, its name stripped of direction overrides');

// Mail from outside claiming to be Alice must not spend Alice's quota, and outside
// mail can only store so much for one recipient before files are left out.
const D = makeClient();
const daveEmail = `d${stamp}@sealed.local`;
const dave = await register(D, daveEmail, 'dave-correct-horse-battery-staple');
const nineMb = randomBytes(9 * 1024 * 1024);
for (let i = 0; i < 4; i++) {
  await fromOutside.sendMail({ from: alice.email, to: daveEmail, subject: `Relleno ${i}`, text: 'x',
    attachments: [{ filename: `relleno-${i}.bin`, content: nineMb }] });
}
const daveBox = (await D.req('GET', '/api/messages?box=inbox')).data.messages;
const daveContents = await Promise.all(daveBox.map(async (m) =>
  seal.decryptBody(await seal.unwrapMessageKey(m.encKey, dave.privKey), m.ciphertext, m.iv)));
const lastFill = daveContents.find((c) => c.subject === 'Relleno 3');
assert.ok(!lastFill.attachments, 'files past the inbound quota are left out');
assert.match(lastFill.body, /límite de adjuntos recibidos de fuera/);
assert.equal(daveContents.filter((c) => c.attachments).length, 3);
const afterSpoof = await sendWithFiles(A2, alice.email, alice.pubKeyB64, bobEmail, 'Sigo pudiendo',
  [{ name: 'a.bin', type: 'application/octet-stream', bytes: randomBytes(1024 * 1024) }]);
assert.equal(afterSpoof.status, 200, 'spoofed From must not count against Alice -> ' + JSON.stringify(afterSpoof.data));
ok('outside mail claiming to be someone does not spend their quota, and stops storing files past the recipient quota');

const overQuota = await sendWithFiles(A2, alice.email, alice.pubKeyB64, bobEmail, 'Demasiado',
  [{ name: 'a.bin', type: 'application/octet-stream', bytes: randomBytes(9 * 1024 * 1024) },
   { name: 'b.bin', type: 'application/octet-stream', bytes: randomBytes(1) }]);
const overQuota2 = await sendWithFiles(A2, alice.email, alice.pubKeyB64, bobEmail, 'Demasiado 2',
  [{ name: 'c.bin', type: 'application/octet-stream', bytes: randomBytes(9 * 1024 * 1024) }]);
const overQuota3 = await sendWithFiles(A2, alice.email, alice.pubKeyB64, bobEmail, 'Demasiado 3',
  [{ name: 'd.bin', type: 'application/octet-stream', bytes: randomBytes(9 * 1024 * 1024) }]);
assert.deepEqual([overQuota.status, overQuota2.status, overQuota3.status], [200, 200, 413], 'the third 9 MB send passes 30 MB');
ok('the per-account attachment quota counts what the account itself sent');

assert.equal((await A2.req('POST', '/api/messages/external', { to: bobEmail, subject: 's', body: 'b', selfCopy })).status, 400);
assert.equal((await A2.req('POST', '/api/messages/external', { to: 'a@gmail.com', subject: 'x\r\nBcc: v@evil.com', body: 'b', selfCopy })).status, 400);
assert.equal((await A2.req('POST', '/api/messages/external', { to: 'a@gmail.com', subject: 's', body: 'b', selfCopy }, { csrf: false })).status, 403);
ok('external send refuses internal addresses, header injection (CR/LF) and missing CSRF');

const wrongDomain = await makeClient().req('POST', '/api/register', {
  email: 'pepe@gmail.com', saltAuth: 'ab', saltWrap: 'ab', authKey: 'ab', pubKey: 'QUJD', encPrivKey: 'QUJD', privIv: 'QUJD',
  recovery: { saltAuth: 'ab', saltWrap: 'ab', authKey: 'ab', encPrivKey: 'QUJD', privIv: 'QUJD' },
});
assert.equal(wrongDomain.status, 400);
ok('accounts can only be created on the mail domain (no claiming a gmail.com address)');

// ---------- inbound through Resend (polled API, no public URL) ----------
const waitFor = async (fn, ms = 6000) => {
  const t = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t > ms) return null;
    await new Promise((r) => setTimeout(r, 150));
  }
};
const viaResendSubject = `Via Resend ${marker}`;
fakeResendInbox.push(
  { id: 'rs-1', to: bobEmail, from: 'socia@empresa.com', subject: viaResendSubject, text: `Recibido por Resend. ${marker}-rs`, auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' } },
  { id: 'rs-2', to: 'nadie@sealed.local', from: 'x@empresa.com', subject: 'para nadie', text: 't', auth: { dmarc: 'pass' } },
  { id: 'rs-3', to: 'alguien@otro-dominio.com', from: 'x@empresa.com', subject: 'otro dominio', text: 't', auth: { dmarc: 'pass' } },
);
const findViaResend = async () => {
  const list = (await BF.req('GET', '/api/messages?box=inbox')).data.messages;
  const out = [];
  for (const m of list.filter((x) => x.external === 1)) {
    const c = await seal.decryptBody(await seal.unwrapMessageKey(m.encKey, bobFinal.privKey), m.ciphertext, m.iv);
    if (c.subject === viaResendSubject) out.push({ m, c });
  }
  return out.length ? out : null;
};
const viaResend = await waitFor(findViaResend);
assert.ok(viaResend, 'mail polled from Resend reached the inbox');
assert.equal(viaResend[0].m.sender, 'socia@empresa.com');
assert.ok(viaResend[0].c.body.includes(`${marker}-rs`));
assert.deepEqual(viaResend[0].c.auth, { spf: 'pass', dkim: 'pass', dmarc: 'pass' });
ok('mail received by Resend is polled, sealed for the recipient and keeps the DMARC verdict (sealed too)');

await new Promise((r) => setTimeout(r, 1200)); // several more polls
assert.equal((await findViaResend()).length, 1, 'a polled message must be delivered exactly once');
assert.equal(fakeResendAuth.rejected, 0, 'every call to Resend carried the receive key');
assert.ok(fakeResendAuth.ok >= 3);
ok('each Resend message is delivered once across repeated polls, always authenticated with the key');

const dbAfterResend = fs.readdirSync(tmp).filter((f) => f.startsWith('test.db'))
  .map((f) => fs.readFileSync(path.join(tmp, f)).toString('latin1')).join('');
assert.ok(!dbAfterResend.includes(`${marker}-rs`) && !dbAfterResend.includes('Recibido por Resend'), 'plaintext found in the database!');
ok('mail polled from Resend is not stored in the clear either');

outside.close();
fakeResend.close();
console.log(`\nALL ${passed} CHECKS PASSED`);
process.exit(0); // the child server keeps the event loop alive; the exit hook cleans up
