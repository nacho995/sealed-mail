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
import { fileURLToPath } from 'node:url';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import nodemailer from 'nodemailer';

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

async function register(client, email, password) {
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
assert.equal(afterRec[0].body, secret);
ok('after recovery the OLD mail is still readable (same private key, re-wrapped)');

const oldSession = await B.req('GET', '/api/messages?box=inbox');
assert.equal(oldSession.status, 401, 'old sessions must be revoked');
ok('all previous sessions revoked by the recovery');

assert.equal((await loginRaw(makeClient(), bobEmail, bobPw)).r.status, 401);
ok('old password no longer works');

const N = makeClient();
const bobN = await login(N, bobEmail, bobNewPw);
assert.equal((await readBox(N, bobN.privKey, 'inbox'))[0].body, secret);
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

outside.close();
console.log(`\nALL ${passed} CHECKS PASSED`);
process.exit(0); // the child server keeps the event loop alive; the exit hook cleans up
