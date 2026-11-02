// All cryptography happens here, in the browser. The server never receives the
// password, the private key, or any plaintext message body.
//
// Design (PGP / ProtonMail style):
//   - Each account has an RSA-OAEP keypair.
//   - The private key is exported and encrypted with a key derived from the
//     password (PBKDF2); only the ciphertext is uploaded.
//   - A message is encrypted with a fresh random AES-GCM key; that key is then
//     RSA-wrapped once per recipient. The server stores ciphertext + wrapped keys.

const subtle = window.crypto.subtle;
const PBKDF2_ITERS = 310000; // OWASP-range for PBKDF2-HMAC-SHA256 (2023+)
const enc = new TextEncoder();
const dec = new TextDecoder();

// Purpose labels bound into the two key wraps as AEAD additional data (AES-GCM) and
// RSA-OAEP label. They tie each ciphertext to its role, so a blob lifted from one slot
// cannot be fed into another: it fails as a clean authenticated-decryption error rather
// than surfacing later as a bad key import. Must match server/sealing.js byte for byte.
const PRIVKEY_AAD = enc.encode('sealed-mail private-key v1');
const MSGKEY_LABEL = enc.encode('sealed-mail message-key v1');

// ---- encoding helpers ----
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  // 32 KB at a time: fast for attachments, and below the engine's argument limit
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function randomHex(n) { return bufToHex(window.crypto.getRandomValues(new Uint8Array(n))); }

// ---- key derivation ----
async function deriveBits(password, saltHex, bits) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base, bits,
  );
}
// authKey: sent to the server as the login secret (server stores only scrypt(authKey)).
// The PBKDF2 output goes through HKDF before it leaves the browser, so what is sent is
// never a raw PBKDF2(password, salt). Without that step a malicious server could answer
// /api/salt with the account's saltWrap and be handed wrapKey itself.
async function authKeyHex(password, saltAuthHex) {
  const base = await subtle.importKey('raw', await deriveBits(password, saltAuthHex, 256), 'HKDF', false, ['deriveBits']);
  return bufToHex(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('sealed-mail'), info: enc.encode('login verifier v2') },
    base, 256));
}
// wrapKey: never leaves the browser; encrypts/decrypts the private key.
async function wrapKey(password, saltWrapHex) {
  const bits = await deriveBits(password, saltWrapHex, 256);
  return subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---- identity (RSA-OAEP keypair) ----
async function generateIdentity() {
  return subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt']);
}
async function exportPublicKey(pub) { return bufToB64(await subtle.exportKey('spki', pub)); }
// Human-comparable fingerprint of a public key (SHA-256 of its SPKI bytes), grouped
// for out-of-band verification. If two people read the same fingerprint aloud, the
// server did not substitute a key between them.
async function fingerprint(spkiB64) {
  const hash = await subtle.digest('SHA-256', b64ToBuf(spkiB64));
  return bufToHex(hash).toUpperCase().match(/.{1,4}/g).join(' ');
}
async function importPublicKey(b64) {
  return subtle.importKey('spki', b64ToBuf(b64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}
// The private key is handled as raw PKCS#8 bytes only while it is being (re)wrapped.
// The CryptoKey kept for the session is imported NON-extractable: script running in
// the page can use it while the tab is open but can never export it.
async function exportPkcs8(priv) { return subtle.exportKey('pkcs8', priv); }
async function importPrivateKey(pkcs8) {
  return subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}
async function encryptPkcs8(pkcs8, aesWrapKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: PRIVKEY_AAD }, aesWrapKey, pkcs8);
  return { encPrivKey: bufToB64(ct), privIv: bufToB64(iv) };
}
async function decryptPkcs8(encB64, ivB64, aesWrapKey) {
  return subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(ivB64)), additionalData: PRIVKEY_AAD }, aesWrapKey, b64ToBuf(encB64));
}
async function decryptPrivateKey(encB64, ivB64, aesWrapKey) {
  return importPrivateKey(await decryptPkcs8(encB64, ivB64, aesWrapKey));
}

// Everything the server needs to store for one secret (password OR recovery code):
// two salts, the derived auth key, and the private key wrapped under that secret.
async function secretBundle(secret, pkcs8) {
  const saltAuth = randomHex(16);
  const saltWrap = randomHex(16);
  const authKey = await authKeyHex(secret, saltAuth);
  const { encPrivKey, privIv } = await encryptPkcs8(pkcs8, await wrapKey(secret, saltWrap));
  return { saltAuth, saltWrap, authKey, encPrivKey, privIv };
}

// ---- recovery code ----
// 20 random bytes = 160 bits, base32 (RFC 4648: A-Z 2-7, no 0/1/8/9 to misread),
// shown in groups of 4. High entropy, so it is not brute-forceable even offline.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function generateRecoveryCode() {
  const bytes = window.crypto.getRandomValues(new Uint8Array(20));
  let bits = 0; let value = 0; let out = '';
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out.match(/.{4}/g).join('-');
}
// Accept the code however it was typed back: lower case, spaces, missing dashes.
function normalizeRecoveryCode(s) { return String(s).toUpperCase().replace(/[^A-Z2-7]/g, ''); }

// ---- passkey (WebAuthn PRF) ----
// The PRF output is already a uniform 32-byte secret; HKDF binds it to this one
// purpose so the same authenticator output can never be reused as another key.
async function passkeyWrapKey(prfOutput) {
  const base = await subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('sealed-mail'), info: enc.encode('passkey private-key wrap v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ---- per-message encryption ----
async function encryptBody(obj) {
  const messageKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, messageKey, enc.encode(JSON.stringify(obj)));
  return { messageKey, ciphertext: bufToB64(ct), iv: bufToB64(iv) };
}
// A body is written by whoever sealed it (another user, or our SMTP gateway), so its
// JSON can have any shape. Only the fields the app reads are kept, each with the type
// it expects (anything else becomes undefined): a crafted body like
// {"from":{"toString":1}} must not be able to throw while the folder is drawn.
// Directional formatting characters (bidi overrides/isolates, LRM/RLM) let a sender
// make text render in a misleading order: "factura‮gnp.exe" shows as
// "facturaexe.png". Strip them from every displayed field, as the app already does for
// file names. Newlines and ordinary RTL letters are kept, so legitimate Arabic/Hebrew
// is unaffected; CSS `unicode-bidi` cannot neutralise an embedded override, only strip.
const BIDI_CONTROLS = /[‎‏‪-‮⁦-⁩]/g;
const str = (v) => (typeof v === 'string' ? v.replace(BIDI_CONTROLS, '') : undefined);
function cleanBody(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('malformed message body');
  const body = {
    from: str(raw.from),
    to: Array.isArray(raw.to) ? raw.to.map(str).filter((t) => typeof t === 'string') : undefined,
    subject: str(raw.subject),
    body: str(raw.body),
  };
  if (raw.auth && typeof raw.auth === 'object') {
    body.auth = { spf: str(raw.auth.spf), dkim: str(raw.auth.dkim), dmarc: str(raw.auth.dmarc) };
  }
  // Entries keep their position (it is the file's index), even when malformed.
  if (Array.isArray(raw.attachments)) {
    body.attachments = raw.attachments.map((a) => (a && typeof a === 'object'
      ? { name: str(a.name), type: str(a.type), size: Number.isInteger(a.size) ? a.size : undefined, sha256: str(a.sha256) }
      : null));
  }
  return body;
}
async function decryptBody(messageKey, ctB64, ivB64) {
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(ivB64)) }, messageKey, b64ToBuf(ctB64));
  return cleanBody(JSON.parse(dec.decode(pt)));
}
// Wrap the AES message key for one recipient's RSA public key.
async function wrapMessageKey(messageKey, recipientPub) {
  const raw = await subtle.exportKey('raw', messageKey);
  return bufToB64(await subtle.encrypt({ name: 'RSA-OAEP', label: MSGKEY_LABEL }, recipientPub, raw));
}
async function unwrapMessageKey(encKeyB64, myPriv) {
  const raw = await subtle.decrypt({ name: 'RSA-OAEP', label: MSGKEY_LABEL }, myPriv, b64ToBuf(encKeyB64));
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---- attachments ----
// Each file is encrypted under the message key with a fresh IV and its position as
// additional data, so a file cannot be passed off as another one or as the body.
// The body carries { name, type, size, sha256 } for every file; the reader checks the
// decrypted bytes against it, so the server cannot substitute a file either.
const attachmentAad = (i) => enc.encode(`sealed-mail attachment ${i}`);

async function describeFile(name, type, bytes) {
  return { name, type, size: bytes.byteLength, sha256: bufToHex(await subtle.digest('SHA-256', bytes)) };
}
async function encryptAttachment(messageKey, bytes, index) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: attachmentAad(index) }, messageKey, bytes);
  return { ciphertext: bufToB64(ct), iv: bufToB64(iv) };
}
// Throws when the bytes are not exactly the file the body describes.
async function decryptAttachment(messageKey, ctB64, ivB64, index, expected) {
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(ivB64)), additionalData: attachmentAad(index) },
    messageKey, b64ToBuf(ctB64));
  if (!expected || pt.byteLength !== expected.size || bufToHex(await subtle.digest('SHA-256', pt)) !== expected.sha256) {
    throw new Error('attachment does not match the message');
  }
  return pt;
}

export const crypto = {
  randomHex, authKeyHex, wrapKey,
  generateIdentity, exportPublicKey, importPublicKey, fingerprint,
  exportPkcs8, importPrivateKey, encryptPkcs8, decryptPkcs8, decryptPrivateKey, secretBundle,
  generateRecoveryCode, normalizeRecoveryCode, passkeyWrapKey,
  encryptBody, decryptBody, wrapMessageKey, unwrapMessageKey,
  describeFile, encryptAttachment, decryptAttachment,
  bufToB64, // plaintext files for outside addresses travel as base64 JSON
};
