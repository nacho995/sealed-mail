const { webcrypto } = require('node:crypto');

const { subtle } = webcrypto;

// Seals content for a set of recipients in EXACTLY the format the browser produces
// (public/js/crypto.js: encryptBody + wrapMessageKey): AES-256-GCM over the JSON, a
// 96-bit IV, and the AES key RSA-OAEP(SHA-256)-wrapped once per recipient. The
// recipient's browser then opens it with the same code as any internal message.
//
// Used ONLY for mail that arrives by ordinary SMTP, which is plaintext by nature
// until this point. It is sealed in memory and only the ciphertext is stored.
async function sealForRecipients(content, recipientPubKeysB64) {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.from(JSON.stringify(content), 'utf8'));
  const raw = await subtle.exportKey('raw', key);
  try {
    const encKeys = [];
    for (const spkiB64 of recipientPubKeysB64) {
      const pub = await subtle.importKey('spki', Buffer.from(spkiB64, 'base64'),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      encKeys.push(Buffer.from(await subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw)).toString('base64'));
    }
    return { ciphertext: Buffer.from(ct).toString('base64'), iv: Buffer.from(iv).toString('base64'), encKeys };
  } finally {
    new Uint8Array(raw).fill(0); // the message key must not outlive the wrapping
  }
}

module.exports = { sealForRecipients };
