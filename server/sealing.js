const { webcrypto, createHash } = require('node:crypto');

const { subtle } = webcrypto;

// Seals content for a set of recipients in EXACTLY the format the browser produces
// (public/js/crypto.js: encryptBody + wrapMessageKey): AES-256-GCM over the JSON, a
// 96-bit IV, and the AES key RSA-OAEP(SHA-256)-wrapped once per recipient. The
// recipient's browser then opens it with the same code as any internal message.
//
// Used ONLY for mail that arrives by ordinary SMTP, which is plaintext by nature
// until this point. It is sealed in memory and only the ciphertext is stored.
//
// files: [{ name, type, content: Buffer }]. Like the browser, each file is encrypted
// under the message key with its position as AES-GCM additional data, and its name,
// type, size and SHA-256 go into the encrypted body (content.attachments).
const attachmentAad = (i) => Buffer.from(`sealed-mail attachment ${i}`, 'utf8');

async function sealForRecipients(content, recipientPubKeysB64, files = []) {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const body = files.length
    ? { ...content, attachments: files.map((f) => ({
      name: f.name, type: f.type, size: f.content.length,
      sha256: createHash('sha256').update(f.content).digest('hex'),
    })) }
    : content;
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.from(JSON.stringify(body), 'utf8'));
  const sealedFiles = [];
  for (const [i, f] of files.entries()) {
    const fileIv = webcrypto.getRandomValues(new Uint8Array(12));
    const fileCt = await subtle.encrypt({ name: 'AES-GCM', iv: fileIv, additionalData: attachmentAad(i) }, key, f.content);
    sealedFiles.push({ ciphertext: Buffer.from(fileCt), iv: Buffer.from(fileIv).toString('base64') });
  }
  const raw = await subtle.exportKey('raw', key);
  try {
    const encKeys = [];
    for (const spkiB64 of recipientPubKeysB64) {
      const pub = await subtle.importKey('spki', Buffer.from(spkiB64, 'base64'),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      encKeys.push(Buffer.from(await subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw)).toString('base64'));
    }
    return { ciphertext: Buffer.from(ct).toString('base64'), iv: Buffer.from(iv).toString('base64'), encKeys, attachments: sealedFiles };
  } finally {
    new Uint8Array(raw).fill(0); // the message key must not outlive the wrapping
  }
}

module.exports = { sealForRecipients };
